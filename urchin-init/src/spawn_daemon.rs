//! Daemon spawning, directory provisioning, and LAPI/AppSec watchdog probes for `urchin-init`.

use std::fs::{self, Permissions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

pub const REQUIRED_DIRS: &[&str] = &[
    "/etc/crowdsec",
    "/etc/crowdsec/acquis.d",
    "/etc/crowdsec/appsec-configs",
    "/etc/crowdsec/appsec-rules",
    "/etc/crowdsec/collections",
    "/etc/crowdsec/contexts",
    "/etc/crowdsec/hub",
    "/etc/crowdsec/notifications",
    "/etc/crowdsec/parsers/s00-raw",
    "/etc/crowdsec/parsers/s01-parse",
    "/etc/crowdsec/parsers/s02-enrich",
    "/etc/crowdsec/patterns",
    "/etc/crowdsec/postoverflows",
    "/etc/crowdsec/scenarios",
    "/var/lib/crowdsec/data",
    "/var/lib/crowdsec/data/trace",
    "/var/log/caddy",
    "/var/log/emby",
    "/var/log/jellyfin",
    "/var/log/seerr",
    "/var/log/host",
    "/tmp",
];

pub fn parse_octal_umask(s: &str) -> u32 {
    u32::from_str_radix(s.trim(), 8).unwrap_or(0o002)
}

pub fn format_umask(umask_val: u32) -> String {
    format!("{umask_val:03o}")
}

fn ensure_machine_id() {
    let mid = Path::new("/etc/machine-id");
    if mid.exists() {
        return;
    }
    let boot_uuid = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .or_else(|_| fs::read_to_string("/proc/sys/kernel/random/uuid"))
        .unwrap_or_default();
    let hex: String = boot_uuid
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(32)
        .collect();
    let id = if hex.len() == 32 {
        hex
    } else {
        "a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()
    };
    let _ = fs::write(mid, format!("{id}\n"));
}

pub fn ensure_runtime_directories() {
    for dir in REQUIRED_DIRS {
        let p = Path::new(dir);
        let _ = fs::create_dir_all(p);
    }
    let _ = fs::set_permissions("/tmp", Permissions::from_mode(0o1777));
    ensure_machine_id();
}

pub fn apply_appdata_ownership(puid: u32, pgid: u32) {
    let owner = format!("{puid}:{pgid}");
    let _ = Command::new("chown")
        .args(["-R", &owner, "/etc/crowdsec", "/var/lib/crowdsec/data"])
        .status();
    for cred in [
        "/etc/crowdsec/local_api_credentials.yaml",
        "/etc/crowdsec/online_api_credentials.yaml",
    ] {
        let p = Path::new(cred);
        if p.exists() {
            let _ = fs::set_permissions(p, Permissions::from_mode(0o600));
        }
    }
}

pub fn spawn_crowdsec(umask_val: u32) -> Result<Child, String> {
    Command::new("crowdsec")
        .args(["-c", "/etc/crowdsec/config.yaml"])
        .env("SSL_CERT_DIR", "/etc/ssl/certs")
        .env("UMASK", format_umask(umask_val))
        .spawn()
        .map_err(|e| format!("Failed to spawn crowdsec: {e}"))
}

pub fn spawn_health_server(puid: u32, pgid: u32, umask_val: u32) -> Result<Child, String> {
    let mut cmd = Command::new("/bin/urchin-health");
    cmd.env("UMASK", format_umask(umask_val));
    if puid > 0 && pgid > 0 {
        cmd.uid(puid).gid(pgid);
    }
    cmd.spawn()
        .map_err(|e| format!("Failed to spawn /bin/urchin-health: {e}"))
}

pub fn http_probe_local(port: u16, path: &str) -> Option<(u16, String)> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 16384 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code = text
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    Some((code, text))
}

pub fn lapi_healthy(port: u16) -> bool {
    if let Some((code, text)) = http_probe_local(port, "/health") {
        code == 200 && text.contains("\"up\"")
    } else {
        false
    }
}

pub fn appsec_healthy(port: u16) -> bool {
    if let Some((code, _)) = http_probe_local(port, "/") {
        matches!(code, 200 | 400 | 401 | 403 | 404)
    } else {
        false
    }
}

pub fn terminate_children(children: &mut [Child]) {
    for child in children.iter() {
        let pid_str = child.id().to_string();
        let _ = Command::new("kill").args(["-TERM", &pid_str]).status();
    }
    thread::sleep(Duration::from_secs(2));
    for child in children.iter_mut() {
        let _ = child.kill();
        if let Ok(st) = child.wait() {
            let _ = st.signal();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_umask_parsing_and_formatting() {
        assert_eq!(parse_octal_umask("002"), 0o002);
        assert_eq!(parse_octal_umask("022"), 0o022);
        assert_eq!(format_umask(0o002), "002");
    }

    #[test]
    fn test_required_dirs_include_media_logs_and_crowdsec() {
        assert!(REQUIRED_DIRS.contains(&"/etc/crowdsec"));
        assert!(REQUIRED_DIRS.contains(&"/var/lib/crowdsec/data"));
        assert!(REQUIRED_DIRS.contains(&"/var/log/emby"));
        assert!(REQUIRED_DIRS.contains(&"/var/log/jellyfin"));
        assert!(REQUIRED_DIRS.contains(&"/var/log/seerr"));
        assert!(REQUIRED_DIRS.contains(&"/var/log/caddy"));
        assert!(REQUIRED_DIRS.contains(&"/var/log/host"));
    }
}
