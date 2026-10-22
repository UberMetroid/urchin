//! Baked-in media stack parsers, whitelists, scenarios, acquisition, and staging sync for Urchin.

use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const SEERR_LOGS_YAML: &str = include_str!("../../assets/seerr-logs.yaml");
pub const EMBY_LOGS_YAML: &str = include_str!("../../assets/z-emby-custom-logs.yaml");
pub const JELLYFIN_LOGS_YAML: &str = include_str!("../../assets/z-jellyfin-custom-logs.yaml");
pub const SYSLOG_LOGS_YAML: &str = include_str!("../../assets/z-syslog-custom-logs.yaml");
pub const WHITELIST_YAML: &str = include_str!("../../assets/clownhouse-whitelist.yaml");
pub const SEERR_BF_YAML: &str = include_str!("../../assets/seerr-bf.yaml");
pub const ACQUIS_YAML: &str = include_str!("../../assets/acquis.yaml");
pub const APPSEC_CONFIG_YAML: &str = include_str!("../../assets/appsec-config.yaml");

const DEFAULT_CIDRS: &[&str] = &["127.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10"];

pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets_ok = parts.iter().all(|p| {
        !p.is_empty()
            && p.chars().all(|c| c.is_ascii_digit())
            && !(p.len() > 1 && p.starts_with('0'))
            && p.parse::<u8>().is_ok()
    });
    octets_ok && ip != "0.0.0.0" && ip != "255.255.255.255"
}

pub fn is_valid_cidr(cidr: &str) -> bool {
    if let Some((ip, prefix)) = cidr.split_once('/') {
        !prefix.is_empty()
            && prefix.chars().all(|c| c.is_ascii_digit())
            && !(prefix.len() > 1 && prefix.starts_with('0'))
            && prefix
                .parse::<u8>()
                .map(|p| (8..=32).contains(&p))
                .unwrap_or(false)
            && is_valid_ipv4(ip)
    } else {
        is_valid_ipv4(cidr)
    }
}

pub fn normalize_cidr(entry: &str) -> Option<String> {
    let trimmed = entry.trim();
    if !is_valid_cidr(trimmed) {
        return None;
    }
    if trimmed.contains('/') {
        Some(trimmed.to_string())
    } else {
        Some(format!("{trimmed}/32"))
    }
}

pub fn render_whitelist_yaml(lan_network: &str) -> String {
    let _ = WHITELIST_YAML;
    let mut cidrs: Vec<String> = Vec::new();
    for base in DEFAULT_CIDRS {
        cidrs.push((*base).to_string());
    }
    let mut user_cidrs = Vec::new();
    for raw in lan_network.split(',') {
        if let Some(norm) = normalize_cidr(raw) {
            if !user_cidrs.contains(&norm) {
                user_cidrs.push(norm);
            }
        }
    }
    if user_cidrs.is_empty() {
        for line in WHITELIST_YAML.lines() {
            if let Some(rest) = line.trim().strip_prefix("- ") {
                if let Some(norm) = normalize_cidr(rest) {
                    if !cidrs.contains(&norm) {
                        cidrs.push(norm);
                    }
                }
            }
        }
    } else {
        for c in user_cidrs {
            if !cidrs.contains(&c) {
                cidrs.push(c);
            }
        }
    }
    let mut out = String::from(
        "name: clownhouse/internal-whitelist\n\
         description: \"Whitelist localhost, Docker bridge, Tailscale CGNAT, and home LAN networks\"\n\
         whitelist:\n\
         \x20 reason: \"Trusted internal, Tailscale, and home LAN networks\"\n\
         \x20 cidr:\n",
    );
    for c in cidrs {
        out.push_str(&format!("    - {c}\n"));
    }
    out
}

pub fn sync_dir_ignore_existing(src: &Path, dst: &Path) -> io::Result<()> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            sync_dir_ignore_existing(&src_path, &dst_path)?;
        } else if ft.is_file() && !dst_path.exists() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub fn link_staged_hub_items(etc_root: &Path) -> io::Result<()> {
    let pairs = [
        ("hub/appsec-rules/crowdsecurity", "appsec-rules"),
        ("hub/appsec-configs/crowdsecurity", "appsec-configs"),
        ("hub/collections/crowdsecurity", "collections"),
        ("hub/collections/LePresidente", "collections"),
        ("hub/parsers/s00-raw/crowdsecurity", "parsers/s00-raw"),
        ("hub/parsers/s01-parse/crowdsecurity", "parsers/s01-parse"),
        ("hub/parsers/s01-parse/LePresidente", "parsers/s01-parse"),
        ("hub/parsers/s02-enrich/crowdsecurity", "parsers/s02-enrich"),
        ("hub/scenarios/crowdsecurity", "scenarios"),
        ("hub/scenarios/LePresidente", "scenarios"),
        ("hub/contexts/crowdsecurity", "contexts"),
    ];
    for (src_rel, dst_rel) in pairs {
        let src_dir = etc_root.join(src_rel);
        let dst_dir = etc_root.join(dst_rel);
        let _ = sync_dir_ignore_existing(&src_dir, &dst_dir);
    }
    Ok(())
}

pub fn install_media_configs(etc_root: &Path, lan_network: &str) -> io::Result<()> {
    let s01 = etc_root.join("parsers/s01-parse");
    let s02 = etc_root.join("parsers/s02-enrich");
    let scenarios = etc_root.join("scenarios");
    let appsec = etc_root.join("appsec-configs");
    let acquis_d = etc_root.join("acquis.d");

    for dir in [&s01, &s02, &scenarios, &appsec, &acquis_d] {
        fs::create_dir_all(dir)?;
    }
    let _ = link_staged_hub_items(etc_root);

    let files: &[(&Path, &str, &str)] = &[
        (&s01, "seerr-logs.yaml", SEERR_LOGS_YAML),
        (&s01, "z-emby-custom-logs.yaml", EMBY_LOGS_YAML),
        (&s01, "z-jellyfin-custom-logs.yaml", JELLYFIN_LOGS_YAML),
        (&s01, "z-syslog-custom-logs.yaml", SYSLOG_LOGS_YAML),
        (&scenarios, "seerr-bf.yaml", SEERR_BF_YAML),
        (&appsec, "urchin-appsec.yaml", APPSEC_CONFIG_YAML),
        (etc_root, "acquis.yaml", ACQUIS_YAML),
    ];

    for (dir, name, content) in files {
        let path = dir.join(name);
        let _ = fs::remove_file(&path);
        fs::write(&path, content)?;
        let _ = fs::set_permissions(&path, Permissions::from_mode(0o644));
    }

    let wl_path = s02.join("clownhouse-whitelist.yaml");
    let _ = fs::remove_file(&wl_path);
    fs::write(&wl_path, render_whitelist_yaml(lan_network))?;
    let _ = fs::set_permissions(&wl_path, Permissions::from_mode(0o644));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_cidr_validation_and_whitelist_rendering() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.1"));
        assert!(!is_valid_cidr("0.0.0.0/0"));
        assert!(!is_valid_cidr("10.0.0.0/7"));
        assert!(!is_valid_cidr("+1.2.3.4"));
        assert!(!is_valid_cidr("1.2.3.4/+24"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
        assert!(!is_valid_cidr("010.0.0.1/8"));
        assert!(!is_valid_cidr("invalid;rm -rf"));

        let yaml = render_whitelist_yaml("10.99.0.0/16, 1.2.3.4, 0.0.0.0/0, +1.2.3.4");
        assert!(yaml.contains("- 127.0.0.0/8"));
        assert!(yaml.contains("- 10.99.0.0/16"));
        assert!(yaml.contains("- 1.2.3.4/32"));
        assert!(!yaml.contains("192.168.1.0/24"));
        assert!(!yaml.contains("0.0.0.0"));
        assert!(!yaml.contains("+1.2.3.4"));
    }

    #[test]
    fn test_install_media_configs_to_temp_dir() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("urchin_test_{stamp}"));
        install_media_configs(&tmp, "192.168.50.0/24").unwrap();

        assert!(tmp.join("parsers/s01-parse/seerr-logs.yaml").exists());
        assert!(tmp
            .join("parsers/s01-parse/z-emby-custom-logs.yaml")
            .exists());
        assert!(tmp
            .join("parsers/s01-parse/z-jellyfin-custom-logs.yaml")
            .exists());
        assert!(tmp
            .join("parsers/s01-parse/z-syslog-custom-logs.yaml")
            .exists());
        assert!(tmp
            .join("parsers/s02-enrich/clownhouse-whitelist.yaml")
            .exists());
        assert!(tmp.join("scenarios/seerr-bf.yaml").exists());
        assert!(tmp.join("appsec-configs/urchin-appsec.yaml").exists());
        assert!(tmp.join("acquis.yaml").exists());

        let wl =
            fs::read_to_string(tmp.join("parsers/s02-enrich/clownhouse-whitelist.yaml")).unwrap();
        assert!(wl.contains("192.168.50.0/24"));
        let _ = fs::remove_dir_all(&tmp);
    }
}
