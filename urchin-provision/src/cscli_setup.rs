//! CrowdSec CLI (`cscli`) orchestration: local machine credentials, CAPI registration,
//! hub collections, and bouncer API key provisioning.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub const DEFAULT_COLLECTIONS: &str = "crowdsecurity/linux \
    crowdsecurity/caddy \
    crowdsecurity/http-cve \
    crowdsecurity/base-http-scenarios \
    crowdsecurity/whitelist-good-actors \
    crowdsecurity/appsec-virtual-patching \
    crowdsecurity/appsec-generic-rules \
    LePresidente/emby \
    LePresidente/jellyfin";

pub const HARDENED_CONFIG_YAML: &str = include_str!("../../assets/config.yaml");

pub fn log(msg: &str) {
    eprintln!("[urchin-provision] {msg}");
}

pub fn run_cscli(args: &[&str]) -> Result<String, String> {
    let mut full_args = vec!["-c", "/etc/crowdsec/config.yaml"];
    full_args.extend_from_slice(args);
    let output = Command::new("cscli")
        .args(&full_args)
        .output()
        .map_err(|e| format!("Failed to execute cscli {args:?}: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "cscli {args:?} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn parse_collection_list(raw: &str, disabled: &str) -> Vec<String> {
    let disabled_set: Vec<&str> = disabled
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let mut out = Vec::new();
    for item in raw
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if item
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_'))
            && item.contains('/')
            && !disabled_set.contains(&item)
            && !out.iter().any(|existing| existing == item)
        {
            out.push(item.to_string());
        }
    }
    out
}

pub fn json_has_named_entry(json: &str, field: &str, expected: &str) -> bool {
    let needle = format!("\"{field}\":\"{expected}\"");
    let compact: String = json.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    compact.contains(&needle)
}

pub fn render_config_yaml(disable_online_api: bool) -> String {
    if disable_online_api {
        HARDENED_CONFIG_YAML
            .lines()
            .filter(|line| {
                let t = line.trim();
                t != "online_client:" && !t.contains("online_api_credentials.yaml")
            })
            .map(|l| format!("{l}\n"))
            .collect()
    } else {
        HARDENED_CONFIG_YAML.to_string()
    }
}

pub fn ensure_config_yaml(etc_root: &Path, disable_online_api: bool) -> Result<(), String> {
    fs::create_dir_all(etc_root)
        .map_err(|e| format!("Failed to create {}: {e}", etc_root.display()))?;
    let cfg_path = etc_root.join("config.yaml");
    let rendered = render_config_yaml(disable_online_api);
    fs::write(&cfg_path, rendered)
        .map_err(|e| format!("Failed to write {}: {e}", cfg_path.display()))?;
    let _ = fs::set_permissions(&cfg_path, Permissions::from_mode(0o644));
    Ok(())
}

pub fn ensure_local_machine(etc_root: &Path, machine_id: &str) -> Result<(), String> {
    let creds = etc_root.join("local_api_credentials.yaml");
    let creds_valid = creds
        .exists()
        .then(|| fs::read_to_string(&creds).ok())
        .flatten()
        .map(|s| s.contains("login:") && s.contains("password:"))
        .unwrap_or(false);

    let list_json = run_cscli(&["machines", "list", "-o", "json"]).unwrap_or_default();
    if creds_valid && json_has_named_entry(&list_json, "machineId", machine_id) {
        log(&format!("Local machine '{machine_id}' already registered."));
        return Ok(());
    }

    log(&format!(
        "Registering local machine credentials for '{machine_id}'..."
    ));
    let _ = run_cscli(&["machines", "delete", machine_id]);
    run_cscli(&["machines", "add", machine_id, "--auto", "--force"])?;
    if creds.exists() {
        let _ = fs::set_permissions(&creds, Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn ensure_capi_credentials(etc_root: &Path, disable_online_api: bool) {
    if disable_online_api {
        log("Online CAPI disabled by environment.");
        return;
    }
    let online_creds = etc_root.join("online_api_credentials.yaml");
    let has_creds = online_creds
        .exists()
        .then(|| fs::read_to_string(&online_creds).ok())
        .flatten()
        .map(|s| s.contains("login:") && s.contains("password:"))
        .unwrap_or(false);
    if !has_creds {
        log("Registering with CrowdSec Central API (CAPI)...");
        if let Err(e) = run_cscli(&[
            "capi",
            "register",
            "-f",
            "/etc/crowdsec/online_api_credentials.yaml",
        ]) {
            log(&format!("WARN: CAPI registration skipped/failed: {e}"));
        } else if online_creds.exists() {
            let _ = fs::set_permissions(&online_creds, Permissions::from_mode(0o600));
        }
    }
}

pub fn ensure_bouncer(name: &str, api_key: &str) -> Result<(), String> {
    let key = api_key.trim();
    if key.is_empty() {
        return Ok(());
    }
    let list_json = run_cscli(&["bouncers", "list", "-o", "json"]).unwrap_or_default();
    if json_has_named_entry(&list_json, "name", name) {
        log(&format!(
            "Re-provisioning bouncer '{name}' with configured API key..."
        ));
        let _ = run_cscli(&["bouncers", "delete", name]);
    } else {
        log(&format!("Registering bouncer '{name}'..."));
    }
    run_cscli(&["bouncers", "add", name, "-k", key]).map(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_collection_list_and_filtering() {
        let cols = parse_collection_list(
            "crowdsecurity/linux, LePresidente/emby invalid_item crowdsecurity/caddy",
            "LePresidente/emby",
        );
        assert_eq!(cols, vec!["crowdsecurity/linux", "crowdsecurity/caddy"]);
    }

    #[test]
    fn test_json_has_named_entry_and_config_render() {
        let sample = r#"[{"name": "caddy-bouncer", "revoked": false}]"#;
        assert!(json_has_named_entry(sample, "name", "caddy-bouncer"));
        assert!(!json_has_named_entry(sample, "name", "other-bouncer"));

        let cfg_on = render_config_yaml(false);
        assert!(cfg_on.contains("online_api_credentials.yaml"));
        assert!(cfg_on.contains("listen_addr: 127.0.0.1"));
        let cfg_off = render_config_yaml(true);
        assert!(!cfg_off.contains("online_api_credentials.yaml"));
    }
}
