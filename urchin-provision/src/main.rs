//! Urchin provisioner binary: seeds `/etc/crowdsec` and `/var/lib/crowdsec/data`,
//! installs custom media stack parsers/scenarios/whitelists, updates the hub, and
//! registers local machine and bouncer API keys.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod cscli_setup;
mod media_configs;

use std::env;
use std::path::Path;
use std::process::exit;

use cscli_setup::{
    ensure_bouncer, ensure_capi_credentials, ensure_config_yaml, ensure_local_machine, log,
    parse_collection_list, run_cscli, DEFAULT_COLLECTIONS,
};
use media_configs::{install_media_configs, sync_dir_ignore_existing};

fn env_is_true(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn provision_hub_items(collections: &[String]) {
    log("Updating CrowdSec Hub index...");
    if let Err(e) = run_cscli(&["hub", "update"]) {
        log(&format!(
            "WARN: cscli hub update failed (offline/seeded mode): {e}"
        ));
    }

    for parser in ["crowdsecurity/docker-logs", "crowdsecurity/cri-logs"] {
        let _ = run_cscli(&["parsers", "install", parser, "--force"]);
    }

    for col in collections {
        log(&format!("Installing/verifying hub collection '{col}'..."));
        if let Err(e) = run_cscli(&["collections", "install", col, "--force"]) {
            log(&format!("WARN: Could not install collection '{col}': {e}"));
        }
    }

    if !env_is_true("NO_HUB_UPGRADE") {
        let _ = run_cscli(&["hub", "upgrade"]);
    }
}

fn provision_all_bouncers() -> Result<(), String> {
    if let Ok(caddy_key) = env::var("BOUNCER_KEY_CADDY") {
        if !caddy_key.trim().is_empty() {
            ensure_bouncer("caddy-bouncer", &caddy_key)?;
        }
    }
    for (k, v) in env::vars() {
        if k == "BOUNCER_KEY_CADDY" {
            continue;
        }
        if let Some(suffix) = k.strip_prefix("BOUNCER_KEY_") {
            let name = suffix.trim().to_ascii_lowercase().replace('_', "-");
            if !name.is_empty() && !v.trim().is_empty() {
                let bouncer_name = if name.ends_with("-bouncer") {
                    name
                } else {
                    format!("{name}-bouncer")
                };
                ensure_bouncer(&bouncer_name, &v)?;
            }
        }
    }
    Ok(())
}

fn run_provision() -> Result<(), String> {
    let etc_root = Path::new("/etc/crowdsec");
    let data_root = Path::new("/var/lib/crowdsec/data");
    let staging_etc = Path::new("/share/crowdsec/staging/etc/crowdsec");
    let staging_data = Path::new("/share/crowdsec/staging/var/lib/crowdsec/data");
    let disable_online_api = env_is_true("DISABLE_ONLINE_API");

    log("Seeding /etc/crowdsec and /var/lib/crowdsec/data from immutable Guix staging...");
    sync_dir_ignore_existing(staging_etc, etc_root)
        .map_err(|e| format!("Failed to seed /etc/crowdsec: {e}"))?;
    sync_dir_ignore_existing(staging_data, data_root)
        .map_err(|e| format!("Failed to seed /var/lib/crowdsec/data: {e}"))?;

    ensure_config_yaml(etc_root, disable_online_api)?;

    let lan_network =
        env::var("LAN_NETWORK").unwrap_or_else(|_| "192.168.1.0/24,100.64.0.0/10".to_string());
    let custom_hostname = env::var("CUSTOM_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let raw_collections =
        env::var("COLLECTIONS").unwrap_or_else(|_| DEFAULT_COLLECTIONS.to_string());
    let disabled_collections = env::var("DISABLE_COLLECTIONS").unwrap_or_default();
    let collections = parse_collection_list(&raw_collections, &disabled_collections);

    ensure_local_machine(etc_root, &custom_hostname)?;
    ensure_capi_credentials(etc_root, disable_online_api);
    provision_hub_items(&collections);

    log(
        "Installing baked-in custom media stack parsers, whitelists, scenarios, and acquisition...",
    );
    install_media_configs(etc_root, &lan_network)
        .map_err(|e| format!("Failed to install custom media configs: {e}"))?;

    provision_all_bouncers()?;

    log("Provisioning complete.");
    Ok(())
}

fn main() {
    if let Err(e) = run_provision() {
        log(&format!("FATAL: {e}"));
        exit(1);
    }
}
