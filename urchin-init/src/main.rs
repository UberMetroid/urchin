//! Urchin PID 1 supervisor and continuous LAPI (`:8080`) / AppSec WAF (`:7422`) watchdog.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod spawn_daemon;

use std::env;
use std::process::{exit, Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use spawn_daemon::{
    apply_appdata_ownership, appsec_healthy, ensure_runtime_directories, format_umask,
    lapi_healthy, parse_octal_umask, spawn_crowdsec, spawn_health_server, terminate_children,
};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

const LAPI_PORT: u16 = 8080;
const APPSEC_PORT: u16 = 7422;

fn log(msg: &str) {
    eprintln!("[urchin-init] {msg}");
}

fn spawn_or_exit(res: Result<Child, String>) -> Child {
    match res {
        Ok(c) => c,
        Err(e) => {
            log(&format!("FATAL: {e}"));
            exit(1);
        }
    }
}

fn supervise_loop(
    puid: u32,
    pgid: u32,
    umask_val: u32,
    mut crowdsec_child: Child,
    mut health_child: Child,
) {
    let mut last_watchdog = Instant::now();
    let mut boot_grace_until = Instant::now() + Duration::from_secs(20);
    let mut consecutive_failures = 0u32;

    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        if let Ok(Some(st)) = crowdsec_child.try_wait() {
            log(&format!("WARN: crowdsec exited with {st}; restarting..."));
            if let Ok(c) = spawn_crowdsec(umask_val) {
                crowdsec_child = c;
                boot_grace_until = Instant::now() + Duration::from_secs(20);
                consecutive_failures = 0;
            }
        }

        if let Ok(Some(st)) = health_child.try_wait() {
            log(&format!(
                "WARN: urchin-health exited with {st}; restarting..."
            ));
            if let Ok(c) = spawn_health_server(puid, pgid, umask_val) {
                health_child = c;
            }
        }

        if Instant::now() >= boot_grace_until && last_watchdog.elapsed() >= Duration::from_secs(5) {
            last_watchdog = Instant::now();
            let lapi_ok = lapi_healthy(LAPI_PORT);
            let appsec_ok = appsec_healthy(APPSEC_PORT);

            if !lapi_ok || !appsec_ok {
                consecutive_failures = consecutive_failures.saturating_add(1);
                log(&format!(
                    "ALERT: Watchdog check failed (lapi_8080={lapi_ok}, appsec_7422={appsec_ok}, consecutive={consecutive_failures}/6)"
                ));
                if consecutive_failures >= 6 {
                    log("ALERT: LAPI/AppSec unresponsive for 30s; restarting crowdsec...");
                    let _ = crowdsec_child.kill();
                    let _ = crowdsec_child.wait();
                    if let Ok(c) = spawn_crowdsec(umask_val) {
                        crowdsec_child = c;
                        boot_grace_until = Instant::now() + Duration::from_secs(20);
                        consecutive_failures = 0;
                    }
                }
            } else {
                consecutive_failures = 0;
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    log("Shutdown requested; terminating child daemons gracefully...");
    let mut children = [crowdsec_child, health_child];
    terminate_children(&mut children);
    log("Clean shutdown complete.");
}

fn main() {
    let puid: u32 = env::var("PUID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(99);
    let pgid: u32 = env::var("PGID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let umask_str = env::var("UMASK").unwrap_or_else(|_| "002".to_string());
    let umask_val = parse_octal_umask(&umask_str);

    log(&format!(
        "Starting urchin-init supervisor (PUID={puid}, PGID={pgid}, UMASK={})",
        format_umask(umask_val)
    ));

    ensure_runtime_directories();

    log("Executing urchin-provision to configure parsers, scenarios, whitelists, hub, and bouncers...");
    let prov_status = Command::new("/bin/urchin-provision").status();
    match prov_status {
        Ok(s) if s.success() => log("urchin-provision completed successfully."),
        _ => {
            log("FATAL: urchin-provision failed. Refusing to start crowdsec.");
            exit(1);
        }
    }

    apply_appdata_ownership(puid, pgid);

    let crowdsec_child = spawn_or_exit(spawn_crowdsec(umask_val));
    let health_child = spawn_or_exit(spawn_health_server(puid, pgid, umask_val));

    log("All child daemons launched (crowdsec LAPI:8080, AppSec WAF:7422, urchin-health:9399).");
    supervise_loop(puid, pgid, umask_val, crowdsec_child, health_child);
}
