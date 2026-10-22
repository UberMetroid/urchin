//! Urchin healthcheck CLI (`--check`) and JSON status HTTP server (`:9399/status`).
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod probe_crowdsec;

use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use probe_crowdsec::{
    collect_metrics, format_status_http_response, probe_appsec_up, probe_lapi_up,
};

const HEALTH_PORT: u16 = 9399;
const LAPI_PORT: u16 = 8080;
const APPSEC_PORT: u16 = 7422;
const METRICS_PORT: u16 = 6060;
const MAX_CONCURRENT_CLIENTS: usize = 64;

fn log(msg: &str) {
    eprintln!("[urchin-health] {msg}");
}

fn handle_client(mut stream: TcpStream, start_epoch: u64) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut req_buf = [0u8; 1024];
    let n = stream.read(&mut req_buf).unwrap_or(0);
    let req_line = String::from_utf8_lossy(&req_buf[..n]);
    let path = req_line
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/status");

    if path != "/" && path != "/status" && path != "/health" {
        let not_found =
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"error\":\"not_found\"}\n";
        let _ = stream.write_all(not_found.as_bytes());
        return;
    }

    let lapi_up = probe_lapi_up(LAPI_PORT);
    let appsec_up = probe_appsec_up(APPSEC_PORT);
    let metrics = collect_metrics(METRICS_PORT);

    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let uptime = now_epoch.saturating_sub(start_epoch);

    let resp = format_status_http_response(lapi_up, appsec_up, &metrics, uptime);
    let _ = stream.write_all(resp.as_bytes());
}

fn run_check_mode() -> i32 {
    let lapi_up = probe_lapi_up(LAPI_PORT);
    let appsec_up = probe_appsec_up(APPSEC_PORT);
    if lapi_up && appsec_up {
        println!("{{\"status\":\"healthy\",\"lapi_up\":true,\"appsec_waf_up\":true}}");
        0
    } else {
        eprintln!(
            "{{\"status\":\"unhealthy\",\"lapi_up\":{lapi_up},\"appsec_waf_up\":{appsec_up}}}"
        );
        1
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--check" || a == "-c") {
        exit(run_check_mode());
    }

    let start_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let active_clients = Arc::new(AtomicUsize::new(0));

    let Ok(listener) = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, HEALTH_PORT)))
    else {
        log(&format!(
            "FATAL: Failed to bind health server on :{HEALTH_PORT}"
        ));
        exit(1);
    };
    log(&format!(
        "Health & WAF Status API listening on 0.0.0.0:{HEALTH_PORT} (/status)"
    ));

    for stream in listener.incoming().flatten() {
        let prev = active_clients.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONCURRENT_CLIENTS {
            active_clients.fetch_sub(1, Ordering::AcqRel);
            drop(stream);
            continue;
        }
        let counter = Arc::clone(&active_clients);
        thread::spawn(move || {
            handle_client(stream, start_epoch);
            counter.fetch_sub(1, Ordering::AcqRel);
        });
    }
}
