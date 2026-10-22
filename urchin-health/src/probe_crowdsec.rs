//! CrowdSec LAPI (`/health`), AppSec WAF (`:7422`), and Prometheus (`:6060/metrics`) probes
//! and JSON status formatting for Urchin.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub active_decisions: u64,
    pub caddy_parsed: u64,
    pub emby_parsed: u64,
    pub jellyfin_parsed: u64,
    pub seerr_parsed: u64,
    pub syslog_parsed: u64,
    pub appsec_processed: u64,
}

pub fn http_get_local(port: u16, path: &str, timeout: Duration) -> Option<(u16, String)> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 262_144 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&buf).into_owned();
    let first_line = text.lines().next()?;
    let status_str = first_line.split_whitespace().nth(1)?;
    let status_code = status_str.parse::<u16>().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .or_else(|| text.split_once("\n\n").map(|(_, b)| b.to_string()))
        .unwrap_or_default();
    Some((status_code, body))
}

pub fn probe_lapi_up(port: u16) -> bool {
    if let Some((code, body)) = http_get_local(port, "/health", Duration::from_secs(1)) {
        code == 200 && body.contains("\"up\"")
    } else {
        false
    }
}

pub fn probe_appsec_up(port: u16) -> bool {
    if let Some((code, _)) = http_get_local(port, "/", Duration::from_secs(1)) {
        matches!(code, 200 | 400 | 401 | 403 | 404)
    } else {
        false
    }
}

fn parse_metric_u64(line: &str) -> u64 {
    line.split_whitespace()
        .last()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

pub fn parse_prometheus_metrics(raw: &str) -> MetricsSnapshot {
    let mut snap = MetricsSnapshot::default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("cs_active_decisions") {
            snap.active_decisions = snap
                .active_decisions
                .saturating_add(parse_metric_u64(trimmed));
        } else if trimmed.starts_with("cs_parser_hits_ok_total") {
            let val = parse_metric_u64(trimmed);
            if trimmed.contains("acquis_type=\"caddy\"") {
                snap.caddy_parsed = snap.caddy_parsed.saturating_add(val);
            } else if trimmed.contains("acquis_type=\"emby\"") {
                snap.emby_parsed = snap.emby_parsed.saturating_add(val);
            } else if trimmed.contains("acquis_type=\"jellyfin\"") {
                snap.jellyfin_parsed = snap.jellyfin_parsed.saturating_add(val);
            } else if trimmed.contains("acquis_type=\"seerr\"") {
                snap.seerr_parsed = snap.seerr_parsed.saturating_add(val);
            } else if trimmed.contains("acquis_type=\"syslog\"") {
                snap.syslog_parsed = snap.syslog_parsed.saturating_add(val);
            }
        } else if trimmed.starts_with("cs_appsec_reqs_total") {
            snap.appsec_processed = snap
                .appsec_processed
                .saturating_add(parse_metric_u64(trimmed));
        }
    }
    snap
}

pub fn collect_metrics(metrics_port: u16) -> MetricsSnapshot {
    if let Some((200, body)) = http_get_local(metrics_port, "/metrics", Duration::from_secs(1)) {
        parse_prometheus_metrics(&body)
    } else {
        MetricsSnapshot::default()
    }
}

pub fn format_status_http_response(
    lapi_up: bool,
    appsec_up: bool,
    metrics: &MetricsSnapshot,
    uptime_secs: u64,
) -> String {
    let healthy = lapi_up && appsec_up;
    let http_status = if healthy {
        "200 OK"
    } else {
        "503 Service Unavailable"
    };
    let label = if healthy { "healthy" } else { "unhealthy" };
    let body = format!(
        "{{\"status\":\"{label}\",\"lapi_up\":{lapi_up},\"appsec_waf_up\":{appsec_up},\"active_decisions\":{},\"acquisition_parsers\":{{\"caddy\":{},\"emby\":{},\"jellyfin\":{},\"seerr\":{},\"syslog\":{},\"appsec_reqs\":{}}},\"uptime_seconds\":{uptime_secs}}}\n",
        metrics.active_decisions,
        metrics.caddy_parsed,
        metrics.emby_parsed,
        metrics.jellyfin_parsed,
        metrics.seerr_parsed,
        metrics.syslog_parsed,
        metrics.appsec_processed,
    );
    format!(
        "HTTP/1.1 {http_status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prometheus_metrics_and_json_response() {
        let sample = "\
# HELP cs_active_decisions Number of active decisions.
cs_active_decisions{action=\"ban\",origin=\"CAPI\",reason=\"http:scan\"} 15000
cs_active_decisions{action=\"ban\",origin=\"crowdsec\",reason=\"clownhouse/seerr-bf\"} 2
cs_parser_hits_ok_total{acquis_type=\"caddy\",source=\"/var/log/caddy/access.log\",type=\"file\"} 320
cs_parser_hits_ok_total{acquis_type=\"emby\",source=\"/var/log/emby/embyserver.txt\",type=\"file\"} 171
cs_parser_hits_ok_total{acquis_type=\"jellyfin\",source=\"/var/log/jellyfin/log_20261022.log\",type=\"file\"} 209
cs_parser_hits_ok_total{acquis_type=\"seerr\",source=\"/var/log/seerr/seerr-2026-10-22.log\",type=\"file\"} 173
cs_parser_hits_ok_total{acquis_type=\"syslog\",source=\"/var/log/host/syslog\",type=\"file\"} 655
cs_appsec_reqs_total{appsec_engine=\"0.0.0.0:7422/\",source=\"172.17.0.1\"} 284
";
        let snap = parse_prometheus_metrics(sample);
        assert_eq!(snap.active_decisions, 15002);
        assert_eq!(snap.caddy_parsed, 320);
        assert_eq!(snap.emby_parsed, 171);
        assert_eq!(snap.jellyfin_parsed, 209);
        assert_eq!(snap.seerr_parsed, 173);
        assert_eq!(snap.syslog_parsed, 655);
        assert_eq!(snap.appsec_processed, 284);

        let http = format_status_http_response(true, true, &snap, 42);
        assert!(http.starts_with("HTTP/1.1 200 OK"));
        assert!(http.contains("\"status\":\"healthy\""));
        assert!(http.contains("\"active_decisions\":15002"));

        let unhealthy = format_status_http_response(true, false, &snap, 42);
        assert!(unhealthy.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(unhealthy.contains("\"status\":\"unhealthy\""));
    }
}
