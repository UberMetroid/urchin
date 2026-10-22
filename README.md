# Urchin

<p align="center">
  <img src="assets/urchin-icon.png" alt="Urchin" width="160" />
</p>

CrowdSec LAPI & AppSec WAF Security Engine for the media stack (`Emby`, `Jellyfin`, `Seerr`, `Caddy`, and Unraid host `syslog`), built from first principles on **Zero Trust**:

1. **Assume inbound traffic is hostile.** Every request hitting your reverse proxy is inspected in-band by the CrowdSec **AppSec WAF** (`:7422`) against virtual-patching and generic exploit rules (`crowdsecurity/appsec-virtual-patching`, `crowdsecurity/appsec-generic-rules`) while real-time log acquisition tails `Caddy`, `Emby`, `Jellyfin`, `Seerr`, and Unraid `syslog` for brute-force and credential-stuffing attacks.
2. **Assume default parsers miss application edge cases.** Stock hub parsers miss usernames containing spaces in Jellyfin, IPv4-mapped IPv6 addresses (`::ffff:`) in Seerr failed sign-ins, and Unraid `sshd-session` log lines. Urchin bakes in custom grok parsers (`seerr-logs`, `z-emby-custom-logs`, `z-jellyfin-custom-logs`, `z-syslog-custom-logs`), leaky-bucket brute-force scenarios (`seerr-bf`), and strict CIDR whitelists (`LAN_NETWORK`) directly into the binary via `include_str!`.
3. **Assume the container runtime is hostile.** Built with **GNU Guix** and **3 static, zero-dependency Rust binaries** (`#![forbid(unsafe_code)]`) alongside static `crowdsec` and `cscli` binaries. There is no `apt`, `apk`, `yq`, `bash` entrypoint script, or third-party Rust crate supply chain inside the supervision plane.

---

## 1. Install

### Option A: Unraid (WebUI Template)
```bash
curl -fsSL https://raw.githubusercontent.com/UberMetroid/urchin/main/unraid-template.xml \
  -o /boot/config/plugins/dockerMan/templates-user/my-urchin.xml
```
In Unraid: **Docker** -> **Add Container** -> select **`urchin`** -> optionally set `BOUNCER_KEY_CADDY` -> **Apply** (pulls `ghcr.io/ubermetroid/urchin:latest` automatically).

### Option B: Docker / Podman CLI
```bash
docker run -d \
  --name=urchin \
  --restart=unless-stopped \
  --security-opt=no-new-privileges:true \
  -p 8291:8080/tcp \
  -p 7423:7422/tcp \
  -p 9399:9399/tcp \
  -e LAN_NETWORK="192.168.1.0/24,100.64.0.0/10" \
  -e BOUNCER_KEY_CADDY="your_caddy_bouncer_api_key" \
  -v /mnt/cache/appdata/urchin/config:/etc/crowdsec:rw \
  -v /mnt/cache/appdata/urchin/data:/var/lib/crowdsec/data:rw \
  -v /mnt/cache/appdata/caddy/logs:/var/log/caddy:ro \
  -v /mnt/cache/appdata/emby/logs:/var/log/emby:ro \
  -v /mnt/cache/appdata/binhex-jellyfin/logs:/var/log/jellyfin:ro \
  -v /mnt/cache/appdata/binhex-seerr/seerr/logs:/var/log/seerr:ro \
  -v /var/log:/var/log/host:ro \
  ghcr.io/ubermetroid/urchin:latest
```

---

## 2. Connect Your Media Stack & Reverse Proxy

| Port (Host -> Container) | Service | How to Connect |
| :--- | :--- | :--- |
| **`8291 -> 8080`** | **CrowdSec LAPI** | Point your Caddy bouncer (`ticker_url` / `api_url`) to `http://<host-ip>:8291` using the key set in `BOUNCER_KEY_CADDY`. |
| **`7423 -> 7422`** | **AppSec WAF Engine** | Point your Caddy `crowdsec` AppSec module (`appsec_url`) to `http://<host-ip>:7423` for real-time in-band virtual patching. |
| **`9399 -> 9399`** | **Health & WAF Status** | `curl http://<host-ip>:9399/status` returns JSON (`healthy`, `lapi_up`, `appsec_waf_up`, `active_decisions`, and per-service parsed line counters). |

---

## 3. Configuration

| Variable | Required | Default | Purpose |
| :--- | :---: | :--- | :--- |
| `LAN_NETWORK` | **Yes** | `192.168.1.0/24,100.64.0.0/10` | Comma-separated LAN/Tailscale subnets whitelisted from bans |
| `BOUNCER_KEY_CADDY` | No | — | Auto-provisions `caddy-bouncer` in LAPI on startup |
| `COLLECTIONS` | No | `crowdsecurity/linux crowdsecurity/caddy ...` | Space-separated CrowdSec Hub collections installed on startup |
| `DISABLE_ONLINE_API` | No | `false` | Set `true` to disable CrowdSec Central API (CAPI) community blocklist pull |
| `PUID` / `PGID` / `UMASK` | No | `99` / `100` / `002` | Unprivileged runtime UID, GID, and file creation mask |

---

## 4. Verify It Yourself (Don't Trust Us)

### Check LAPI, AppSec WAF & Active Decisions
```bash
curl -s http://localhost:9399/status
docker exec urchin /bin/urchin-health --check
docker exec urchin cscli metrics
```

### Build from Source & Reproduce the Image
```bash
cargo test --workspace --all-targets
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --workspace --target x86_64-unknown-linux-gnu
mkdir -p prebuilt && cp target/x86_64-unknown-linux-gnu/release/urchin-* prebuilt/
CID=$(docker create crowdsecurity/crowdsec:latest)
docker cp "$CID:/usr/local/bin/crowdsec" prebuilt/crowdsec
docker cp "$CID:/usr/local/bin/cscli" prebuilt/cscli
docker cp "$CID:/staging" prebuilt/staging
docker rm -v "$CID"
guix pack -f docker --entry-point=/bin/urchin-init -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm
```
