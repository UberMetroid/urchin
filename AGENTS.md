# urchin — House Laws & Agent Engineering Standards

This document is the **single canonical source of truth** for all code, architecture, and system integration standards for `urchin` (hardened GNU Guix + zero-dependency Rust CrowdSec LAPI & AppSec WAF Security Engine appliance for the media stack). Every human contributor and AI agent must strictly follow these rules without exception.

**Precedence:** Where this file and CI disagree, this file wins. A rule not enforced anywhere is a bug in this file, not a suggestion to ignore.

**Rule Markers:**
- `[GATE:<tool>]` — Machine-enforced by automated compiler flags, clippy, or `cargo test`. Must pass in CI.
- `[POLICY]` — Enforced during code review. Dictates architecture, naming taste, restraint, and ergonomics.

---

## 1. The Page Rule (Code Layout & Sizing)

A **page** is one committed Rust file. Every page holds one idea, fits in one head, and carries its own weight.

- `[GATE:test]` **16–256 Lines**: Every committed `.rs` file must be between **16 and 256 lines** (`content.lines().count()`, blank lines and comments count). Enforced by `tests/page_rules.rs`.
- `[GATE:test]` **Shim Exemption (Floor Only)**: A file is a shim if every non-empty, non-comment, non-attribute line starts with `mod `, `use `, `pub mod `, or `pub use `. Shims skip the 16-line floor; the 256-line ceiling still strictly applies.
- `[GATE:test]` **Directory Density (≤ 8 files)**: At most 8 `.rs` files per directory. Crowded directories split into functional subdirectories grouped by domain.
- `[GATE:test]` **Banned Drawer Filenames**: `util.rs`, `utils.rs`, `helper.rs`, `helpers.rs`, `common.rs`, `misc.rs`, `shared.rs`, `base.rs`, `core.rs`.
- `[POLICY]` **Domain Naming Recipe**: Name pages after their concrete noun or verb:
  - Action pages: `spawn_daemon.rs`, `probe_crowdsec.rs`, `cscli_setup.rs`.
  - State pages: `media_configs.rs`.
- `[POLICY]` **Blobs Out**: Move static configurations, parsers, whitelists, and scenarios into `assets/` and load with `include_str!`.
- `[POLICY]` **Never Pad**: Do not add comments or blank lines to clear 16 lines. Fold small files into their single caller or nearest sibling.

---

## 2. Architecture & Zero-Dependency Discipline

- `[GATE:test]` **Zero External Dependencies**: All 3 workspace crates (`urchin-init`, `urchin-provision`, `urchin-health`) must compile with zero external crates in `[dependencies]` (`std` only) for reproducible offline GNU Guix builds.
- `[POLICY]` **Deep Modules over Speculative Traits (Rule of Two)**: Do not define traits or generic type parameters unless at least two distinct implementations exist in the repository today. Prefer concrete structs with private fields and cohesive public methods.
- `[POLICY]` **Clean Implementation & Attribution**: All code is original, written against Linux networking and POSIX standards under the MIT license.

---

## 3. Pure Rust & Crash-Resilience Standards

- `[GATE:clippy]` **Zero-Panic Invariant**: No bare `.unwrap()`, `.expect()`, or `panic!()` in production code (`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`). `.unwrap()` and `.expect()` are permitted **only** inside `#[cfg(test)]` modules.
- `[GATE:rustc]` **`#![forbid(unsafe_code)]`**: Unsafe code is strictly forbidden across all crate roots and test modules.
- `[GATE:test]` **No Shell Invocations**: Subprocesses must never invoke `sh -c` or `bash -c`. Use direct `std::process::Command::new(argv0).args(...)`. Enforced by `tests/lint.rs`.

---

## 4. Security Engine & WAF Invariants

- `[GATE:test]` **Baked-In Media Stack Parsers & Scenarios**:
  All custom parsers (`seerr-logs.yaml`, `z-emby-custom-logs.yaml`, `z-jellyfin-custom-logs.yaml`, `z-syslog-custom-logs.yaml`), whitelists (`clownhouse-whitelist.yaml`), scenarios (`seerr-bf.yaml`), acquisition (`acquis.yaml`), and AppSec configs (`appsec-config.yaml`) are baked into `urchin-provision` via `include_str!`.
- `[GATE:test]` **Strict CIDR Whitelist Sanitization**:
  `LAN_NETWORK` inputs are validated for strict IPv4/CIDR syntax before rendering `clownhouse-whitelist.yaml`, preventing YAML injection.
- `[GATE:test]` **Continuous LAPI & AppSec Watchdog**:
  `urchin-init` continuously monitors both LAPI (`:8080/health`) and AppSec WAF (`:7422`) and automatically restarts `crowdsec` if either service hangs or crashes.

---

## 5. Verification Ladder

Order matters. Each step must pass completely before running the next:

1. `cargo test --workspace --all-targets` — All unit, integration, and Page Rule lint tests pass.
2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` — Zero warnings, zero panics.
3. `cargo fmt --all -- --check` — Standard formatting verified.
4. `cargo build --release --workspace` — Stripped release binaries built cleanly.

---

## 6. Known Gaps — Not Enforced

- **Live CrowdSec Hub & CAPI Network Calls**: Full end-to-end `cscli hub update` and `cscli capi register` require internet access inside the container runtime; unit tests verify config rendering, CIDR sanitization, collection filtering, and Prometheus metric parsing headlessly.

---

## 7. Multi-Engine Audit Protocol (Pre-Release)

Advisory tiered audit run before tagging releases, budgeted by token capacity:
1. **`mcode`** (Abundant tokens): Full codebase scan for contract mismatches, packaging specs, and CI gates.  
   `mcode exec --permission full "<prompt>"`
2. **`vibe`** (Moderate tokens): Adversarial diff inspection for subtle regressions, security bypasses, and API validity.  
   `vibe -p "<prompt>" --trust --auto-approve`
3. **`grok`** (Strict quota): High-value referee and final sanity check on critical release diffs.  
   `grok -p "<prompt>" --always-approve`
4. **`gemma4`** (Local offline): On-device validation pass with local weights.  
   `gemma4 -p "<prompt>"`

**Rule:** External audits are strictly advisory; all findings must be verified against source code. External LLMs never gate CI—the §5 Verification Ladder is the sole canonical authority.
