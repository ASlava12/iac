# Future Work

Items deferred indefinitely — not actively scheduled, not on the
near-term roadmap. Live here so they're not lost but also don't
clutter [TASKS.md](TASKS.md) week-to-week.

Move an item *back* to TASKS.md when the gating condition changes
(hardware ordered, operator complaint filed, scale crossed, etc.).

---

## Phase 10 — Real MIPS device bring-up

**Status:** hardware-gated. Cross-compile + binary-size + qemu
smoke + runbook recipe are all done — see TASKS_ARCHIVE.md
sections for Phase 10 cross-compile (commit `f3f0a21`, mipsel-musl
iac-agent at 7.0 MiB stripped) and the runbook section "Cross-
compile for MIPS / OpenWrt" (commit `684436a`). What remains is
exercising the agent on real hardware to validate that the Tier-3
toolchain output actually behaves on MIPS24KEc / MIPS32 rel2 CPUs
the way the integration tests assert it does on amd64/aarch64.

**What needs validating:**

- `firewall.rule` provider against real iptables / nftables on the
  device.
- `file` provider against the device's actual filesystem
  (typically `overlayfs` over flash on OpenWrt — different
  atomic-rename semantics than ext4/tmpfs the unit tests use).
- Capability allowlist enforcement on a constrained-memory host
  (128 MB RAM is the typical OpenWrt budget).
- Agent observe loop + heartbeat under network conditions of a
  consumer router (NAT, MTU, intermittent backhaul).

**Concrete hardware recommendation (per session 2026-05-17):**

| Device                              | Cost      | Spec                            | Notes |
|-------------------------------------|-----------|---------------------------------|-------|
| **GL.iNet GL-MT300N-V2 "Mango"**    | $20–30    | MIPS 24KEc 580 MHz, 128 MB RAM, 16 MB flash | Recommended — OpenWrt out of the box, USB-powered |
| GL.iNet GL-MT1300 "Beryl"           | $50–70    | MIPS dual-core, 256 MB RAM, 32 MB flash      | More headroom |
| TP-Link Archer C7 v2/v5 (used)      | $30–50    | MIPS 24Kc, 128 MB / 16 MB                    | Most-documented OpenWrt target |
| GL.iNet GL-AR300M16                 | $35–45    | MIPS 24Kc, 128 MB RAM, 16 MB flash + 128 MB NAND | NAND for state without filling primary flash |

**Do NOT buy:**

- Anything **MIPS big-endian** (`mips-unknown-linux-musl`). The
  cross-build target is little-endian (`mipsel-`); BE devices
  would need a separate toolchain + binary.
- ARM-based "network gear" (most newer GL.iNet, MikroTik hAP ac²,
  etc.). ARM is already validated via the Pi 4 trial (Phase 8.7)
  and doesn't exercise the Tier-3 compilation path Phase 10 is
  about.
- x86-class mini-PCs — not Tier-3, not MIPS.

**Plus accessories:**

- USB-Ethernet cable (initial setup).
- Optional USB-to-serial adapter ($5–10) for console debugging if
  SSH breaks during bring-up.

**Time budget:** half-day if first time with OpenWrt (flash
recovery, opkg, SSH key setup, init script), 1–2 hours if
familiar. The cross-build itself is ~7 minutes (already documented
in [docs/en/runbook.md](docs/en/runbook.md) "Cross-compile for
MIPS / OpenWrt").

**Total cost to unblock:** ~$25–35.

---

## v2 / out-of-scope

These are listed in TASKS.md under "v2 / out-of-scope" — kept
there because they're decisions, not deferred work. Promotions
here would mean someone took ownership of the item and is
sketching when/how. For now: don't surprise us, don't actively
explore.

(See [TASKS.md](TASKS.md#v2--out-of-scope) for the canonical list:
multi-tenancy, Web UI, federation, k8s/terraform/helm providers,
plugin marketplace, macOS/Windows agents.)
