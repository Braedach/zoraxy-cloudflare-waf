# zoraxy-cloudflare-waf

A [Zoraxy](https://zoraxy.aroz.org) reverse proxy plugin that watches Zoraxy's own access
log and blacklist events for abusive clients, and mirrors them into a Cloudflare **IP
List** referenced by a single custom WAF rule — so Cloudflare's edge blocks them before
they ever reach the proxy again.

## Why not a per-IP custom rule?

Cloudflare's plans cap custom rules (5 on Free/Pro). This plugin maintains one IP List
and ensures exactly one persistent rule exists referencing it
(`ip.src in $<your_list_name>`) — unlimited IPs, one rule slot, and it never touches any
other rule you've configured by hand.

## How it works

This is a `PluginType_Utilities` plugin — it never registers a static/dynamic capture
path, so it's never in the live proxy request path. It has two independent detectors that
both feed a single decision funnel (`internal/blocker`):

1. **Log tailer** (`internal/logtail`) follows Zoraxy's current-month
   `zr_YYYY-M.log`, matching the same `[client: ip]` / status-code / exploit-pattern
   fields as `Proxmox/LXC/Scripts/forensic-report-zoraxy-v2.sh` in the homelab repo. A
   client crossing the configured 4xx/5xx threshold in the configured window, or hitting
   an exploit-pattern match, becomes a block candidate.
2. **Event subscriber** listens for Zoraxy's own `blacklistedIpBlocked` event, so an IP
   your existing access-rule blacklist just blocked gets mirrored into Cloudflare
   immediately.

Every candidate is validated (`internal/ipfilter`) against Cloudflare's own published edge
ranges before it's ever sent to Cloudflare — a candidate IP that's private/loopback, or
that's itself a Cloudflare edge IP (meaning something upstream read the wrong header), is
rejected rather than blocked. **Always trust `CF-Connecting-IP`, never
`X-Forwarded-For`**, on tunnel-relayed traffic — see `setup-lxc-proxy.sh` in the homelab
repo for why.

## Setup

```bash
go build .                          # local sanity build
./build.sh                          # cross-compile linux/amd64 for the alex LXC
```

On `alex` (see `Proxmox/LXC/Readme.md` in the homelab repo for the box this targets):

```bash
mkdir -p /srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
scp build/zoraxy-cloudflare-waf_*_linux_amd64 \
  alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/zoraxy-cloudflare-waf
scp cloudflarewaf.example.json \
  alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/cloudflarewaf.json
```

Edit `cloudflarewaf.json` on `alex` with a **scoped** Cloudflare API token (`Account →
Rulesets → Edit`, `Zone → Firewall Services → Edit` — not the Global API Key), account ID
and zone ID. Then, from Zoraxy's admin UI, enable the plugin — it'll show up under
Plugins, with its own settings page for everything else (enable/dry-run toggle,
thresholds, IP list name, block action).

**Defaults are deliberately inert**: `enabled: false` and `dry_run: true` out of the box.
Nothing calls Cloudflare until you flip both on from the plugin's UI, after reviewing what
it would have done in the recent-actions log.

## Status

v0.1 — scaffolded and smoke-tested standalone (introspect output, config persistence, UI,
status API all verified). **Not yet tested against a real Cloudflare zone** — the
`internal/cloudflare` client is written to the documented API shapes but wants a live
smoke test with a scoped token before `dry_run` gets switched off for real.

Not yet implemented: unblocking / list pruning, and folding in the `Fail2ban/` filter
rules from the homelab repo as an additional pattern source (planned next).

## Licensing note

This repo is MIT (see `LICENSE`). `mod/zoraxy_plugin/` is vendored, unmodified, from
[tobychui/zoraxy](https://github.com/tobychui/zoraxy) (AGPL-3.0) — it's the IPC glue every
Zoraxy plugin's own docs tell you to copy in, used here strictly out-of-process over
loopback HTTP, not linked into Zoraxy itself. See `mod/zoraxy_plugin/VENDORED_FROM.txt`.
