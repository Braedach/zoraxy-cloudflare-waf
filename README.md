# zoraxy-cloudflare-waf

A [Zoraxy](https://zoraxy.aroz.org) reverse proxy plugin that watches Zoraxy's own access
log and blacklist events for abusive clients, and mirrors them into a Cloudflare **IP
List** referenced by a single custom WAF rule — so Cloudflare's edge blocks them before
they ever reach the proxy again.

## Cloudflare limits, and how this plugin manages them

These numbers are Cloudflare's own current documented limits (Free/Pro/Business — verify
against your actual plan, these can change):

| Limit | Value | Source |
|---|---|---|
| Custom rules per zone | 5 | [Cloudflare Community](https://community.cloudflare.com/t/number-of-waf-firewall-rules-allowed-on-free-accounts/593171) |
| Expression length per rule | 4,096 characters | [Cloudflare Community](https://community.cloudflare.com/t/number-of-waf-firewall-rules-allowed-on-free-accounts/593171) |
| IP list items, account-wide | 10,000 across all custom lists | [Lists API docs](https://developers.cloudflare.com/waf/tools/lists/lists-api/) |

**Why one IP List instead of a rule per IP, or IPs inline in a rule expression:** a rule
listing raw IPs (`ip.src eq 1.2.3.4 or ip.src eq 5.6.7.8 or ...`) hits the 4,096-character
expression cap after roughly 100-150 IPv4 addresses. This plugin instead maintains one
Cloudflare **IP List** and ensures exactly one persistent custom rule references it —
`(ip.src in $<your_list_name>)`, ~30-40 characters regardless of how many IPs the list
holds. That sidesteps the expression-length cap entirely and uses exactly one of your five
rule slots no matter how many IPs get blocked. It never touches any other rule you've
configured by hand (matched/updated by the Cloudflare-assigned rule ID once created, not
by scanning-and-guessing).

**The real ceiling is the list's 10,000-item cap**, not the rule. `Config.MaxIPListItems`
(default 10,000) is this plugin's own pre-flight guard — checked live before every add, so
a full list fails softly (`skipped-list-full` in the action log) instead of erroring
against the Cloudflare API. There's no automatic pruning yet (see Status below) — a list
that fills up needs a manual trim in the Cloudflare dashboard until that's built.

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

Then, from Zoraxy's admin UI, enable the plugin — it'll show up under Plugins, with its own
settings page (`Config → Cloudflare` fieldset) for the rest of the setup: paste the token,
account ID and zone ID there directly, rather than hand-editing the JSON.

### Creating a correctly scoped API token

**Never use the Global API Key.** At
[dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) →
**Create Custom Token**, grant exactly these two permissions and nothing more:

| Scope | Permission | Why |
|---|---|---|
| Account | `Account Filter Lists` → **Edit** | create/update the IP list |
| Zone | `WAF` → **Edit** | create/update the one custom rule referencing that list |

Scope both to the specific account and the specific zone `alex` proxies for — not "All
accounts" / "All zones". Both the Account ID and Zone ID are on the zone's **Overview**
page in the Cloudflare dashboard, right-hand sidebar.

Paste the token into the plugin's UI, then click **Test Connection** before doing anything
else — it checks the token is valid and that both scopes actually work (a live, read-only
check: it does not create or modify anything), and reports exactly which one is missing if
either fails. **The `Enabled` toggle stays disabled until a test succeeds** — server-side,
not just in the UI, so there's no way to accidentally flip it on unconfigured.

**Defaults are deliberately inert**: `enabled: false` and `dry_run: true` out of the box.
Nothing calls Cloudflare until you flip both on from the plugin's UI, after reviewing what
it would have done in the recent-actions log.

## Status

v0.1 — scaffolded and smoke-tested standalone: introspect output, config persistence, UI,
status API, setup gating (server-side, not just client-side), and a live `/api/test` round
trip to Cloudflare's real API (confirmed it fails gracefully on bad credentials) all
verified. **Not yet tested against a real, correctly-scoped Cloudflare zone** — the
`internal/cloudflare` client is written to the documented API shapes but wants a live
smoke test with a real scoped token before `dry_run` gets switched off for real.

Not yet implemented: unblocking / list pruning (a full list currently just stops accepting
new blocks rather than evicting old ones), and folding in the `Fail2ban/` filter rules from
the homelab repo as an additional pattern source (planned next).

## Licensing note

This repo is MIT (see `LICENSE`). `mod/zoraxy_plugin/` is vendored, unmodified, from
[tobychui/zoraxy](https://github.com/tobychui/zoraxy) (AGPL-3.0) — it's the IPC glue every
Zoraxy plugin's own docs tell you to copy in, used here strictly out-of-process over
loopback HTTP, not linked into Zoraxy itself. See `mod/zoraxy_plugin/VENDORED_FROM.txt`.
