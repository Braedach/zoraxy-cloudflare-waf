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
configured by hand — with one caveat: the plugin recognises *its own* rule by the Cloudflare-assigned
rule ID once it has created it, but until that first real block (no ID stored yet) it looks for an
existing rule with exactly the same **WAF rule name** (`rule_description`) and takes that over. So give
the plugin's rule a name that no rule of yours already uses.

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
  alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/com.braedach.zoraxy.cloudflarewaf
scp icon.png \
  alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/icon.png
scp cloudflarewaf.example.json \
  alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/cloudflarewaf.json
```

**The executable must be named exactly like its folder** (`com.braedach.zoraxy.cloudflarewaf`) —
Zoraxy 3.3.4 rejects it with `no valid entry point found` otherwise. Zoraxy only scans the plugins
folder at startup, so restart Zoraxy after the first install.

Then, from Zoraxy's admin UI, enable the plugin and open its page (under the Plugins section). Do the
rest of the setup there — paste the token, account ID and zone ID directly, rather than hand-editing the
JSON. The page has a collapsible **How this works** section that covers the same ground as this README.
The token, account ID and zone ID fields are masked (use **Show**; they re-hide after 15 seconds).

To pick up a replaced binary, restart Zoraxy — it only loads plugin binaries at startup.

### Creating a correctly scoped API token

**Never use the Global API Key.** At
[dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) →
**Create Custom Token**, grant exactly these two permissions and nothing more:

| Scope | Permission | Why |
|---|---|---|
| Account | `Account Filter Lists` → **Edit** | create/update the IP list |
| Zone | `WAF` → **Edit** | create/update the one custom rule referencing that list |

Further down the same form:

- **Account Resources** → `Include` → your specific account by name, not "All accounts".
- **Zone Resources** → `Include` → the specific zone `alex` proxies for, not "All zones".
- **Client IP Address Filtering** (optional) → leave blank for the first deploy. This
  restricts which source IP the API calls may come from - since the plugin runs *on*
  `alex`, that means `alex`'s WAN egress IP, **not** whatever machine you're creating the
  token from (don't click "Use my IP" unless you're on the same connection `alex`
  egresses through). A locked-down IP filter is good extra hardening once you know that
  IP is stable, but a home ISP rotating it would fail every API call until you noticed
  and updated the token — not something to add before the plugin's proven itself.

Both the account "All accounts" would otherwise cover, and the specific zone, are the
minimum blast radius this token needs: even a fully leaked token can only touch this one
account's IP lists and this one zone's WAF rules, nothing else in your Cloudflare account.

Both the Account ID and Zone ID (for the plugin's own config, separate from the token
scoping above) are on the zone's **Overview** page in the Cloudflare dashboard, right-hand
sidebar.

Paste the token into the plugin's UI, then click **Test Connection** before doing anything
else — it checks the token is valid and that both scopes actually work (a live, read-only
check: it does not create or modify anything), and reports exactly which one is missing if
either fails. Test Connection checks whatever is currently typed in the boxes and does **not** save it —
click **Save** afterwards. **The `Enabled` toggle stays locked until credentials are in place** (saved, or
a Test Connection has just succeeded), and the server refuses to save `enabled: true` unless the token,
account ID and zone ID are all set — so it can't be switched on unconfigured.

**Defaults are deliberately inert**: `enabled: false` and `dry_run: true` out of the box.
- **Enabled off** — nothing is acted on.
- **Enabled + Dry run** — every decision is recorded and logged, but **nothing is written to Cloudflare**
  (the only call the plugin makes to your Cloudflare account is Test Connection's read-only check; it also
  downloads Cloudflare's public edge IP ranges, used to avoid ever blocking Cloudflare itself).
- **Enabled, Dry run off** — live. The first real block creates the IP list and the WAF rule if they don't
  exist yet, then adds the IP. Until then Cloudflare shows nothing new; that is expected.

Review what it *would* have done (below) before turning Dry run off.

### Names: IP list vs WAF rule

Two different settings, easy to mix up:

- **IP list name** — the machine name Cloudflare uses inside the rule expression (`ip.src in $<name>`).
  Letters, digits and underscores only, max 50, no spaces (Save rejects anything else). Default
  `zoraxy_cf_waf_blocklist`.
- **WAF rule name** — free-text label shown in Cloudflare's Security Rules list; spaces and capitals are
  fine. **Make it unique** — see the caveat in [Cloudflare limits](#cloudflare-limits-and-how-this-plugin-manages-them).

### Seeing what it is doing

- The **Recent actions** table on the plugin's page. It is in memory only — it empties whenever the plugin
  or Zoraxy restarts.
- The Zoraxy journal, which keeps history (Zoraxy captures the plugin's output):

  ```bash
  journalctl -u zoraxy -f | grep -F "Zoraxy Cloudflare WAF plugin"
  ```

  You'll see the config summary at startup (never the credentials — only whether they're set),
  `logtail: following <file>`, one `action: <result> ip=… source=… reason=… detail=…` line per decision
  (`blocked`, `dry-run`, `error`, `skipped-invalid-ip`, `skipped-disabled`, `skipped-list-full`; repeat
  hits for an already-actioned IP are left out of the journal but still appear in the table), and a
  `logtail: alive` heartbeat every 30 minutes with lines-read / candidates-raised counters.

### Block action

The single managed WAF rule (`ip.src in $<list>`) uses the action chosen in the UI's **Block action**
dropdown; the server rejects anything else:

| Action | Effect |
|---|---|
| `block` | Hard block (default). |
| `managed_challenge` | Cloudflare picks the challenge — gentler on real users behind a shared/CGNAT IP. |
| `js_challenge` | Passive JavaScript check. |
| `challenge` | Interactive (CAPTCHA-style) challenge. |
| `log` | Records the match only, blocks nothing. **Enterprise plans only.** |

`skip` is deliberately not offered (it's an allow-list action and needs parameters this plugin doesn't
send). Changing the action updates the existing rule in place, but only at the next real block — saving the
setting doesn't call Cloudflare.

### Plugin UI constraints (Zoraxy 3.3.x)

Zoraxy embeds plugin pages in `<iframe sandbox="allow-scripts allow-same-origin">`. That means **no
`<form>` submission** (silently swallowed — no event, no request; use a button + `fetch`), no `alert()` /
`confirm()`, and no link navigation (`target=_top` / popups are blocked — show URLs as text). POSTs must send
the CSRF token (injected into the page as `{{.csrfToken}}`) back in an **`X-CSRF-Token`** header.

## Status

v0.1. Verified on Zoraxy 3.3.4 (linux/amd64): introspect output, plugin load, config persistence, the UI
(save, masking, validation, action log), the status API, setup gating, journal logging, log-tail detection
end to end (an exploit-pattern request is detected and correctly refused as a private address), and Test
Connection against a real, correctly-scoped Cloudflare token (token valid, IP-list access, WAF access).
**Not yet exercised: the live write path** — creating the IP list and WAF rule and adding an IP against a real
zone. The `internal/cloudflare` client is written to the documented API shapes but has only been run in
dry-run mode so far; treat live mode as unproven until you've watched a first block yourself.

Not yet implemented: unblocking / list pruning (a full list currently just stops accepting
new blocks rather than evicting old ones), and folding in the `Fail2ban/` filter rules from
the homelab repo as an additional pattern source (planned next).

## Licensing note

This repo is MIT (see `LICENSE`). `mod/zoraxy_plugin/` is vendored, unmodified, from
[tobychui/zoraxy](https://github.com/tobychui/zoraxy) (AGPL-3.0) — it's the IPC glue every
Zoraxy plugin's own docs tell you to copy in, used here strictly out-of-process over
loopback HTTP, not linked into Zoraxy itself. See `mod/zoraxy_plugin/VENDORED_FROM.txt`.
