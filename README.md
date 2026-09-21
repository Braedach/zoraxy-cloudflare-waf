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
configured by hand, and the code is written so that it can't:

- **Your other rules are never re-sent.** The plugin adds its rule with Cloudflare's single-rule call
  (`POST /zones/{zone}/rulesets/{id}/rules`) and later edits only that rule (`PATCH …/rules/{rule id}`).
  The whole-list `PUT` — which Cloudflare documents as *replacing every rule in the phase* — is used only to
  create the phase's very first rule on a zone that verifiably has none (it lists the zone's rulesets first to
  confirm). Fields the plugin doesn't model on your rules (`action_parameters`, logging, disabled state…)
  therefore can't be lost.
- **A failed read writes nothing.** If reading the zone's current rules fails for any reason — timeout, rate
  limit, 5xx, 403 — the plugin stops. Only an explicit 404 ("no rules yet") is treated as an empty zone.
- **Your rules are never adopted by name.** The plugin recognises its own rule by the Cloudflare-assigned rule
  ID once it has created it. Before that (no ID stored yet) it adopts a rule with the same **WAF rule name**
  only if that rule already references the plugin's list; a same-named rule that doesn't is treated as yours,
  left untouched, and blocks are reported as `error` in the action log. **Test Connection warns you about such
  a clash in advance.**

**A separate, easily-missed limit: how many *lists* an account may have.** This is not the same as the 5 custom
*rules* above. Cloudflare's quota for custom lists depends on your plan and is small on Free (check **Manage Account →
Configurations → Lists**); the plugin needs one. If the account is already at its quota, the first real block fails with
Cloudflare error 10019 ("maximum number of lists") — the plugin stops before creating a rule or touching any of yours, and
reports it in the action log with the names of the lists you do have. To fix it, either free a list (delete an unused one —
Cloudflare refuses while *any* rule in *any* zone of the account still uses it, so a parked domain's rule can be the culprit) or
set **IP list name** to an existing **IP** list that is only a block list. **Never reuse an allow list**: blocked IPs added to it
would be let through. Test Connection shows your lists and warns about all of this before you go live.

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
   client becomes a block candidate by any of three routes:
   - an **exploit pattern** in the request line (path traversal, `/etc/passwd`, `/actuator/`, …);
   - a **sensitive-path probe** — asking for something only a scanner asks for, *whatever the response
     status*: VCS metadata (`/.git/…`, `/.svn/…`, `/.hg/…`), `/.env`, tool/cloud credential directories
     (`/.aws/`, `/.docker/`, `/.kube/`, `/.ssh/`, `/.azure/`, `/.gcloud/`, `/.config/`, `/.anthropic/`,
     `/.vscode/`, `/.idea/`), credential dotfiles (`.netrc`, `.npmrc`, `.pypirc`, `.htpasswd`, `.htaccess`,
     `.bash_history`, `.DS_Store`), credential-named files (`credentials.json`, `client_secret.json`,
     `service-account.yaml`, …) and SSH keys (`id_rsa`, `id_ed25519`, …). Matching is on the request path only,
     case-insensitive, and also on the percent-decoded path;
   - more than the configured number of **4xx/5xx responses** in the configured window.

   *Why the path probes exist:* single-page apps answer **any** path with `200` and their index page, so a
   scanner sweeping them never produces the errors the threshold counts. On a real 38-hour sample, the
   threshold rule flagged 8 scanner IPs and missed 9 more that the path rules catch (17 in total); none of the
   other ~140 public IPs in that sample was flagged by them. The set is deliberately narrow: bare `.php`, `phpinfo`, `wp-*`,
   `config.json`, `.zip`/`.bak`/`.sql` are **not** included, because legitimate sites use them and a false
   positive locks an operator out of their own site. `/.well-known/` (ACME, webfinger, nodeinfo) never
   matches.
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
either fails. It also reports how many custom rules the zone already has (Free plans allow 5 in total) and
warns if the WAF rule name clashes with one of your existing rules. It also lists the custom lists your account
already has (name, type, items, how many rules use each) and warns if creating the plugin's list would likely hit
the list quota, if the list you named is not an IP list, or if it is used by rules that aren't the plugin's.
Test Connection checks whatever is currently typed in the boxes and does **not** save it —
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
  (the reason is `sensitive-path probe (vcs): /.git/config`, `exploit-pattern-match in request line` or
  `more than N 4xx/5xx responses within Ws`)
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

v0.2. **Dry-run verified on a live proxy; live mode not yet run against a real zone.**

- *Verified on Zoraxy 3.3.4 and 3.3.5 (linux/amd64):* introspect output, plugin load (and reload after Zoraxy's
  own auto-update), config persistence, the UI (save, masking, validation, action log), the status API, setup
  gating, journal logging, and Test Connection against a real, correctly-scoped token.
- *38-hour dry-run soak on a real homelab proxy* (~170,000 log lines, 156 public IPs): 8 IPs flagged, every one
  a genuine scanner (a LeakIX crawler, credential-file hunters, `.git/config` sweeps), 0 false positives; no
  errors, ~10 MB RSS, ~0 CPU. It also showed the threshold rule missing scanners that hit single-page apps,
  which is why the path probes were added in 0.2.
- *The Cloudflare write path* was reviewed against Cloudflare's documentation before going live, which found
  and fixed three defects that dry-run can't reveal: a whole-list `PUT` that would have resent the operator's
  rules stripped of unmodelled fields; a failed read being treated as "no rules" (which would have replaced them
  all); and IPs being added with a `PATCH …/items` call Cloudflare doesn't document (items are added with
  `POST …/items`, where re-adding an existing IP just replaces its entry). These paths are now unit-tested
  against a fake Cloudflare API that records every request (`go test ./...`, no network needed).
- *First live attempt (2026-09-21):* the plugin reached Cloudflare, was refused with error 10019 (the account was at its
  list quota — an unused list still referenced by a rule in another zone), and stopped without writing anything
  else, which is the abort-safe behaviour the tests assert. The error is now explained in plain words and Test
  Connection shows the account's lists up front.
- **Still not exercised: a real block against a real Cloudflare zone** — actual list creation, rule creation
  and item add. Treat live mode as unproven until you've watched the first block land in your dashboard, and
  start with `managed_challenge` rather than `block` (bots fail it; a wrongly flagged person can pass it).

Not yet implemented: unblocking / list pruning (a full list currently just stops accepting
new blocks rather than evicting old ones), and folding in the `Fail2ban/` filter rules from
the homelab repo as an additional pattern source (planned next).

## Development

```bash
go vet ./... && go test ./...        # no network: the Cloudflare client is tested against a fake API server
```

## Licensing note

This repo is MIT (see `LICENSE`). `mod/zoraxy_plugin/` is vendored, unmodified, from
[tobychui/zoraxy](https://github.com/tobychui/zoraxy) (AGPL-3.0) — it's the IPC glue every
Zoraxy plugin's own docs tell you to copy in, used here strictly out-of-process over
loopback HTTP, not linked into Zoraxy itself. See `mod/zoraxy_plugin/VENDORED_FROM.txt`.
