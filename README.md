# zoraxy-cloudflare-waf

A [Zoraxy](https://zoraxy.aroz.org) reverse proxy plugin that watches Zoraxy's own access
log and blacklist events for abusive clients, and mirrors them into a Cloudflare **IP
List** referenced by a single custom WAF rule — so Cloudflare's edge blocks them before
they ever reach the proxy again. Optionally it also bans them in Zoraxy's own blacklist as a second layer, and
blocks expire automatically.

## At a glance

- **What it is:** a Zoraxy plugin that turns scanner behaviour in Zoraxy's own access log into automatic bans at Cloudflare's edge, with an optional second layer in Zoraxy's blacklist. Bans expire; it ships in dry-run.
- **Who it is for:** anyone publishing services through Zoraxy and Cloudflare (the Free plan is enough) who wants scanners stopped in seconds without hand-copying addresses.
- **Status:** v0.3.4, running in production since 21 September 2026, 71 tests, reproducible release builds. In October to the 25th it banned 107 distinct addresses.
- **New in v0.3.4:** the settings page's "How this works" text is corrected and completed (dry run covers both layers, the cooldown, Zoraxy-only mode, the full list of scanner paths, history now survives restarts). Since v0.3.3 the Recent actions table survives restarts (`zoraxy_actions.jsonl`). Docs: the multi-zone workaround, the 30-minute heartbeat and a weekly report script.
- **Also in this repository:** [`scripts/forensic-report.sh`](scripts/README.md), a read-only weekly report of what reached your proxy and what was refused; [a public analysis of six months of real scanner traffic](docs/forensic/README.md); [a guide to reading that report, including when an AI writes the analysis](docs/forensic/REPORT-GUIDE.md).
- **The story and the reasoning:** [Zoraxy: Reverse Proxy](https://www.braedach.com/zoraxy-reverse-proxy-2/) on the author's blog.

**Where to find things:** [Setup](#setup) · [Upgrading](#upgrading) · [How to tell it is working](#how-to-tell-it-is-working) ·
[Troubleshooting](#troubleshooting) · [Uninstalling and cleaning up](#uninstalling-and-cleaning-up) ·
[Verifying a release](#verifying-a-release) · [Security and privacy](#security-and-privacy) · [Known limits](#known-limits) ·
[Compatibility](#compatibility) · [Testing](docs/TESTING.md) · [Weekly report script](scripts/README.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) ·
[Reporting a vulnerability](SECURITY.md)

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
   `zr_YYYY-M.log`, reading the `[client: ip]`, request-path and status-code fields Zoraxy
   writes on every line. A
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
   matches. One exact-path exception exists, for an application's own front-end file that looks like a probe:
   n8n's `/types/credentials.json` (a static list of credential *types*). It matches the whole path only, so
   `/credentials.json` and lookalikes are still flagged.
2. **Event subscriber** listens for Zoraxy's own `blacklistedIpBlocked` event, so an IP
   your existing access-rule blacklist just blocked gets mirrored into Cloudflare
   immediately.

Every candidate is validated (`internal/ipfilter`) against Cloudflare's own published edge
ranges before it's ever sent to Cloudflare — a candidate IP that's private/loopback, or
that's itself a Cloudflare edge IP (meaning something upstream read the wrong header), is
rejected rather than blocked. **Always trust `CF-Connecting-IP`, never
`X-Forwarded-For`**, on tunnel-relayed traffic — the latter is attacker-controlled.

## Setup

Requirements: **Zoraxy 3.3.4 or newer**, Linux, and a Cloudflare API token if you want the Cloudflare layer (scoping below).
The plugin ships inert: `enabled: false`, `dry_run: true`.

[Releases](https://github.com/Braedach/zoraxy-cloudflare-waf/releases) carry `amd64`, `arm64`, `arm` (ARMv7) and `386` builds,
all static and from the same commit. **`amd64` is the architecture in production use; `386` has been executed (its `-introspect` output checked); `arm64`
and ARMv7 are cross-compiled and have not been run on real hardware by the author** — they should work, but please report
anything that doesn't.

**Option A — download the release** (no Go needed; substitute your architecture):

```bash
ARCH=amd64        # amd64 | arm64 | arm | 386
curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/latest/download/cloudflarewaf_linux_$ARCH
curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # must print: cloudflarewaf_linux_<arch>: OK
```

`icon.png` and `cloudflarewaf.example.json` come from this repository.

**Option B — build from source:**

```bash
go build .                          # local sanity build
./build.sh                          # cross-compile linux/amd64 into ./build/
./build.sh release                  # every published architecture + SHA256SUMS, into ./build/release/
```

Copy the binary (from either option) into Zoraxy's plugin folder (`<zoraxy dir>/plugins/`; the paths below assume `/srv/zoraxy` —
adjust to your install, and use `scp` if Zoraxy runs on another machine):

```bash
PLUGIN_DIR=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
mkdir -p "$PLUGIN_DIR"
cp cloudflarewaf_linux_$ARCH "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"   # or build/zoraxy-cloudflare-waf_*_linux_*
cp icon.png "$PLUGIN_DIR/icon.png"
cp cloudflarewaf.example.json "$PLUGIN_DIR/cloudflarewaf.json"
chmod 755 "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"; chmod 600 "$PLUGIN_DIR/cloudflarewaf.json"
```

**The executable must be named exactly like its folder** — Zoraxy 3.3.4 rejects it with `no valid entry
point found` otherwise. The folder name itself is free (Zoraxy's plugin-store installer names both after the
plugin's display name, "Zoraxy Cloudflare WAF plugin"). Zoraxy reads the plugins folder at startup, so if a
newly copied plugin doesn't appear, restart Zoraxy.

Then, from Zoraxy's admin UI, enable the plugin and open its page (under the Plugins section). Do the
rest of the setup there — paste the token, account ID and zone ID directly, rather than hand-editing the
JSON. The page has a collapsible **How this works** section that covers the same ground as this README.
The token, account ID and zone ID fields are masked (use **Show**; they re-hide after 15 seconds).

To pick up a replaced binary, restart Zoraxy.

Once the plugin is listed in Zoraxy's own plugin store, installing it from there does all of the above for you: Zoraxy creates the
folder, names the binary to match, downloads the icon, and shows you the API permissions the plugin asks for before you enable it.

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
- **Zone Resources** → `Include` → the specific zone(s) this proxy serves, not "All zones".
- **Client IP Address Filtering** (optional) → leave blank for the first deploy. This
  restricts which source IP the API calls may come from - since the plugin runs *on* the
  Zoraxy host, that means that host's public egress IP, **not** whatever machine you're
  creating the token from (don't click "Use my IP" unless you're on the same connection the
  Zoraxy host egresses through). A locked-down IP filter is good extra hardening once you know that
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
account ID and zone ID are all set, or **Also ban in Zoraxy** is ticked (Zoraxy-layer-only mode) — so it can't be switched on unconfigured.

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

- The **Recent actions** table on the plugin's page, restored from `zoraxy_actions.jsonl` (next to the plugin binary) when the plugin
  starts, so a restart no longer empties it (from v0.3.3; earlier versions kept it in memory only).
- The Zoraxy journal, which keeps history (Zoraxy captures the plugin's output):

  ```bash
  journalctl -u zoraxy -f | grep -F "Zoraxy Cloudflare WAF plugin"
  ```

  You'll see the config summary at startup (never the credentials — only whether they're set),
  `logtail: following <file>`, one `action: <result> ip=… source=… reason=… detail=…` line per decision
  (the reason is `sensitive-path probe (vcs): /.git/config`, `exploit-pattern-match in request line` or
  `more than N 4xx/5xx responses within Ws`)
  (`blocked`, `partial`, `dry-run`, `expired`, `error`, `skipped-invalid-ip`, `skipped-disabled`, `skipped-list-full`; repeat
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

### Automatic expiry

Blocks this plugin created are removed automatically once they are older than **Remove blocks automatically after
(days)** — default **14**, `0` keeps them forever. Many scanners use rented cloud addresses that are later reused by
legitimate services, so a permanent block slowly becomes a false positive.

- Runs hourly (first pass two minutes after start) and **only while live** — never in dry run or while disabled.
- Only entries the plugin added are ever removed: Cloudflare list items whose comment starts `zoraxy/`, and bans it
  recorded in `zoraxy_bans.json` (below). Anything you added by hand, in either place, is never touched.
- An item's age is Cloudflare's own `modified_on` time (re-adding an IP refreshes it). An item whose age can't be read is
  left alone.
- Safety: if listing the items fails, nothing is deleted; a delete with no item IDs is refused outright; at most 200
  items are removed per run (the rest follow on later runs), in batches of 100.
- The action log shows one `expired` line per run; the journal says `expiry: removed N …`, or once an hour
  `expiry: checked N Cloudflare list item(s), M added by this plugin, none older than D days` so you can see it is running.

### Zoraxy's own blacklist (optional second layer)

Tick **Also ban blocked IPs in Zoraxy's own access-rule blacklist** and every blocked IP is also added to the blacklist of
the Zoraxy access rule(s) you choose (default: the `default` rule), **in addition to** Cloudflare. The layers are
independent: if one fails and the other works the action shows as `partial` with the failing layer's reason in the Detail
column, and with the box ticked the plugin can even run **without Cloudflare credentials** (Zoraxy layer only).

Zoraxy's Quick Ban tab is only a shortcut list (today's busiest client IPs) — it can't be edited. The blacklist behind it
accepts any IP or range, and Zoraxy provides no automatic detection of abusers; detecting them is what this plugin adds.

**What has to be true for a ban to actually block anything** (the page warns about the first; the rest is on you):

1. **The rule's blacklist must be switched on** in Zoraxy (per access rule). A ban added to a rule whose blacklist is off is
   accepted and silently does nothing — the picker and the action log say so.
2. **Zoraxy must see the visitor's real address.** An access rule judges the TCP peer's address unless *Trust proxy headers
   only* is on **and** the peer is in Zoraxy's trusted-proxy list, in which case it reads `CF-Connecting-IP` /
   `X-Real-IP` / `X-Forwarded-For`. Behind a Cloudflare tunnel the peer is the box running `cloudflared` — `127.0.0.1`/`::1`,
   or the box's **own LAN address** if the tunnel's service URL resolves to it — none of which are in Zoraxy's default
   trusted list (Cloudflare's public edge ranges only). Until they are, the rule sees the box's own address: a country
   whitelist with "allow local and loopback" waves everything through and no blacklist entry matches a real visitor.
   Add all of the box's own addresses to Zoraxy's trusted proxies and turn **Trust proxy headers only** on for **every
   rule that filters by IP or country — including the built-in Default rule**. With it off a rule *never* reads the
   real-IP header, even from a trusted peer: on the author's setup a request claiming a blocked country got `200` on a
   Default-rule host until the switch was turned on, and `403` afterwards. Then verify from the box itself (a fake client
   IP in the header must get `403` on a host whose rule blocks that country, for each address `cloudflared` may connect
   from):

   ```bash
   curl -sk -o /dev/null -w '%{http_code}\n' --resolve <host>:443:<this-box-LAN-IP> \
        -H 'CF-Connecting-IP: 8.8.8.8' https://<host>/
   ```

   Cloudflare-side blocking is unaffected by any of this, which is why a misconfigured Zoraxy goes unnoticed.
   The box's LAN address usually comes from DHCP: give it a router reservation, or the trusted entry silently goes stale
   when the lease changes.
3. **Permissions.** The plugin declares the few Zoraxy API calls it needs (`GET /plugin/api/access/list`,
   `POST /plugin/api/blacklist/ip/add`, `POST …/ip/remove`, `GET …/blacklist/list`); Zoraxy lists them in the plugin's
   info page and issues the plugin an API key for exactly those. **Restart Zoraxy once** after installing this version so the
   key is issued. Zoraxy grants permission per endpoint, not per rule, so the key could ban into any rule; the plugin only
   ever touches the rules you tick, and only calls these endpoints when the box is ticked (plus a read-only rule listing for
   the picker).

Zoraxy's list call returns bare IPs with no dates, so the plugin keeps its own record of what it banned and when —
`zoraxy_bans.json` next to its binary (mode 0600; a corrupt file is moved aside, never overwritten). That record is what
expiry uses, and it means bans an operator added by hand are never removed. Bans are single IPs (no ranges), and adding an IP
that is already banned is harmless.

Upstream note: Zoraxy has an open report that IP whitelist/blacklist checks can be bypassed by spoofing proxy headers
([tobychui/zoraxy#978](https://github.com/tobychui/zoraxy/issues/978)); Zoraxy-side bans are only as strong as your trusted-proxy
setup, whereas Cloudflare's edge decision uses the real connection. Keep Cloudflare as the primary layer.

### Plugin UI constraints (Zoraxy 3.3.x)

Zoraxy embeds plugin pages in `<iframe sandbox="allow-scripts allow-same-origin">`. That means **no
`<form>` submission** (silently swallowed — no event, no request; use a button + `fetch`), no `alert()` /
`confirm()`, and no link navigation (`target=_top` / popups are blocked — show URLs as text). POSTs must send
the CSRF token (injected into the page as `{{.csrfToken}}`) back in an **`X-CSRF-Token`** header.

## Troubleshooting

**The Recent actions table is empty.** From v0.3.3 it is restored from `zoraxy_actions.jsonl` on start, so an empty table means the file is
missing or unreadable (the journal says why: look for `history:` lines). On v0.3.2 and earlier it was kept in memory only and a restart
cleared it. Either way nothing is lost: the blocks themselves, the Cloudflare list, the Zoraxy bans and the plugin's own ban record all
survive a restart. The other durable log is the journal — `journalctl -u zoraxy | grep -F "Zoraxy Cloudflare WAF plugin"` — which also carries a heartbeat every 30 minutes and an
hourly expiry line, so you can tell "running, nothing to do" from "not running".

**Nothing appears in Cloudflare.** Expected until the first real block: the IP list and the WAF rule are created lazily. Until then
Test Connection is the way to check the credentials. Also make sure **Dry run** is off — in dry run the plugin only logs what it
would do.

**A block failed with "maximum number of lists".** Cloudflare limits how many custom *lists* an account may have, separately from
the 5 custom rules; see [Cloudflare limits](#cloudflare-limits-and-how-this-plugin-manages-them).

**Zoraxy bans don't block anything.** Two things must be true, and both are easy to miss behind a tunnel or proxy: the access
rule's **blacklist must be switched on**, and Zoraxy must see the visitor's real address (trusted proxies + *Trust proxy headers
only*, **including for the Default rule**). See [Zoraxy's own blacklist](#zoraxys-own-blacklist-optional-second-layer).

**The plugin doesn't appear in Zoraxy.** The executable must be named exactly like its folder, and Zoraxy reads the plugins folder
at startup — restart it after copying a plugin in by hand.

**A legitimate visitor was blocked.** Remove the IP from the Cloudflare list (and from the access rule's blacklist if the Zoraxy
layer is on). There is no unblock button in the plugin yet. Detection is deliberately narrow — see
[How it works](#how-it-works) for exactly what triggers a block.

## Compatibility

- **Zoraxy:** 3.3.4 or newer. Used in production on 3.3.4, 3.3.5 and the 3.3.5 release candidates 2, 3 and 4 (linux/amd64), including
  across Zoraxy's own self-updates.
- **Cloudflare:** any plan that has custom WAF rules and account IP lists. The Free plan works; its limits (five custom rules per zone,
  a small list quota) are described [above](#cloudflare-limits-and-how-this-plugin-manages-them).
- **Architectures:** see [Setup](#setup).

## Upgrading

Your settings (`cloudflarewaf.json`) and the ban record (`zoraxy_bans.json`) live next to the binary and are **not** touched by an upgrade.

1. Read the [changelog](CHANGELOG.md) for anything that needs your attention.
2. Download the new binary and `SHA256SUMS` and verify them exactly as in [Setup](#setup).
3. Replace the binary **by renaming a new file over the old one** (a running binary cannot be overwritten in place):

   ```bash
   PLUGIN_DIR=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
   cp "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf" /root/cloudflarewaf.previous       # keep a rollback copy
   install -m 755 cloudflarewaf_linux_$ARCH "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new"
   mv -f "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new" "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"
   ```
4. Restart Zoraxy (it launches plugins at startup; a restart briefly interrupts proxying, so pick a quiet moment).
5. Check the [health signs](#how-to-tell-it-is-working) below. To roll back, put the previous binary back the same way and restart.

## How to tell it is working

1. **The process and version.** The plugin's journal line shows the loaded settings (credentials are reported only as `credentials_set=true`):

   ```bash
   journalctl -u zoraxy | grep -F "Zoraxy Cloudflare WAF plugin" | grep "loaded config" | tail -1
   ```

   Expect `enabled=true dry_run=false` once you have gone live. The binary reports its version with `./<binary> -introspect`.
2. **It is alive.** An hourly `expiry:` line and a `logtail: alive` line (every 30 minutes) appear, with no `error`, `fail` or `panic` lines.
3. **The places a ban lives agree.** For the addresses the plugin banned, three counts should match: the Cloudflare IP list (Cloudflare
   dashboard, Manage Account, Configurations, Lists), the plugin's ban record (`python3 -c 'import json; print(len(json.load(open("zoraxy_bans.json"))))'`),
   and the blacklist of each Zoraxy access rule you selected (Zoraxy UI, Access Rules). No private or loopback address should be on the list.
   A mismatch means one layer failed; the journal line for that ban says which.
4. **A harmless end-to-end test.** Request a path no real client asks for, for example `/.git/config`, from an address you do not mind banning
   (not your own), then look for an `action: blocked` line. Remove the test address afterwards (see [Troubleshooting](#troubleshooting)).

## Uninstalling and cleaning up

The plugin creates things in your Cloudflare account and in Zoraxy that it **does not delete itself**. To remove it completely:

1. **Disable the plugin** in Zoraxy's plugin page, or delete its folder, and restart Zoraxy.
2. **Cloudflare, the rule first.** Security, Security rules: delete the custom rule the plugin created (its name is the **WAF rule name** setting; the
   default is `Zoraxy CF WAF Sync - managed IP blocklist`). Only that rule; the plugin never edited any other.
3. **Cloudflare, then the list.** Manage Account, Configurations, Lists: delete the IP list (the **IP list name** setting; default
   `zoraxy_cf_waf_blocklist`). Cloudflare refuses to delete a list a rule still uses, so do step 2 first.
4. **Zoraxy's blacklists.** If you used the second layer, remove the addresses the plugin added from the access rules you selected. They are
   the keys of `zoraxy_bans.json`:

   ```bash
   python3 -c 'import json; print("\n".join(json.load(open("zoraxy_bans.json"))))'
   ```
5. **Revoke the API token** in Cloudflare (My Profile or Manage Account, API Tokens) and delete the plugin folder. The folder's `cloudflarewaf.json` holds the token; `zoraxy_actions.jsonl` (v0.3.3 and later) is the history of what the plugin did.

## Verifying a release

Every release has a `SHA256SUMS` file; check it as shown in [Setup](#setup). You can also rebuild a release yourself and compare, because the builds
are reproducible: with the Go 1.24 toolchain, `git checkout vX.Y.Z && ./build.sh release` produced binaries byte-for-byte identical to the published
`cloudflarewaf_linux_*` files for v0.3.1 and v0.3.2 on all four architectures (checked 21 October 2026). v0.3.0 predates the release build recipe and will
not match.

## Security and privacy

- **What it talks to.** Outbound only: `api.cloudflare.com` (the API calls your token authorises: list and rule management) and
  `www.cloudflare.com/ips-v4` and `/ips-v6` (Cloudflare's published address ranges, so the plugin never bans Cloudflare itself). It sends nothing to
  the author or any third party, and has no telemetry. Its page is served on `127.0.0.1` only, through Zoraxy's plugin proxy.
- **What it asks Zoraxy for.** Four API permissions, shown by Zoraxy before you enable the plugin: list access rules, read a blacklist, and add or remove a
  blacklist entry. They are used only for the optional Zoraxy layer.
- **Your credentials.** The Cloudflare token lives in `cloudflarewaf.json` (mode 600) in the plugin folder, is masked in the page, and is never written to the journal.
  Give it only the two scopes listed under [Creating a correctly scoped API token](#creating-a-correctly-scoped-api-token).
- **What it changes in Cloudflare.** One account IP list and one custom WAF rule that references it. It never resends or edits your other rules (the tests prove
  that, including that a failed read never leads to a write).
- **Files it writes**, next to the binary: `cloudflarewaf.json`, `zoraxy_bans.json` (and a short-lived `zoraxy_bans.json.tmp`, or `zoraxy_bans.json.corrupt-<time>` if the file was ever unreadable) and, from v0.3.3, the action history `zoraxy_actions.jsonl` (mode 600, at most about 10 MB with its one rotated copy `zoraxy_actions.jsonl.1`; it holds only what the journal already shows, no credentials).
- **Safe by default.** It ships disabled and in dry-run, so it does nothing until you turn it on and turn dry-run off.
- **Reporting a vulnerability:** see [SECURITY.md](SECURITY.md).

## Known limits

- **One Cloudflare account and one zone per plugin instance.** The IP list is account-wide, but the plugin creates and maintains the WAF rule in a single zone.
  Several zones behind one Zoraxy are not supported yet (asked for in [issue #5](https://github.com/Braedach/zoraxy-cloudflare-waf/issues/5)).
  **Workaround that works today:** because the IP list is account-wide, add the one-line custom rule `ip.src in $<your_list_name>` by hand in every other zone
  of the same account, with the action you prefer (Managed Challenge or Block). The plugin keeps the list current and never edits a rule it did not create,
  so the two do not interfere. Native multi-zone support is under consideration and waiting on answers in the issue (same account? same action in every zone?).
  Zones in a different Cloudflare account cannot share the list and would need their own instance.
- **No manual "unblock this IP" button.** Remove the address from the Cloudflare list and from the Zoraxy access rules by hand (see [Troubleshooting](#troubleshooting)).
- **The Recent actions table shows the last 200 actions.** From v0.3.3 it is restored from `zoraxy_actions.jsonl` after a restart (on v0.3.2 and earlier it was in memory only and a restart emptied it). The journal remains the other durable record.
- **Detection is deliberately narrow** (see [How it works](#how-it-works)): a few path families, exploit patterns and error bursts. It is a reflex against scanners, not a full WAF.
- **A request Cloudflare itself blocks never reaches Zoraxy's log**, so the plugin cannot learn from it.

## Status

**v0.3.4 — working in production** (v0.3.4 corrects the settings-page help text only; the persistent action history, new in v0.3.3, was deployed on 21 October 2026; the results below are from v0.3.0 to v0.3.2 unless stated). Both layers have been running on a live proxy (Zoraxy behind a Cloudflare tunnel) since
2026-09-21, the Zoraxy-blacklist layer since 2026-09-22.

- *Production results to 21 October 2026 (v0.3.0 to v0.3.2):* in October the plugin banned **94 distinct scanner addresses**, about 40 of them in Google Cloud
  ranges, from 97 ban actions: 81 by a sensitive-path probe, 10 by an error burst, 5 relayed from Zoraxy's own blacklist and 1 by an exploit pattern; from the triggering request to the ban the median was 3 seconds (1 to 4 seconds for the sensitive-path detector, which does most of the work; error bursts take about 30 seconds by design, because they must wait for the evidence), and while an address was banned every request that reached Zoraxy was refused by its blacklist. On 21 October the Cloudflare list, the plugin's ban record and the blacklists of both selected
  Zoraxy rules all held the same 62 addresses, no private or loopback address was on the list, and the journal showed no errors, with the 30-minute heartbeat and
  hourly expiry lines throughout. Expiry has been removing aged bans from both layers (77 expiry actions since the first on 6 October) without error. The v0.3.1 and
  v0.3.2 release binaries rebuild byte-for-byte identical from their tags (see [Verifying a release](#verifying-a-release)).
- *Latest soak — 12.7 hours with both layers live:* **15 blocks, every one a genuine scanner** (`.DS_Store` and `/.git/config`
  sweeps, Laravel `/.ENV` probes, `/.claude`/`/.codex` credential hunts, and two Metabase CVE probes that arrived through
  Zoraxy's own `blacklistedIpBlocked` event). **No false positives and no misses** — no public IP that hit a detection rule went
  unblocked. No errors, ~11 MB RSS, ~0 CPU. The three records agreed exactly: 15 tracked bans, 15 IPs in each of the two selected
  Zoraxy access rules, and the matching Cloudflare list items. Bans and the ban store survived two Zoraxy restarts.
  Enforcement was observed in the wild, not just in tests: a scanner banned at 23:43:46 had its next requests answered with `403`
  by Zoraxy eight seconds later.
- *Earlier, Cloudflare layer only:* within 17 hours of going live it blocked 9 scanner IPs and Cloudflare's counter showed **262
  hits** on the WAF rule; 6 of the 9 never came back and the other 3 stopped within 4–19 seconds (the list update propagating).
  It also survived a Zoraxy self-update (3.3.4 → 3.3.5) and a host reboot unattended.
- *Before that, a 38-hour dry run* (~170,000 log lines, 156 public IPs): 8 IPs flagged, all genuine — and it exposed the
  threshold rule missing scanners that hit single-page apps, which is why the path probes exist.
- *The Cloudflare write path* was reviewed against Cloudflare's documentation before going live, which found and fixed three
  defects a dry run cannot reveal (a whole-list `PUT` that would have resent the operator's own rules stripped of fields; a failed
  read treated as "no rules"; and a non-existent `PATCH …/items` call — items are added with `POST …/items`). The first live
  attempt then hit the account's **list quota** (Cloudflare error 10019) and stopped safely without writing anything else; that
  error is now explained in plain words, and Test Connection shows the account's lists up front.
- *Tests:* **71 tests in 5 packages, all passing, race detector clean, `gofmt` and `go vet` clean** (v0.3.3, 21 October 2026; v0.3.2 had 63). The Cloudflare and
  Zoraxy clients are tested against fake servers that record every request — including that a failed read never leads to a write, that other rules are
  never resent, and that expiry only removes entries this plugin created. No network is needed. What each test proves is in [docs/TESTING.md](docs/TESTING.md).

**Expiry removal is verified in production.** The first bans reached 14 days on 2026-10-06 and have been removed hourly since,
from the Cloudflare list and from Zoraxy's blacklist together, with no errors. Only entries this plugin created were touched.
(v0.3.0 logged an address removed from both layers twice and counted it twice, e.g. `ip=2 IP(s)` for one address; v0.3.1
reports each address once. The removals themselves were always correct.)

**Not implemented:** a manual "unblock this IP" button, more than one Cloudflare zone per plugin instance, and additional pattern sources
(for example fail2ban filter rules).

## Development

```bash
gofmt -l .                           # must print nothing
go vet ./... && go test -race ./...  # no network: the Cloudflare client is tested against a fake API server
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and [docs/TESTING.md](docs/TESTING.md) for what the suite covers.

## Licensing note

This repo is MIT (see `LICENSE`). `mod/zoraxy_plugin/` is vendored, unmodified, from
[tobychui/zoraxy](https://github.com/tobychui/zoraxy) (AGPL-3.0) — it's the IPC glue every
Zoraxy plugin's own docs tell you to copy in, used here strictly out-of-process over
loopback HTTP, not linked into Zoraxy itself. See `mod/zoraxy_plugin/VENDORED_FROM.txt`.
