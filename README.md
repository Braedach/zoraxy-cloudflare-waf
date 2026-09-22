# zoraxy-cloudflare-waf

A [Zoraxy](https://zoraxy.aroz.org) reverse proxy plugin that watches Zoraxy's own access
log and blacklist events for abusive clients, and mirrors them into a Cloudflare **IP
List** referenced by a single custom WAF rule — so Cloudflare's edge blocks them before
they ever reach the proxy again. Optionally it also bans them in Zoraxy's own blacklist as a second layer, and
blocks expire automatically.

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
   matches.
2. **Event subscriber** listens for Zoraxy's own `blacklistedIpBlocked` event, so an IP
   your existing access-rule blacklist just blocked gets mirrored into Cloudflare
   immediately.

Every candidate is validated (`internal/ipfilter`) against Cloudflare's own published edge
ranges before it's ever sent to Cloudflare — a candidate IP that's private/loopback, or
that's itself a Cloudflare edge IP (meaning something upstream read the wrong header), is
rejected rather than blocked. **Always trust `CF-Connecting-IP`, never
`X-Forwarded-For`**, on tunnel-relayed traffic — the latter is attacker-controlled.

## Setup

Requirements: **Zoraxy 3.3.4 or newer**, linux/amd64 (the only architecture currently built — see
[Releases](https://github.com/Braedach/zoraxy-cloudflare-waf/releases)), and a Cloudflare API token if you want the Cloudflare
layer (scoping below). The plugin ships inert: `enabled: false`, `dry_run: true`.

**Option A — download the release** (no Go needed):

```bash
curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/latest/download/cloudflarewaf_linux_amd64
curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS            # must print: cloudflarewaf_linux_amd64: OK
```

`icon.png` and `cloudflarewaf.example.json` come from this repository.

**Option B — build from source:**

```bash
go build .                          # local sanity build
./build.sh                          # cross-compile linux/amd64 into ./build/
```

Copy the binary (from either option) into Zoraxy's plugin folder (`<zoraxy dir>/plugins/`; the paths below assume `/srv/zoraxy` —
adjust to your install, and use `scp` if Zoraxy runs on another machine):

```bash
PLUGIN_DIR=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
mkdir -p "$PLUGIN_DIR"
cp cloudflarewaf_linux_amd64 "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"   # or build/zoraxy-cloudflare-waf_*_linux_amd64
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

## Status

**v0.3.0 — working in production.** Both layers have been running on a live proxy (Zoraxy behind a Cloudflare tunnel) since
2026-09-21, the Zoraxy-blacklist layer since 2026-09-22.

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
- *Tests:* the Cloudflare and Zoraxy clients are unit-tested against fake servers that record every request — including that a
  failed read never leads to a write, that other rules are never resent, and that expiry only removes entries this plugin created
  (`go vet ./... && go test ./...`, no network needed; race detector clean).

**Not yet exercised in production:** an actual expiry *removal*. The pruner has run hourly against a real list for days and
correctly found nothing old enough to remove (default 14 days), so deletion is so far covered only by the tests.

**Not implemented:** a manual "unblock this IP" button, architectures other than linux/amd64, and additional pattern sources
(for example fail2ban filter rules).

## Development

```bash
go vet ./... && go test ./...        # no network: the Cloudflare client is tested against a fake API server
```

## Licensing note

This repo is MIT (see `LICENSE`). `mod/zoraxy_plugin/` is vendored, unmodified, from
[tobychui/zoraxy](https://github.com/tobychui/zoraxy) (AGPL-3.0) — it's the IPC glue every
Zoraxy plugin's own docs tell you to copy in, used here strictly out-of-process over
loopback HTTP, not linked into Zoraxy itself. See `mod/zoraxy_plugin/VENDORED_FROM.txt`.
