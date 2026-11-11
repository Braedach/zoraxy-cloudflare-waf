# Changelog

Versions follow the plugin's own `version_major/minor/patch` (shown in Zoraxy's plugin list).

## 0.4.0 — unreleased (tested as release candidate rc2; see `docs/UPGRADING-0.4.0.md`)
**Why:** two things in one release. Issue #5 asked for more than one Cloudflare account and domain. And seven months of real access logs showed where scanner detection could be both earlier and wider. Read `docs/UPGRADING-0.4.0.md` before upgrading: it covers install, **mitigation**, **rollback** and what was tested.

**Security**
- Closes two CodeQL "reflected cross-site scripting" alerts in the vendored Zoraxy plugin glue (`mod/zoraxy_plugin/embed_webserver.go`): the CSRF token Zoraxy passes in a request header was written into the settings page as received. It is now checked against a plain-token pattern first and replaced by the existing placeholder otherwise. The header normally comes from Zoraxy itself and a browser cannot be made to send it cross-site, so the practical risk was low; the scanner was right that the code did not check it.

**Improvements**
- **Several Cloudflare accounts and domains.** Up to three accounts (tabs *Cloudflare Account 1, 2, 3*), each with its own token, Account ID, IP list, rule name and block action, and up to five zones (a zone is one domain) per account: fifteen domains in all. One failing account never stops the others: new result **partial**, naming the account. Expiry runs per distinct list. A single-account setup behaves exactly as before and its settings file is not changed.
- **Three new families of scanner paths, each with its own switch:** known exploit endpoints (PHPUnit, Laravel Ignition, Yii debug, laravel-filemanager, a WordPress plugin hole, scanner "-notfound" canary paths), PHP diagnostics pages (`phpinfo` and friends) and hosting-panel and debug endpoints (cPanel proxy paths, `/server-status`, `/_profiler`, `/telescope/requests`, `/trace.axd`, `/@vite/env`). **`/phpinfo.php`, which earlier versions deliberately ignored, is now flagged.**
- **Two families from v0.3.5** (below) are included: AI-coding-agent configuration and CI definitions, matched at the site root only.
- **Operator control.** The settings page has a tick box per family and a **never-ban list** (exact paths, or a prefix such as `/myapp/*`), applied on Save without a restart. A family that is switched off is named in a WARNING line at start-up and on every save. Invalid entries are refused with a message.
- **Clearer settings page.** "How this works" now begins with Cloudflare's words in plain terms (a zone is a domain; where to find the IDs; how many Zone IDs to enter). It also says exactly when the heartbeat lines appear: `logtail: alive` every 30 minutes always, the hourly `expiry:` line only while live.

**Response time and coverage**
- **Reaction time:** the log is read every **0.5 s instead of 2 s**. A sweep of about 54 paths lasts about four seconds, so the old poll let most of it through before the first request was read. Measured on a test bench: a request written to the log became a detection in **0.03 to 0.48 s (median 0.23 s)**. The time for Cloudflare to add the address comes on top and was not part of that measurement.
- **Coverage:** in seven months of real logs from one proxy (about 1,600 external addresses, roughly 270 of which behaved as scanners and made over half of all external requests), 14 scanners are caught only by the new families: 11 were never banned before (they stayed under the 30-error threshold, with 8 to 101 requests each) and 3 were banned only at their 30th request.
- **Cost:** replaying 143,000 real log lines showed no measurable extra work from the new settings (about 89 microseconds a line with them and 90 without).

**Compatibility (is it breaking?)**
- Settings, history files and Cloudflare objects: no. An existing `cloudflarewaf.json` loads unchanged; new keys are written only when you use a new feature (a second account or domain, a switch or a never-ban path). Older versions ignore the new keys.
- Detection is **stricter by default**. If an application you run legitimately serves one of the paths, its visitors would be banned: untick the family or add the path to the never-ban list (see *Mitigation* in the upgrade guide).

**How it was tested (no private data is used or published)**
- 116 automated tests with the race detector, `gofmt` and `go vet` clean; deliberately breaking the switch or never-ban code makes the new tests fail.
- 48,867 real external requests were replayed through the detector; every scanner caught only by the new families is a multi-path sweep and none looks like an ordinary visitor.
- A throwaway Zoraxy running the real plugin against a **simulated** Cloudflare with three accounts and four domains: all accounts blocked, a failing account (partial, then recovered), a same-named foreign rule left alone, the one-list limit reported by account, dry run (no calls made), expiry on every account's list, all new families reaching every account, switches and the never-ban list, upgrade from an old single-account settings file, and the **documented rollback** to v0.3.5 in both variants.
- The settings page's Save path: the multi-account settings, tokens and labels survive a Save; invalid entries are refused and change nothing; a switch takes effect on the next log line.
- **Not tested:** real second and third Cloudflare accounts (the simulation follows the same API calls the plugin makes on a real account, but it is not Cloudflare), and arm64, ARMv7 and 386 on real hardware (cross-compiled only).

## 0.3.5 — 2026-11-11
**Why this release:** in November scripted sweeps were seen asking for about 54 secrets and configuration paths in roughly 4 seconds, including AI-coding-agent
settings (`/.claude/settings.json`, `/.cursor/mcp.json`) and CI definitions (`/.github/workflows/…`). The plugin already banned most of them on the first
request, but not these, so the sweep ran on until a path it did know arrived.
- New sensitive-path families, banned on the first request like the existing ones: **agent-config** (`/.claude…`, `/.cursor…`, `/.mcp.json`),
  **ci-config** (`/.github/`, `/.gitlab/`, `/.circleci/`, `/.gitlab-ci.yml`, `/.travis.yml`) and three more credential dotfiles (`.boto`, `.s3cfg`, `.amplifyrc`).
- The new families match **at the site root only** (`/.github/…`, not `/owner/repo/src/branch/main/.github/…`), so a git forge such as Gitea, Forgejo or GitLab showing a
  repository's own `.github`, `.claude` or `.gitlab-ci.yml` never gets its readers banned. Scanners ask at the root. Tests cover forge-style URLs.
- `/.github/workflows/ci.yml` at the root was listed as a path that must never be flagged. That was a precaution, not a requirement: no application served through the
  proxy asks for it there. It is now flagged, and the test list says so.
- Still deliberately not flagged: bare `.php`, `phpinfo`, `wp-*`, `config.json`, `.zip/.bak/.sql`, `Dockerfile` and `docker-compose.yml`.
- Detection, expiry and the Cloudflare/Zoraxy calls are otherwise unchanged. 17 new paths are tested at three response statuses; the tests fail without the change (51 failures).

## 0.3.4 — 2026-10-26
**Why this release:** the "How this works" help on the settings page had drifted from the code (it still said the Recent actions table empties on restart, described dry run as Cloudflare-only, and listed only some of the scanner paths). Page text and docs only; **no change to detection, bans, expiry or the Cloudflare/Zoraxy calls.**
- Settings page help corrected: history survives restarts (last 200 actions, `zoraxy_actions.jsonl`); dry run stops both layers; the re-block cooldown (default 24 h) is named and kept apart from expiry (default 14 days); Zoraxy-only mode; the full list of paths that count as a scanner probe; what is never blocked; hourly expiry (200 a run); list-name limit and defaults; never reuse an allow list; what a Zoraxy-side ban needs to work; one account and zone per instance (with the workaround); no unblock button.
- README, full pass: the enable-gate paragraph now states that Zoraxy-only mode can be enabled without Cloudflare credentials; the stale "no automatic pruning yet" sentence replaced (blocks expire automatically); the plugin is described as listed in the Zoraxy store; dry run described for both layers; the re-block cooldown named; the never-validated address kinds completed; "Verifying a release", Known limits and Status updated with the October figures and the 26 October checks; the stale known limit removed.
- `docs/TESTING.md`, `SECURITY.md` and `CONTRIBUTING.md` updated, the last with the release-candidate procedure (feature branch, pre-release, distinct asset names, never merged until tested).
- Docs only: the `logtail: alive` heartbeat is every 30 minutes (README and TESTING.md said hourly); Known limits now document the multi-zone
  workaround and the stale settings-page sentence about the in-memory history. No code change.
- `scripts/forensic-report.sh` v2.11.0: platform status gains per-certificate last-renewed dates and the last 30 days' renewals, a "Monitored-target outages" section from Zoraxy's uptime monitor, and uptime-checker gaps printed as ranges; fixes a stray "Broken pipe" line that could end the Exploit / Probe section. The forensic report is otherwise unchanged. No plugin code change.
- Added `scripts/forensic-report.sh` (v2.10.0, sanitised public edition of the weekly report script) with its README, `docs/forensic/` (the public six-month analysis, rev 1.7, and REPORT-GUIDE.md) and an "At a glance" section in the README.
- Public analysis expanded (about 4,500 words): banned-address origins, measured ban latency by detector, path families, two burst timelines, daily ban waves and an FAQ. README now states the measured latency (median 3 s from the triggering request) instead of "one to two seconds".
- Public analysis refreshed to 25 October 2026 (revision 1.8) and renamed to the monthly convention (`Zoraxy-Forensic-Network-Analysis-2026-October-PUBLIC.docx`): 107 banned addresses, re-measured ban latency (median 2 s; path probes 1 to 6 s), enforcement while banned (603 requests refused, none reached an application), a rotating-/24 actor and the steady sweeps since 21 October. Leak-checked.
- Compatibility: verified on Zoraxy 3.3.5-rc4 (25 October 2026): the plugin loaded, restored its history from disk (27 entries) and ran without errors after the self-update.
- Planned: multi-zone support (issue #5): see the issue for the design and the reporter's reply.

## 0.3.3 — 2026-10-21
**Why this release:** the Recent actions table was in memory, so every Zoraxy restart emptied it, and Zoraxy restarts weekly when it self-updates. Operators
and report writers lost the record of what the plugin had done (the journal kept it, but mixed with other output).
- **Persistent action history.** Every action is now appended to `zoraxy_actions.jsonl` next to the plugin binary (one JSON object per line: time,
  address, reason, source, result, detail), and the table is restored from it on start. Size-capped (5 MB, with one rotated copy, so about 10 MB at most),
  mode 0600, no credentials in it. A write failure is logged once and ignored: it can never stop a ban. `skipped-duplicate` entries are not
  written (the same rule the journal uses), and dedup state is not restored, so a restart never suppresses a block.
- Behaviour is otherwise identical to 0.3.2: detection, bans and expiry are unchanged.

## 0.3.2 — 2026-10-12
**Why this release:** a false positive found while reviewing a week of production logs. n8n's editor requests
`/types/credentials.json` on every page load and the credential-file pattern flagged it, so anyone using n8n through the proxy
from a public address would have been banned in both layers. Nobody was affected (it was only ever seen from a private address,
which the plugin skips). 0.3.2 adds an exact-path exception for that one file. **Everything else is unchanged.**
- **False positive fixed: n8n.** n8n's editor loads `/types/credentials.json` (a static list of credential *type* definitions,
  not credentials) on every page load, and the credential-file pattern matched it, so anyone using n8n through the proxy from a
  public address would have been banned in both layers. Seen in production only from a private address, where the plugin
  already skips banning, so no one was affected yet. The fix is an **exact-path exception** (whole raw path, query string
  ignored; never a prefix, never the decoded form). Lookalikes such as `/credentials.json`, `/x/types/credentials.json`,
  other extensions and encoded variants are still flagged; tests cover both directions. Detection is otherwise unchanged.

## 0.3.1 — 2026-10-07
**Why this release:** the first real expiry removals ran in production on 2026-10-06 and worked (Cloudflare and Zoraxy sides
removed together, hourly, no errors), which also exposed a cosmetic bug in the journal line. 0.3.1 fixes that line and
records the verification. **Behaviour is otherwise identical to 0.3.0**: detection, blocking and what expiry removes are
unchanged.
- **Expiry log line fixed:** an address removed from both Cloudflare and Zoraxy was listed twice and double-counted in the
  `expired` action (`ip=2 IP(s)` for one address). The action now lists and counts distinct addresses. Cosmetic only: the
  removals themselves were always correct, and the per-layer `expiry: removed N …` journal lines are unchanged.
- `build.sh release` builds every published architecture (amd64, arm64, ARMv7, 386) into `build/release/` with `SHA256SUMS`,
  named as the plugin store expects; `./build.sh <arch>…` builds a specific list.
- README: install from the release with checksum verification, requirements, and a Troubleshooting section (chief among them: the
  Recent actions table is in memory and a Zoraxy restart empties it).

## 0.3.0 — 2026-09-22
- **Automatic expiry** of blocks (default 14 days, `0` = never). Hourly pruner, live only; removes only Cloudflare list items
  whose comment starts `zoraxy/` and bans the plugin recorded itself; never acts on a failed read; capped at 200 per run.
  Hourly journal line proves it is running.
- **Optional second layer: ban in Zoraxy's own blacklist** ("Also ban blocked IPs in Zoraxy…", off by default). Independent of
  Cloudflare (results `blocked` / `partial` / `error`); can run without Cloudflare credentials. Access rules are read from
  Zoraxy live; the page warns when a rule's blacklist is off. Declares four Zoraxy plugin-API permissions.
- Documented that bans (and any country/IP access rule) only see real visitors behind a tunnel/proxy when the proxy's
  addresses are Zoraxy trusted proxies and **Trust proxy headers only** is on for the rule, including the Default rule.

## 0.2.1 — 2026-09-21
- Cloudflare error 10019 ("maximum number of lists") explained in plain words; Test Connection lists the account's lists and
  warns about quota, non-IP lists, and lists used by someone else's rules (the allow-list trap).

## 0.2.0 — 2026-09-21
- **Sensitive-path probes** (`/.git`, `/.env`, cloud/tool credential dirs and dotfiles, credential files, SSH keys) flag scanners
  whatever the response status — single-page apps answer such paths with 200, so error counts alone missed them.
- **Safer Cloudflare write path:** rules are added/edited with the single-rule API and never resent; a failed read writes nothing;
  a rule with the plugin's name that it did not create is never touched; list items are added with `POST …/items`.
- Journal logging of every decision, a heartbeat every 30 minutes, masked account/zone IDs, block-action dropdown, in-page help,
  IP-list-name validation, working Save inside Zoraxy's sandboxed frame, `X-CSRF-Token` fix.

## 0.1.0 — 2026-09-19
- First version: follows Zoraxy's access log and blacklist events, mirrors abusive IPs into a Cloudflare IP list referenced by one
  custom WAF rule; dry-run by default; setup gating and Test Connection.
