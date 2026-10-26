# Changelog

Versions follow the plugin's own `version_major/minor/patch` (shown in Zoraxy's plugin list).

## Unreleased
- Docs only: the `logtail: alive` heartbeat is every 30 minutes (README and TESTING.md said hourly); Known limits now document the multi-zone
  workaround and the stale settings-page sentence about the in-memory history. No code change.
- Added `scripts/forensic-report.sh` (v2.10.0, sanitised public edition of the weekly report script) with its README, `docs/forensic/` (the public six-month analysis, rev 1.7, and REPORT-GUIDE.md) and an "At a glance" section in the README.
- Public analysis expanded (about 4,500 words): banned-address origins, measured ban latency by detector, path families, two burst timelines, daily ban waves and an FAQ. README now states the measured latency (median 3 s from the triggering request) instead of "one to two seconds".
- Public analysis refreshed to 25 October 2026 (revision 1.8) and renamed to the monthly convention (`Zoraxy-Forensic-Network-Analysis-2026-October-PUBLIC.docx`): 107 banned addresses, re-measured ban latency (median 2 s; path probes 1 to 6 s), enforcement while banned (603 requests refused, none reached an application), a rotating-/24 actor and the steady sweeps since 21 October. Leak-checked.
- Planned: correct the settings-page text; multi-zone support (issue #5), pending the reporter's answers.

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
