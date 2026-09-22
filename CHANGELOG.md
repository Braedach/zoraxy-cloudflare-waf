# Changelog

Versions follow the plugin's own `version_major/minor/patch` (shown in Zoraxy's plugin list).

## Unreleased
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
- Journal logging of every decision, an hourly heartbeat, masked account/zone IDs, block-action dropdown, in-page help,
  IP-list-name validation, working Save inside Zoraxy's sandboxed frame, `X-CSRF-Token` fix.

## 0.1.0 — 2026-09-19
- First version: follows Zoraxy's access log and blacklist events, mirrors abusive IPs into a Cloudflare IP list referenced by one
  custom WAF rule; dry-run by default; setup gating and Test Connection.
