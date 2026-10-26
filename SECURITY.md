# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue: use the repository's **Security** tab, **Report a vulnerability**
(GitHub private vulnerability reporting is enabled for this repository).

Please include the plugin version (`<binary> -introspect`), your Zoraxy version, what you saw and how to reproduce it. **Never include a Cloudflare API
token, account or zone ID, or your access logs.** If a token was ever exposed, revoke it in Cloudflare first.

This is a volunteer-maintained project. Reports are handled on a best-effort basis; you will get an acknowledgement and a fix or an explanation as soon as
practical, and you will be credited if you wish.

## Supported versions

Only the latest **stable** release receives fixes; a release candidate (a pre-release such as `v0.4.0-rc1`) is for testing and is not supported for production. See the [releases](https://github.com/Braedach/zoraxy-cloudflare-waf/releases) and the [changelog](CHANGELOG.md).

## What the plugin does and does not do

See "Security and privacy" in the [README](README.md#security-and-privacy): what it connects to, what it stores, what it changes in Cloudflare, and the
scopes the API token needs (only two). Verify a download against `SHA256SUMS` (README, "Setup" and "Verifying a release").
