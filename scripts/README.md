# Weekly forensic report for Zoraxy

`forensic-report.sh` reads Zoraxy's current-month access log and writes a plain-text report of what reached your proxy and what was
refused. It is the **reporting** half of the setup: the plugin in this repository acts in seconds, and the report shows you, once a week,
what the proxy saw. Read-only: it never changes Zoraxy, the plugin or Cloudflare, and never reads the plugin's configuration file
(which holds an API token).

Version 2.11.0. MIT licence, like the rest of the repository.

## What the report contains

| Section | Why you want it |
|---|---|
| By IP, split into LAN and outside | Internal traffic usually outnumbers outside traffic many times over; the split keeps the outside signal visible. |
| Suspicious user agents, status codes, errors by origin | Separates attacks from a misconfigured service. |
| Top 401 clients, top 500 and 502/521 origins | "Who is behind the 401s?" without a manual grep. A single browser tab retrying an expired session can produce thousands. |
| Requests on non-standard ports | Scanners sweep Cloudflare's alternate ports (2053, 2083, 2087, 2096, 8443 and others), and many of those requests reach your applications. |
| 429s by client | Rate-limit hits are invisible to per-host tables, so they are grouped by client. |
| Blocks by Zoraxy layer, per day | **Counts** of exploit-blocked, whitelist and blacklist refusals. The raw sections are filtered views and understate these. |
| Blocked clients | One row per refused client with its counts per layer, main target, first and last time. A 170-request scanner burst is one row, not 170 lines. |
| Exploit and probe attempts | The first and last 30 matching lines; the log has the rest. |

The script also writes `platform-status-<timestamp>.txt` for **you only**: TLS certificate expiry, when each certificate was last renewed and the
last 30 days' successful renewals (with the last week's failures), Zoraxy restarts, the WAF plugin's health (process and binary hash, version, ban record,
bans this month by source and detector, expiry actions, errors, last heartbeat), gaps in the uptime checker (a long gap is printed as one range), and the
**monitored-target outages**: each period this month in which Zoraxy's uptime monitor saw a proxied target offline for ten minutes or more, with when it
went offline, when it came back and for how long. The outage list explains the checker gaps: the checker goes silent while monitored hosts are offline,
so a silent checker does not mean Zoraxy was down. It is a separate file on purpose, so the report can be shared without it.

## Install

```bash
install -m 700 -o root -g root scripts/forensic-report.sh /usr/local/bin/forensic-report.sh
mkdir -p /srv/zoraxy/reports && chmod 700 /srv/zoraxy/reports
# every Sunday at 23:00, mailed to you:
( crontab -l 2>/dev/null; echo '0 23 * * 0 EMAIL_TO=you@example.com /usr/local/bin/forensic-report.sh' ) | crontab -
```

Run it by hand first: `sudo /usr/local/bin/forensic-report.sh`. With `EMAIL_TO` unset nothing is mailed; the two files are left in the reports directory.

Requirements: bash, GNU grep with `-P`, awk, sed and coreutils. Optional: `journalctl` and `openssl` for the platform status, and a
sendmail-compatible mailer if you want it mailed. Debian and Ubuntu have all of these.

## Configuration

Everything is an optional environment variable. Nothing is hard-coded to one site.

| Variable | Default | Meaning |
|---|---|---|
| `ZORAXY_DIR` | `/srv/zoraxy` | Zoraxy install directory |
| `LOGDIR` | `$ZORAXY_DIR/log` | Where `zr_YYYY-M.log` lives |
| `REPORT_DIR` | `$ZORAXY_DIR/reports` | Output directory (kept; never pruned) |
| `EMAIL_TO` | empty | Mail the report here; empty means do not mail |
| `EMAIL_FROM` | `zoraxy-forensics@<hostname>` | Sender |
| `SENDMAIL` | `/usr/sbin/sendmail` | Submission command (needs to accept `-t`) |
| `LAN_V4_REGEX` | `^192\.168\.` | Which client addresses count as LAN. For several ranges: `^(10\.\|192\.168\.\|172\.(1[6-9]\|2[0-9]\|3[01])\.)` |
| `IGNORE_UA_REGEX` | empty | User agents to count but not list (a regex), for a noisy application, for example `^Jellyfin\|^Plex` |
| `UPTIME_PER_DAY` | `576` | Uptime checks you expect per day, for the platform-status gap check |
| `PLUGIN_DIR` | `$ZORAXY_DIR/plugins/com.braedach.zoraxy.cloudflarewaf` | The plugin's folder |
| `OFFLINE_MIN_MINUTES` | `10` | Shortest target outage listed in the platform status's outage section |

## Reading it correctly

Short version; the full rules are in [docs/forensic/REPORT-GUIDE.md](../docs/forensic/REPORT-GUIDE.md).

- **Reports are cumulative month to date.** Compare reports from the same month, or a month's last report.
- **The exploit and whitelist sections are filtered views, not totals.** Use "Blocks by Zoraxy Layer" for totals.
- **A request Cloudflare blocks never appears in this log.** Cloudflare's own counts live in its dashboard only.
- **Check the client before calling a spike an attack.** Private addresses in 401s and 429s are usually your own devices.

## Treat the output as sensitive

The report lists client addresses and which of your hosts they asked for. Read it before sharing it. The platform status shows
certificate and plugin detail and should never leave you. If you publish an analysis, write it fresh from the facts rather than editing
the internal text, and run a leak check over the result; [docs/forensic/](../docs/forensic/) shows one done that way.

## How it was tested

The script is validated by running it against real monthly logs, comparing every section with the previous release, and checking the
mail path with the mailer stubbed, the missing-log failure (exit 1, no mail) and the unset-`EMAIL_TO` path. It is a shell script
with no unit tests; if you change a section, diff the report before and after on a copy of a real log.
