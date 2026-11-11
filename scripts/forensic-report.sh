#!/bin/bash

################################################################################
# Zoraxy Forensic Report Generator (public edition)
# Version: 2.12.0
#
# Part of https://github.com/Braedach/zoraxy-cloudflare-waf  (scripts/forensic-report.sh)
# MIT licence, like the rest of the repository.
#
# What it does
#   Reads the CURRENT MONTH's Zoraxy access log and writes a plain-text forensic report: who is
#   hitting the proxy, which requests were refused and by which layer, error and authentication
#   failure sources, probe paths, user agents and alternate-port sweeps. It can also mail the report.
#   A second file, platform-status-<timestamp>.txt, is written for the operator only (certificate
#   expiry and renewal dates, Zoraxy restarts, the WAF plugin's health, uptime-checker gaps, and the
#   periods in which Zoraxy's uptime monitor saw a proxied target offline).
#
# Read-only: it never changes Zoraxy, the plugin or Cloudflare, and never reads the plugin's
# configuration file (that holds an API token).
#
# Reports are CUMULATIVE month to date (one log file per month). Compare reports from the same
# month, or a month's last report. Do not subtract weeks without checking.
#
# Configuration (environment variables; every one is optional)
#   ZORAXY_DIR        Zoraxy install directory                      default /srv/zoraxy
#   LOGDIR            Zoraxy log directory                          default $ZORAXY_DIR/log
#   REPORT_DIR        where reports are written (kept, never pruned) default $ZORAXY_DIR/reports
#   EMAIL_TO          mail the report here; if empty, nothing is mailed
#   EMAIL_FROM        sender address                                default zoraxy-forensics@<hostname>
#   SENDMAIL          mail submission command                       default /usr/sbin/sendmail
#   LAN_V4_REGEX      which client addresses count as LAN           default ^192\.168\.
#   IGNORE_UA_REGEX   user agents to count but not list (a regex, e.g. '^Jellyfin|^Plex'); default none
#   UPTIME_PER_DAY    uptime checks you expect per day              default 576 (checker every 150 s)
#   OFFLINE_MIN_MINUTES  shortest target outage to list             default 10
#   FORENSIC_MONTH    month to report, YYYY-MM (re-run a past month)  default the current month
#   BURST_MIN_REQUESTS / BURST_WINDOW_SECONDS   what counts as a request burst  default 20 requests in 10 seconds
#   BURST_PROBE_RE    extended regex for probe-like request paths (burst section)  default built in
#   PLUGIN_DIR        the WAF plugin's folder (for platform status) default $ZORAXY_DIR/plugins/com.braedach.zoraxy.cloudflarewaf
#
# Install
#   install -m 700 -o root -g root forensic-report.sh /usr/local/bin/forensic-report.sh
#   mkdir -p /srv/zoraxy/reports && chmod 700 /srv/zoraxy/reports
#   crontab:   0 23 * * 0  EMAIL_TO=you@example.com /usr/local/bin/forensic-report.sh
#
# Requirements: bash, GNU grep (with -P), awk, sed, coreutils. Optional: journalctl and openssl
# (platform status), sendmail-compatible mailer (mail).
#
# Treat the report as sensitive until you have read it: it lists client addresses and the
# hosts they asked for. Share the forensic report only after review; never share platform-status.
#
# Key Changes in v2.12.0:
#   - Added: "Request Bursts from External Addresses". One row per non-LAN address that sent BURST_MIN_REQUESTS (20) or more requests within
#     BURST_WINDOW_SECONDS (10 s), whatever Zoraxy did with them: requests in the busiest window, when, its span, how many were proxied to
#     the application and how many Zoraxy refused, distinct paths, how many of those look like probes, main target and commonest status.
#     Why: a scripted sweep of about 54 credential and configuration paths in four seconds (seven of them in November 2026) is served by
#     Zoraxy and proxied, so it appeared in NO attack table: the Exploit / Probe section lists only requests Zoraxy blocked. It showed only as
#     an address with about 55 requests in the external list. Rows are ordered by probe-like paths, then size; a browser loading a page is
#     a burst with few probe-like paths.
#   - Added (platform status): plugin stops by Zoraxy are counted apart from plugin errors. When Zoraxy stops (weekly update, host reboot)
#     its plugin manager logs "plugin ... encounted a fatal error ... signal: terminated" for each plugin. That is the shutdown signal, not a
#     fault, and it never reached the "Errors/warnings" figure (which counts the plugin's own journal lines); now it is stated: stop lines and
#     how many stops, and any OTHER plugin-manager "fatal error" (a real crash) separately, with its last lines.
#   - Changed (platform status): a monitored-target outage that began before the first event of the month now shows its true start. The
#     outage section reads the previous month's journal as well and shows an outage that overlaps the month and whose target logged an event in the month (a target retired earlier, which
#     the monitor no longer logs, is not listed as offline for ever); a note says when a start comes from the previous month. If the journal does not reach back that far the start is still the first event it holds. (1 Nov 2026 showed about 18 hours
#     for outages that had lasted three days.)
#   - Changed: FORENSIC_MONTH, LOGDIR, REPORT_DIR and EMAIL_TO are configurable (see Configuration above), so a past month can be re-run without
#     mailing it or writing into the live reports directory. The Zoraxy starts, plugin, renewal and outage journal queries use the month's own window.
#     The certificate and process sections are always the live state at run time; for a past month the platform status says so.
#   - Changed: the report header gains a "Month:" line (to date, or complete).
#   - Unchanged: every other section and number, the report file names, the mail format (both attachments), and the 2300 Sunday cron line.
#
#
# Version history (short; the full history is in the repository's git log)
#   2.12.0  new "Request Bursts from External Addresses" section (scripted sweeps that Zoraxy served and proxied now show up);
#           plugin stops counted apart from plugin crashes; a target already offline at the start of the month is looked up
#           in the previous month's journal; the month, log and report directories and the recipient are configurable.
#   2.11.0  platform status: certificates show when each was last renewed and the last 30 days' successful renewals;
#           new "Monitored-target outages" section (when each target went offline, came back, and for how long; it
#           explains uptime-checker silences); uptime-checker gaps printed as ranges. Fixed a stray "Broken pipe"
#           line that could end the Exploit / Probe section. The forensic report itself is unchanged.
#   2.10.0  "Blocked Clients" table (one row per refused client, by layer); raw exploit section capped to the
#           first and last 30 lines; whitelist section shows counts per origin; version read from this header;
#           optional ignore-list for noisy application user agents; platform-status second file.
#   2.9.1   header shows the Zoraxy version and the installed release tag (the binary prints plain "3.3.5" for
#           a release candidate too).
#   2.9.0   "Blocks by Zoraxy Layer (per day)" counts; non-standard-port table with proxied/blocked and first/last seen.
#   2.8.0   Top 401 Clients, Top 500 Origins; origin ports folded into the hostname; uptime checker counted, not listed.
#   2.7.x   fixed 502/521 matching digits anywhere in a line; plugin-manager lines excluded from the exploit section.
#   2.7.0   LAN versus external split of the by-IP list; 429 section; whitelist rejections section.
#
################################################################################

ZORAXY_DIR="${ZORAXY_DIR:-/srv/zoraxy}"
LOGDIR="${LOGDIR:-$ZORAXY_DIR/log}"
REPORT_DIR="${REPORT_DIR:-$ZORAXY_DIR/reports}"
EMAIL_TO="${EMAIL_TO:-}"
SENDMAIL="${SENDMAIL:-/usr/sbin/sendmail}"
LAN_V4_REGEX="${LAN_V4_REGEX:-^192\.168\.}"
IGNORE_UA_REGEX="${IGNORE_UA_REGEX:-}"
UPTIME_PER_DAY="${UPTIME_PER_DAY:-576}"
OFFLINE_MIN_MINUTES="${OFFLINE_MIN_MINUTES:-10}"
PLUGIN_DIR="${PLUGIN_DIR:-$ZORAXY_DIR/plugins/com.braedach.zoraxy.cloudflarewaf}"
BURST_MIN_REQUESTS="${BURST_MIN_REQUESTS:-20}"
BURST_WINDOW_SECONDS="${BURST_WINDOW_SECONDS:-10}"
# Paths a legitimate visitor does not ask for: dotfiles and tool folders, secret and config files, framework disclosures, traversal.
BURST_PROBE_RE="${BURST_PROBE_RE:-(^/[.][A-Za-z]|[.](env|git|aws|npmrc|netrc|ssh)|[.](php|sql|bak|ini|ya?ml|toml|properties|log)([?]|\$)|credentials|secret|passwd|phpinfo|/proc/|[.][.]/|config)}"

# Month to report (YYYY-MM). Default: the current month. All date arithmetic is GNU date.
FORENSIC_MONTH="${FORENSIC_MONTH:-$(date '+%Y-%m')}"
case "$FORENSIC_MONTH" in
    [0-9][0-9][0-9][0-9]-0[1-9]|[0-9][0-9][0-9][0-9]-1[0-2]) ;;
    *) echo "Error: FORENSIC_MONTH must be YYYY-MM (got '$FORENSIC_MONTH')." >&2; exit 2 ;;
esac
MONTH_START="${FORENSIC_MONTH}-01"
MONTH_END="$(date -d "$MONTH_START 1 month" '+%Y-%m-%d')"
PREV_START="$(date -d "$MONTH_START 1 month ago" '+%Y-%m-%d')"
if [ "$FORENSIC_MONTH" = "$(date '+%Y-%m')" ]; then
    MONTH_IS_CURRENT=1
    REF_END="$(date '+%Y-%m-%d %H:%M:%S')"          # "last 7 / 30 days" windows end now
    OUT_END="$(date '+%Y-%m-%dT%H:%M:%S')"          # an outage still open runs to now
    STILL_LABEL="still offline"
else
    MONTH_IS_CURRENT=0
    REF_END="$MONTH_END 00:00:00"                   # ... or at the end of the month for a past month
    OUT_END="${MONTH_END}T00:00:00"
    STILL_LABEL="offline at month end"
fi
CERT_7D="$(date -d "$REF_END 7 days ago" '+%Y-%m-%d %H:%M:%S')"
CERT_30D="$(date -d "$REF_END 30 days ago" '+%Y-%m-%d %H:%M:%S')"

REPORT_TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
mkdir -p "$REPORT_DIR" && chmod 700 "$REPORT_DIR" 2>/dev/null
REPORT_FILE="$REPORT_DIR/forensic-report-${REPORT_TIMESTAMP}.txt"
REPORT_FILENAME="$(basename "$REPORT_FILE")"
PLATFORM_FILE="$REPORT_DIR/platform-status-${REPORT_TIMESTAMP}.txt"
PLATFORM_FILENAME="$(basename "$PLATFORM_FILE")"

# Safely fall back to the plain hostname if the FQDN (-f) is not configured
CURRENT_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
EMAIL_FROM="${EMAIL_FROM:-zoraxy-forensics@${CURRENT_HOSTNAME}}"
EMAIL_SUBJECT="Zoraxy Forensic Report - ${REPORT_TIMESTAMP}"
[ "$MONTH_IS_CURRENT" -eq 1 ] || EMAIL_SUBJECT="Zoraxy Forensic Report - ${FORENSIC_MONTH} (re-run) - ${REPORT_TIMESTAMP}"


# Log file of the month being reported (Zoraxy naming format: zr_YYYY-M.log, no leading zero on the month)
CURRENT_LOG="$LOGDIR/zr_$(date -d "$MONTH_START" '+%Y-%-m').log"

# Zoraxy version for the report header. The flag needs its dashes ("zoraxy version" would start the server), and a timeout keeps
# a hang from blocking the report. The binary reports only the plain version for a release candidate, so the installed
# release tag is read from the updater log as well.
ZORAXY_BIN="${ZORAXY_BIN:-$(command -v zoraxy 2>/dev/null || echo /srv/zoraxy/zoraxy)}"
ZORAXY_VERSION_OUT="$(timeout 10 "$ZORAXY_BIN" --version 2>&1 | head -1)"
[ -n "$ZORAXY_VERSION_OUT" ] || ZORAXY_VERSION_OUT="unavailable ($ZORAXY_BIN --version gave no output)"
ZORAXY_INSTALLED_TAG="$(grep -oP 'update to \Kv[0-9][^ ]*(?= complete)' /var/log/zoraxy-update.log 2>/dev/null | tail -1)"
[ -n "$ZORAXY_INSTALLED_TAG" ] || ZORAXY_INSTALLED_TAG="unknown (not found in /var/log/zoraxy-update.log)"

# Script version from this file's own header (single source of truth; a literal here had to be bumped by hand each release).
SCRIPT_VERSION="$(sed -n 's/^# Version: *//p' "$0" 2>/dev/null | head -1)"
[ -n "$SCRIPT_VERSION" ] || SCRIPT_VERSION="unknown"

# Function to generate report
generate_report() {
    echo
    echo "==============================================="
    echo "        ZORAXY OFFLINE FORENSIC SUMMARY"
    echo "==============================================="
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo "Log file: $CURRENT_LOG"
    if [ "$MONTH_IS_CURRENT" -eq 1 ]; then echo "Month: ${FORENSIC_MONTH} (to date)"; else echo "Month: ${FORENSIC_MONTH} (complete month, re-run)"; fi
    echo "Zoraxy script version: ${SCRIPT_VERSION}"
    echo "Zoraxy version: ${ZORAXY_VERSION_OUT}"
    echo "Zoraxy release installed (updater log): ${ZORAXY_INSTALLED_TAG}"

    echo

    # Abort if the log of the month being reported does not exist
    if [ ! -f "$CURRENT_LOG" ]; then
        echo "ERROR: No log found for ${FORENSIC_MONTH}: $CURRENT_LOG"
        echo "Aborting report generation."
        return 1
    fi

    echo "Log found:"
    echo "$CURRENT_LOG"
    echo

    # Create temp file and ensure it is cleaned up on any exit
    FILTERED=$(mktemp)
    trap "rm -f '$FILTERED'" EXIT

    # No internal/LAN filtering - full logs are kept intact for forensic
    # completeness (see header notes). Only known browser-UI/asset noise is
    # dropped, regardless of source.
    grep -v "netstatgraph" "$CURRENT_LOG" \
    | grep -v "summary?fast" \
    | grep -v "snippet" \
    | grep -v "script/" \
    | grep -v "darktheme" \
    > "$FILTERED"

    # Detect this host's own LAN IPv6 /48 fresh on every run (not hardcoded) -
    # SLAAC gives LAN devices real globally-routable IPv6 addresses (no NAT),
    # and the delegated prefix can rotate on a router restart. Falls back to
    # "unclassified" if no global IPv6 address is present at run time rather
    # than guessing. This is a readability heuristic for the "by IP" split
    # below, not a security boundary - a /48 is deliberately wide enough to
    # also cover sibling VLANs sharing the same delegation.
    LAN_IPV6_PREFIX=$(ip -6 addr show scope global 2>/dev/null \
        | awk '/inet6/ {print $2}' \
        | grep -viE '^(fe80|fc|fd)' \
        | head -1 \
        | cut -d'/' -f1 \
        | awk -F: '{print $1":"$2":"$3}')

    echo "-----------------------------------------------"
    echo " External Requests by IP"
    echo "-----------------------------------------------"
    # Split into LAN and WAN/external rather than one commingled ranked list -
    # internal traffic outnumbers external roughly 30:1 in a typical month,
    # which buries the externally-relevant signal in an unfiltered report.
    # Nothing is dropped here, only grouped for readability.
    ALL_CLIENTS=$(grep -Eo "client: [^]]+" "$FILTERED" | awk '{print $2}')

    echo "  -- LAN (${LAN_V4_REGEX}$( [ -n "$LAN_IPV6_PREFIX" ] && echo ", ${LAN_IPV6_PREFIX}::/48" )) --"
    if [ -n "$LAN_IPV6_PREFIX" ]; then
        echo "$ALL_CLIENTS" | grep -E "${LAN_V4_REGEX}|^${LAN_IPV6_PREFIX}:" | sort | uniq -c | sort -nr
    else
        echo "$ALL_CLIENTS" | grep -E "${LAN_V4_REGEX}" | sort | uniq -c | sort -nr
        echo "  (no global IPv6 address on this host at run time - IPv6 LAN match skipped)"
    fi
    echo
    echo "  -- WAN / External --"
    if [ -n "$LAN_IPV6_PREFIX" ]; then
        echo "$ALL_CLIENTS" | grep -vE "${LAN_V4_REGEX}|^${LAN_IPV6_PREFIX}:" | sort | uniq -c | sort -nr
    else
        echo "$ALL_CLIENTS" | grep -vE "${LAN_V4_REGEX}" | sort | uniq -c | sort -nr
    fi
    echo

    echo "-----------------------------------------------"
    echo " Suspicious User Agents"
    echo "-----------------------------------------------"
    # The proxy's own uptime checker is counted, not listed (it is the top entry every week and is benign).
    echo "  (zoraxy-uptime checker requests excluded from this list: $(grep -c 'useragent: zoraxy-uptime' "$FILTERED"))"
    if [ -n "$IGNORE_UA_REGEX" ]; then
        echo "  (user agents matching IGNORE_UA_REGEX counted, not listed: $(grep -Eo 'useragent: [^]]+' "$FILTERED" | sed 's/^useragent: //' | grep -cE "$IGNORE_UA_REGEX"))"
    fi
    grep -v "Mozilla/5.0" "$FILTERED" \
    | grep -Eo "useragent: [^]]+" \
    | awk -F'useragent: ' '{print $2}' \
    | grep -v '^zoraxy-uptime/' \
    | { if [ -n "$IGNORE_UA_REGEX" ]; then grep -vE "$IGNORE_UA_REGEX"; else cat; fi; } \
    | sort | uniq -c | sort -nr
    echo

    echo "-----------------------------------------------"
    echo " HTTP Status Code Distribution"
    echo "-----------------------------------------------"
    # Extracts the trailing status code from Zoraxy log lines.
    # Zoraxy format ends with: GET /path STATUS or POST /path STATUS
    grep -Eo "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ [0-9]{3}" "$FILTERED" \
    | awk '{print $NF}' \
    | sort | uniq -c | sort -nr
    echo

    echo "-----------------------------------------------"
    echo " HTTP Errors (4xx / 5xx) by Origin"
    echo "-----------------------------------------------"
    # Groups error responses by proxied service (origin) — critical for
    # distinguishing attacks from service misconfigurations.
    grep -E "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ [45][0-9]{2}$" "$FILTERED" \
    | grep -oP '\[origin:[^\]]+\]' \
    | sed -E 's/:[0-9]+\]$/]/' \
    | sort | uniq -c | sort -nr \
    | head -20
    echo

    echo "-----------------------------------------------"
    echo " Top 401 Origins (Authentication Failures)"
    echo "-----------------------------------------------"
    # High 401 counts from a single origin indicate either a credential attack
    # or a misconfigured service (e.g. lost API token polling in a loop).
    grep -E "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ 401$" "$FILTERED" \
    | grep -oP '\[origin:[^\]]+\]' \
    | sed -E 's/:[0-9]+\]$/]/' \
    | sort | uniq -c | sort -nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Top 401 Clients (who is behind the 401s)"
    echo "-----------------------------------------------"
    # Answers "which client?" for an authentication-failure spike (an open tab with an expired session, a mis-tokened agent,
    # or a real credential attack) without a manual grep.
    grep -E "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ 401$" "$FILTERED" \
    | grep -oP '\[client: \K[^\]]+' \
    | sort | uniq -c | sort -nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Top 502 / 521 Origins (Backend Failures)"
    echo "-----------------------------------------------"
    # Identifies which proxied services are generating backend connectivity
    # errors — distinguishes a single failing target from systemic issues.
    # Anchored on the trailing status code (same as the 401 section above). An unanchored match counted any line
    # containing "502"/"521" in a timestamp, container ID or path.
    grep -E "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ (502|521)$" "$FILTERED" \
    | grep -oP '\[origin:[^\]]+\]' \
    | sed -E 's/:[0-9]+\]$/]/' \
    | sort | uniq -c | sort -nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Top 500 Origins (Application Errors)"
    echo "-----------------------------------------------"
    # The application behind the proxy failed (as opposed to being unreachable, which is 502/521 above).
    grep -E "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ 500$" "$FILTERED" \
    | grep -oP '\[origin:[^\]]+\]' \
    | sed -E 's/:[0-9]+\]$/]/' \
    | sort | uniq -c | sort -nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Requests on Non-Standard Ports (per port)"
    echo "-----------------------------------------------"
    # The per-origin tables fold :8443/:20xx into the hostname; this keeps the alternate-port sweeps visible.
    # "proxied" = router:host-http (reached the application); "blocked" = any other router tag (whitelist, blacklist, exploit).
    # First/last are minute-resolution local times, so a one-day burst is distinguishable from a recurring sweep.
    printf '  %-6s %9s %9s %9s  %-16s  %-16s\n' "port" "requests" "proxied" "blocked" "first seen" "last seen"
    grep -E '\[origin:[^]]*:[0-9]+\]' "$FILTERED" \
    | sed -E 's/^.*\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2})[^]]*\] \[router:([a-z-]+)\] \[origin:[^]:]*:([0-9]+)\].*$/\3 \1 \2/' \
    | grep -E '^[0-9]+ [0-9]{4}-' \
    | sort -k1,1n -k2,3 \
    | awk '{ p=$1; ts=$2" "$3; n[p]++; if ($4=="host-http") ok[p]++; else bl[p]++; if (!(p in f)) f[p]=ts; l[p]=ts }
           END { for (p in n) printf "  %-6s %9d %9d %9d  %-16s  %-16s\n", p, n[p], ok[p], bl[p], f[p], l[p] }' \
    | sort -k2,2nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Rate-Limited Requests (429) by Client IP"
    echo "-----------------------------------------------"
    # router:ratelimit entries carry an empty [origin:] field (Zoraxy's rate
    # limiter is global, not per-host), so these are invisible to every
    # origin-grouped section above despite being a genuinely useful signal -
    # a single client hammering the rate limit is worth knowing about.
    # Grouped by client instead, matching Top Exploit Origins below.
    grep "\[router:ratelimit\]" "$FILTERED" \
    | grep -oP '\[client: \K[^\]]+' \
    | sort | uniq -c | sort -nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Blocks by Zoraxy Layer (per day)"
    echo "-----------------------------------------------"
    # Counts, not samples: the Exploit / Probe and Whitelist sections that follow are filtered views and under-represent these.
    #   exploit-blocked = Zoraxy's built-in exploit detection; whitelist = IP/country allowlist; blacklist = Zoraxy's access-rule
    #   blacklist (which the Cloudflare WAF plugin fills). A scanner burst produces many blacklist hits in the seconds after a ban.
    printf '  %-12s %14s %10s %10s\n' "date" "exploit-blocked" "whitelist" "blacklist"
    sed -nE 's/^.*\[([0-9]{4}-[0-9]{2}-[0-9]{2}) [0-9:.]+\] \[router:(exploit-blocked|whitelist|blacklist)\].*$/\1 \2/p' "$FILTERED" \
    | sort \
    | awk '{ d[$1]=1; c[$1" "$2]++; t[$2]++ }
           END { n=0; for (k in d) keys[++n]=k
                 for (i=1;i<=n;i++) for (j=i+1;j<=n;j++) if (keys[j]<keys[i]) { x=keys[i]; keys[i]=keys[j]; keys[j]=x }
                 for (i=1;i<=n;i++) { k=keys[i]; printf "  %-12s %14d %10d %10d\n", k, c[k" exploit-blocked"], c[k" whitelist"], c[k" blacklist"] }
                 printf "  %-12s %14d %10d %10d\n", "TOTAL", t["exploit-blocked"], t["whitelist"], t["blacklist"] }'
    echo

    echo "-----------------------------------------------"
    echo " Blocked Clients (who Zoraxy refused, by layer)"
    echo "-----------------------------------------------"
    # One row per client Zoraxy refused (exploit-blocked, whitelist or blacklist), busiest first, top 40. "Span" is last minus first
    # time in seconds, so a one-minute scanner burst is distinguishable from a client that keeps coming back. Counts, not samples.
    BLK=$(sed -nE 's/^.*\[([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})[0-9.]*\] \[router:(exploit-blocked|whitelist|blacklist)\] \[origin:([^]]*)\] \[client: ([^]]*)\].*$/\1|\2|\3|\4|\5/p' "$FILTERED" \
        | awk -F'|' '
            function epoch(d, t,   a, b, y, m, dd) { split(d, a, "-"); split(t, b, ":"); y = a[1] + 0; m = a[2] + 0; dd = a[3] + 0
                if (m < 3) { y--; m += 12 }
                return (365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + dd) * 86400 + b[1] * 3600 + b[2] * 60 + b[3] }
            { c = $5; o = $4; sub(/:[0-9]+$/, "", o); e = epoch($1, $2); n[c]++; k[c, $3]++; oc[c, o]++; seen[c, o] = 1; orig[c] = 1
              if (!(c in lo) || e < lo[c]) { lo[c] = e; fs[c] = $1 " " $2 }
              if (!(c in hi) || e > hi[c]) { hi[c] = e; ls[c] = $1 " " $2 } }
            END { for (key in seen) { split(key, p, SUBSEP); if (oc[key] > best[p[1]]) { best[p[1]] = oc[key]; top[p[1]] = p[2] } }
                  for (c in n) printf "%d|%s|%d|%d|%d|%s|%s|%s|%d\n", n[c], c, k[c, "exploit-blocked"], k[c, "whitelist"], k[c, "blacklist"], top[c], fs[c], ls[c], hi[c] - lo[c] }' \
        | sort -t'|' -k1,1nr -k2,2)
    if [ -z "$BLK" ]; then
        echo "None detected"
    else
        printf '  %-40s %7s %6s %6s %6s  %-30s %-19s %-19s %7s\n' "client" "events" "expl." "whitel" "blackl" "main target" "first" "last" "span(s)"
        echo "$BLK" | head -40 | awk -F'|' '{ printf "  %-40s %7d %6d %6d %6d  %-30s %-19s %-19s %7d\n", $2, $1, $3, $4, $5, $6, $7, $8, $9 }'
        echo "  clients refused: $(echo "$BLK" | grep -c .), events: $(echo "$BLK" | awk -F'|' '{s += $1} END {print s}'); rows shown: $(echo "$BLK" | head -40 | grep -c .)"
    fi
    echo

    echo "-----------------------------------------------"
    echo " Request Bursts from External Addresses"
    echo "-----------------------------------------------"
    # One row per non-LAN address that sent BURST_MIN_REQUESTS or more requests within BURST_WINDOW_SECONDS, whatever Zoraxy did with them.
    # Zoraxy PROXIES a scripted sweep of probe paths (nothing blocks it until the plugin bans the address after the sweep), so such a sweep is
    # in none of the tables about attacks above or below; it is only here. "peak" = requests in the busiest window; "proxied" reached the
    # application (router:host-http), "refused" did not; "paths" = distinct paths; "probe" = how many of those match BURST_PROBE_RE. A browser
    # loading a page is a burst with few probe-like paths. Counts, not samples. Ordered by probe-like paths, then peak.
    echo "  (${BURST_MIN_REQUESTS} or more requests within ${BURST_WINDOW_SECONDS} s from one non-LAN address)"
    BRS=$(sed -nE 's/^.*\[([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})[0-9.]*\] \[router:([a-z-]+)\] \[origin:([^]]*)\] \[client: ([^]]*)\].* (GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^ ]+) ([0-9]{3})$/\1|\2|\3|\4|\5|\7|\8/p' "$FILTERED" \
        | awk -F'|' -v lan6="$LAN_IPV6_PREFIX" -v W="$BURST_WINDOW_SECONDS" -v MIN="$BURST_MIN_REQUESTS" -v re="$BURST_PROBE_RE" '
            function epoch(d, t,   a, b, y, m, dd) { split(d, a, "-"); split(t, b, ":"); y = a[1] + 0; m = a[2] + 0; dd = a[3] + 0
                if (m < 3) { y--; m += 12 }
                return (365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + dd) * 86400 + b[1] * 3600 + b[2] * 60 + b[3] }
            { c = $5; if (c ~ /^192\.168\./ || (lan6 != "" && index(c, lan6 ":") == 1)) next
              k = ++n[c]; E[c, k] = epoch($1, $2); S[c, k] = $1 " " $2; G[c, k] = $3; O[c, k] = $4; P[c, k] = $6; C[c, k] = $7 }
            END { for (c in n) {
                    i = 1; best = 0
                    for (j = 1; j <= n[c]; j++) { while (E[c, j] - E[c, i] > W) i++; if (j - i + 1 > best) { best = j - i + 1; bi = i; bj = j } }
                    if (best < MIN) continue
                    delete sp; delete oc; delete sc; px = 0; bl = 0; np = 0; pr = 0
                    for (k = bi; k <= bj; k++) { if (G[c, k] == "host-http") px++; else bl++
                        if (!(P[c, k] in sp)) { sp[P[c, k]] = 1; np++; if (P[c, k] ~ re) pr++ }
                        o = O[c, k]; sub(/:[0-9]+$/, "", o); oc[o]++; sc[C[c, k]]++ }
                    mo = ""; mx = 0; for (o in oc) if (oc[o] > mx) { mx = oc[o]; mo = o }
                    ms = ""; mx = 0; for (s in sc) if (sc[s] > mx) { mx = sc[s]; ms = s " x" mx }
                    printf "%s|%d|%s|%d|%d|%d|%d|%d|%s|%s\n", c, best, S[c, bi], E[c, bj] - E[c, bi], px, bl, np, pr, mo, ms } }' \
        | sort -t'|' -k8,8nr -k2,2nr -k1,1)
    if [ -z "$BRS" ]; then
        echo "None detected"
    else
        printf '  %-40s %5s %-19s %5s %8s %7s %5s %5s  %-30s %s\n' "client" "peak" "window start" "span" "proxied" "refused" "paths" "probe" "main target" "status"
        echo "$BRS" | head -30 | awk -F'|' '{ printf "  %-40s %5d %-19s %5d %8d %7d %5d %5d  %-30s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 }'
        echo "  addresses with a burst: $(echo "$BRS" | grep -c .); with 5 or more probe-like paths: $(echo "$BRS" | awk -F'|' '$8 >= 5' | grep -c .); rows shown: $(echo "$BRS" | head -30 | grep -c .)"
    fi
    echo

    echo "-----------------------------------------------"
    echo " Exploit / Probe Attempts"
    echo "-----------------------------------------------"
    # Matches common probe and injection patterns including:
    #   - Path traversal (../, encoded variants)
    #   - Shell/script/SQL injection
    #   - SSRF: cloud metadata endpoint, file:// protocol, Azure credential paths
    #   - Spring Boot actuator endpoint probing (/actuator/env)
    #   - Credential file paths (.env variants, .aws/credentials)
    # Plugin output ([plugin-manager] lines, e.g. the WAF plugin's startup message mentioning "exploit pattern") is not a
    # request and is excluded; the match below applies to request lines only.
    # Capped: the total, then the first and last 30 matching lines (the Blocked Clients table above has the per-client picture).
    EXPL=$(grep -vF "[plugin-manager]" "$FILTERED" \
        | grep -iE "(exploit|\.\./|%2e%2e|cmd=|exec=|eval\(|<script|union.*select|/etc/passwd|/bin/sh|wget |curl |169\.254\.169\.254|file%3a%2f%2f|file://|\.azure/credentials|\.azure/accessTokens|/actuator/env|/actuator/|\.env\.backup|\.env\.prod|dump\.sql|terraform\.tfstate)")
    EXPL_N=$(printf '%s\n' "$EXPL" | grep -c .)
    if [ "$EXPL_N" -eq 0 ]; then
        echo "None detected"
    elif [ "$EXPL_N" -le 60 ]; then
        printf '%s\n' "$EXPL"
    else
        echo "  $EXPL_N matching lines; showing the first 30 and the last 30 (the rest are in the Zoraxy log)"
        printf '%s\n' "$EXPL" 2>/dev/null | head -30
        echo "  ... $((EXPL_N - 60)) lines omitted ..."
        printf '%s\n' "$EXPL" | tail -30
    fi
    echo

    echo "-----------------------------------------------"
    echo " Top Exploit Origins"
    echo "-----------------------------------------------"
    # Shows which external IPs are responsible for the most exploit attempts —
    # useful for WAF block prioritisation.
    grep -iE "(exploit-blocked)" "$FILTERED" \
    | grep -oP '\[client: \K[^\]]+' \
    | sort | uniq -c | sort -nr \
    | head -10
    echo

    echo "-----------------------------------------------"
    echo " Blocked by IP/Geo Whitelist (rejections per origin)"
    echo "-----------------------------------------------"
    # Zoraxy's IP/geo allowlist rejections, counted per origin. Earlier versions listed every event, which grew to hundreds of lines
    # once outside scanners arrived; the per-client detail is in "Blocked Clients" above and the raw lines are in the Zoraxy log.
    grep "\[router:whitelist\]" "$FILTERED" \
    | grep -oP '\[origin:[^\]]+\]' \
    | sed -E 's/:[0-9]+\]$/]/' \
    | sort | uniq -c | sort -nr \
    | head -15 \
    | grep . || echo "None detected"
    echo

    echo "-----------------------------------------------"
    echo " Suspicious Request Paths (top 20)"
    echo "-----------------------------------------------"
    # Extracts the request URI (path + query) from GET/POST lines.
    # Fixed from v2.5.x which incorrectly extracted the status code via $NF.
    grep -E "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)" "$FILTERED" \
    | grep -v 'useragent: zoraxy-uptime' \
    | grep -oP '(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \K[^ ]+(?= [0-9]{3})' \
    | grep -v "^/$" \
    | sort | uniq -c | sort -nr \
    | head -20
    echo

    echo "-----------------------------------------------"
    echo " Summary Complete"
    echo "-----------------------------------------------"
    echo
}

# INTERNAL-ONLY platform status (second attachment). Facts the forensic report cannot show and that used to be gathered by hand:
# certificates, restarts, the WAF plugin and the uptime checker. Deliberately a separate file so the forensic report can be shared
# without it. It never reads the plugin's configuration file (that holds a credential): it uses the ban record, the journal and the
# plugin binary's own -introspect output only. Every probe tolerates a missing tool and says so instead of failing.
generate_platform_status() {
    local PLUG_DIR="$PLUGIN_DIR"
    local PLUG_BIN="$PLUG_DIR/com.braedach.zoraxy.cloudflarewaf"
    local HAVE_J=0; command -v journalctl >/dev/null 2>&1 && HAVE_J=1

    echo
    echo "==============================================="
    echo "   PLATFORM STATUS  -  INTERNAL ONLY"
    echo "==============================================="
    echo "Contains certificate, plugin and host status. Do not share outside the operator."
    if [ "$MONTH_IS_CURRENT" -eq 0 ]; then echo "Month: ${FORENSIC_MONTH} (re-run). Journal sections cover that month; certificate expiry and process state are the live state at run time."; fi
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')   Hostname: $(hostname)   Script version: ${SCRIPT_VERSION}"
    echo

    echo "-----------------------------------------------"
    echo " Host and Zoraxy"
    echo "-----------------------------------------------"
    echo "Host booted:            $(uptime -s 2>/dev/null || echo unknown)"
    echo "Zoraxy service started: $(systemctl show zoraxy -p ActiveEnterTimestamp --value 2>/dev/null || echo unknown)"
    echo "Zoraxy version:         ${ZORAXY_VERSION_OUT}"
    echo "Release installed:      ${ZORAXY_INSTALLED_TAG}"
    echo "Updater runs (last 3):"
    grep -E 'update to .* complete' /var/log/zoraxy-update.log 2>/dev/null | awk '!seen[$0]++' | tail -3 | cut -c1-130 | sed 's/^/  /' | grep . || echo "  (no updater log)"
    if [ "$HAVE_J" -eq 1 ]; then
        echo "Zoraxy starts in ${FORENSIC_MONTH} (journal):"
        journalctl -u zoraxy --since "$MONTH_START" --until "$MONTH_END" --no-pager 2>/dev/null | grep 'Started zoraxy.service' | awk '{print "  " $1, $2, $3}' | tail -12 | grep . || echo "  none"
    fi
    echo

    echo "-----------------------------------------------"
    echo " TLS certificates (Zoraxy)"
    echo "-----------------------------------------------"
    printf '  %-34s %-26s %-10s %s\n' "certificate" "expires" "days left" "file last changed (renewal time)"
    local f subj end secs days now chg; now=$(date +%s)
    for f in $ZORAXY_DIR/conf/certs/*.pem; do
        [ -f "$f" ] || continue
        subj=$(openssl x509 -noout -subject -in "$f" 2>/dev/null | sed 's/.*CN *= *//')
        end=$(openssl x509 -noout -enddate -in "$f" 2>/dev/null | cut -d= -f2)
        [ -n "$end" ] || continue
        secs=$(date -d "$end" +%s 2>/dev/null || echo 0); days=$(( (secs - now) / 86400 ))
        chg=$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null || echo unknown)
        printf '  %-34s %-26s %-10s %s\n' "$subj" "$end" "$days" "$chg"
    done
    if [ "$HAVE_J" -eq 1 ]; then
        echo "Renewal results, 7 days to ${REF_END% *} (journal [cert-renew]):"
        journalctl -u zoraxy --since "$CERT_7D" --until "$REF_END" --no-pager 2>/dev/null | grep '\[cert-renew\]' > /tmp/.fr-cert.$$ 2>/dev/null
        grep -oE 'Successfully renewed _\.[^ ]+\.pem' /tmp/.fr-cert.$$ | sed -E 's/Successfully renewed _\.(.*)\.pem/\1/' | sort | uniq -c | awk '{printf "  succeeded: %s (%d)\n", $2, $1}'
        grep -oE 'Renew _\.[^ ]+\.pem\([^)]*\) failed: .*' /tmp/.fr-cert.$$ | sed -E 's/Renew _\.([^ ]+)\.pem\([^)]*\) failed: (.*)/\1|\2/' | awk -F'|' '{n[$1]++; m[$1]=substr($2,1,150)} END {for (k in n) printf "  FAILED:    %s (%d attempts) last error: %s\n", k, n[k], m[k]}'
        if ! grep -qE 'Successfully renewed|failed:' /tmp/.fr-cert.$$; then echo "  no renewal attempts in the last 7 days"; fi
        rm -f /tmp/.fr-cert.$$
        echo "Successful renewals, last 30 days (journal [cert-renew]; date and time, certificate):"
        journalctl -u zoraxy --since "$CERT_30D" --until "$REF_END" -o short-iso --no-pager 2>/dev/null | grep '\[cert-renew\]' | grep 'Successfully renewed' \
            | sed -nE 's/^([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}).*Successfully renewed _\.(.*)\.pem.*/  \1 \2  \3/p' | sort | tail -12 | grep . || echo "  none"
    fi
    echo

    echo "-----------------------------------------------"
    echo " WAF plugin"
    echo "-----------------------------------------------"
    local PID; PID=$(pgrep -f "^${PLUG_BIN}" 2>/dev/null | head -1)
    if [ -n "$PID" ]; then echo "Process:        running (pid $PID), binary sha256 $(sha256sum "/proc/$PID/exe" 2>/dev/null | cut -c1-16)"; else echo "Process:        NOT RUNNING"; fi
    if [ -x "$PLUG_BIN" ]; then
        echo "Version:        $(timeout 10 "$PLUG_BIN" -introspect 2>/dev/null | grep -oE '"version_(major|minor|patch)": *[0-9]+' | grep -oE '[0-9]+$' | paste -sd. -)"
    fi
    echo "Ban record:     $(grep -o '"banned_at"' "$PLUG_DIR/zoraxy_bans.json" 2>/dev/null | wc -l) addresses tracked for expiry"
    if [ "$HAVE_J" -eq 1 ]; then
        journalctl -u zoraxy --since "$MONTH_START" --until "$MONTH_END" --no-pager 2>/dev/null | grep 'Zoraxy Cloudflare WAF plugin' > /tmp/.fr-plug.$$ 2>/dev/null
        echo "Bans in ${FORENSIC_MONTH}: $(grep -c 'action: blocked' /tmp/.fr-plug.$$) actions, $(grep 'action: blocked' /tmp/.fr-plug.$$ | grep -oE 'ip=[0-9a-fA-F.:]+' | sort -u | wc -l) distinct addresses, $(grep 'action: blocked' /tmp/.fr-plug.$$ | grep -oE 'ip=(34|35)\.[0-9.]+' | sort -u | wc -l) of them in 34.x/35.x"
        echo "  by source:    $(grep 'action: blocked' /tmp/.fr-plug.$$ | grep -oE 'source=[a-z-]+' | sort | uniq -c | awk '{printf "%s=%s  ", $2, $1}')"
        echo "  by detector:  $(grep 'action: blocked' /tmp/.fr-plug.$$ | sed -E 's/.*reason="([^"(:]*).*/\1/' | sort | uniq -c | sort -nr | head -4 | awk '{c=$1; $1=""; printf "[%s]%s  ", c, $0}')"
        echo "Expiry actions: $(grep -c 'action: expired' /tmp/.fr-plug.$$)   Errors/warnings (the plugin's own journal lines): $(grep -ciE 'error|fail|warn|panic' /tmp/.fr-plug.$$)"
        # Zoraxy's plugin manager logs "plugin X encounted a fatal error. Disabling plugin...: signal: terminated" for every plugin each time Zoraxy stops
        # (weekly update, host reboot). That is the shutdown signal, not a fault, and it is not in the Errors/warnings figure above. Any OTHER fatal error is a crash.
        journalctl -u zoraxy --since "$MONTH_START" --until "$MONTH_END" --no-pager 2>/dev/null | grep -F '[plugin-manager]' | grep -F 'encounted a fatal error' > /tmp/.fr-pm.$$ 2>/dev/null
        echo "Plugin stops by Zoraxy (\"signal: terminated\", the shutdown signal, not faults): $(grep -c 'signal: terminated' /tmp/.fr-pm.$$) lines at $(grep 'signal: terminated' /tmp/.fr-pm.$$ | grep -oE '\[20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}' | sort -u | wc -l) Zoraxy stops"
        echo "Plugin crashes (any other plugin-manager fatal error): $(grep -vc 'signal: terminated' /tmp/.fr-pm.$$)"
        grep -v 'signal: terminated' /tmp/.fr-pm.$$ | tail -3 | cut -c1-160 | sed 's/^/  /'
        rm -f /tmp/.fr-pm.$$
        echo "Last heartbeat: $(grep 'logtail: alive' /tmp/.fr-plug.$$ | tail -1 | sed -E 's/.*plugin:[0-9]+\] //' | cut -c1-110)"
        rm -f /tmp/.fr-plug.$$
    fi
    echo

    echo "-----------------------------------------------"
    echo " Uptime checker (expected ${UPTIME_PER_DAY} checks a day, $((UPTIME_PER_DAY / 24)) an hour)"
    echo "-----------------------------------------------"
    # A short day or an empty hour means Zoraxy or its host was down, or the checker stalled.
    # Today is skipped in the per-day check (it is still in progress); partial first and last hours are skipped in the hour check.
    awk -v today="$(date +%F)" -v perday="$UPTIME_PER_DAY" '
        function dfc(y, m, d,   a, yy, mm) { a = int((14 - m) / 12); yy = y + 4800 - a; mm = m + 12 * a - 3; return d + int((153 * mm + 2) / 5) + 365 * yy + int(yy / 4) - int(yy / 100) + int(yy / 400) - 32045 }
        { if (match($0, /\[20[0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]/)) { dh = substr($0, RSTART + 1, 13); d = substr(dh, 1, 10); h = substr(dh, 12, 2) + 0
            all[d " " h] = 1; if (index($0, "useragent: zoraxy-uptime")) { cd[d]++; ch[d " " h]++ } } }
        END { nd = 0; for (k in all) { split(k, p, " "); if (!(p[1] in daysSeen)) { daysSeen[p[1]] = 1; days[++nd] = p[1] } }
              for (i = 1; i <= nd; i++) for (j = i + 1; j <= nd; j++) if (days[j] < days[i]) { x = days[i]; days[i] = days[j]; days[j] = x }
              for (h = 0; h < 24; h++) if ((days[1] " " h) in all) { firstH = h; break }
              for (h = 23; h >= 0; h--) if ((days[nd] " " h) in all) { lastH = h; break }
              short = 0; for (i = 1; i <= nd; i++) if (days[i] != today && cd[days[i]] < perday - 6) { printf "  day %s: %d checks\n", days[i], cd[days[i]]; short++ }
              if (short == 0) printf "  every day complete (%d or more checks)\n", perday - 6
              gaps = 0; nr = 0; prev = -99
              for (i = 1; i <= nd; i++) for (h = 0; h < 24; h++) { k = days[i] " " h
                  if ((k in all) && ch[k] < perday / 24 - 4 && !(i == nd && h == lastH) && !(i == 1 && h == firstH)) {
                      o = dfc(substr(days[i], 1, 4) + 0, substr(days[i], 6, 2) + 0, substr(days[i], 9, 2) + 0) * 24 + h
                      if (o == prev + 1) { rl[nr]++; rt[nr] += ch[k]; re[nr] = sprintf("%s %02d:00", days[i], h) }
                      else { nr++; rl[nr] = 1; rt[nr] = ch[k]; rs[nr] = sprintf("%s %02d:00", days[i], h); re[nr] = rs[nr] }
                      prev = o; gaps++ } }
              for (r = 1; r <= nr; r++) { if (rl[r] == 1) printf "  hour %s has %d checks\n", rs[r], rt[r]
                  else printf "  %s to %s (%d hours): %d checks (%d an hour expected)\n", rs[r], re[r], rl[r], rt[r], perday / 24 }
              if (gaps == 0) print "  no hour with fewer than " perday / 24 - 4 " checks" }' "$FILTERED" 2>/dev/null | head -40
    echo
    echo "-----------------------------------------------"
    echo " Monitored-target outages in ${FORENSIC_MONTH} (offline ${OFFLINE_MIN_MINUTES} minutes or more)"
    echo "-----------------------------------------------"
    # Zoraxy's uptime monitor logs "went offline" and "is back online" per target. It repeats "went offline" after every Zoraxy restart, so only the
    # first one of a run counts. A silent uptime checker (above) coincides with monitored targets being offline; it does not mean Zoraxy was down.
    if [ "$HAVE_J" -eq 1 ]; then
        journalctl -u zoraxy --since "$PREV_START" --until "$MONTH_END" -o short-iso --no-pager 2>/dev/null | grep '\[uptime-monitor\]' | grep -E 'went offline|is back online' > /tmp/.fr-mon.$$ 2>/dev/null
        if [ -s /tmp/.fr-mon.$$ ]; then
            printf '  %-46s %-17s %-17s %s\n' "target" "offline since" "back online" "duration"
            awk -v min="$OFFLINE_MIN_MINUTES" -v mstart="$MONTH_START" -v still="$STILL_LABEL" -v now="$OUT_END" '
                function dfc(y, m, d,   a, yy, mm) { a = int((14 - m) / 12); yy = y + 4800 - a; mm = m + 12 * a - 3; return d + int((153 * mm + 2) / 5) + 365 * yy + int(yy / 4) - int(yy / 100) + int(yy / 400) - 32045 }
                function ep(ts,   y, m, d, H, M, S) { y = substr(ts, 1, 4) + 0; m = substr(ts, 6, 2) + 0; d = substr(ts, 9, 2) + 0; H = substr(ts, 12, 2) + 0; M = substr(ts, 15, 2) + 0; S = substr(ts, 18, 2) + 0; return dfc(y, m, d) * 86400 + H * 3600 + M * 60 + S }
                function fmt(sec,   d, h, m) { d = int(sec / 86400); h = int((sec % 86400) / 3600); m = int((sec % 3600) / 60); return (d > 0 ? d "d " : "") h "h " m "m" }
                function show(t, s, e, open,   dur) { dur = ep(e) - ep(s); if (dur >= min * 60 && substr(e, 1, 10) >= mstart && (t in seen)) { if (substr(s, 1, 10) < mstart) early = 1; printf "  %-46s %s  %-17s %s%s\n", t, substr(s, 1, 10) " " substr(s, 12, 5), (open ? still : substr(e, 1, 10) " " substr(e, 12, 5)), fmt(dur), (open ? " so far" : "") } }
                { ts = substr($1, 1, 19)
                  if (!match($0, /Target [^ ]+ \(/)) next
                  t = substr($0, RSTART + 7, RLENGTH - 9)
                  if (substr(ts, 1, 10) >= mstart) seen[t] = 1
                  if (index($0, "went offline")) { if (!(t in st)) st[t] = ts }
                  else if (index($0, "is back online")) { if (t in st) { if (index(t, "/") == 0) show(t, st[t], ts, 0); delete st[t] } } }
                END { for (t in st) { if (!(t in seen)) continue; if (index(t, "/") > 0) pathopen++; else show(t, st[t], now, 1) }
                      if (pathopen > 0) printf "  (plus %d path-based targets, for example forwards to external services, offline throughout; not listed)\n", pathopen
                      if (early) printf "  (a start date before %s comes from the journal of the previous month)\n", mstart }
            ' /tmp/.fr-mon.$$ > /tmp/.fr-out.$$
            grep -v '^  (' /tmp/.fr-out.$$ | sort -k1,1 -k2,3
            grep '^  (' /tmp/.fr-out.$$
            rm -f /tmp/.fr-out.$$
        else
            echo "  no monitor events in ${FORENSIC_MONTH}"
        fi
        rm -f /tmp/.fr-mon.$$
    else
        echo "  journalctl is not available"
    fi
    echo
    echo "-----------------------------------------------"
    echo " End of platform status"
    echo "-----------------------------------------------"
}

# Generate report and save to file; abort cleanly if generation fails
generate_report > "$REPORT_FILE" 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Report generation failed (check log path or permissions)."
    echo "Partial report (if any) saved to: $REPORT_FILE"
    exit 1
fi

# Internal-only platform status (second attachment). A failure here must never block the forensic report, so it is best-effort.
generate_platform_status > "$PLATFORM_FILE" 2>&1 || echo "Warning: platform status generation reported an error (see $PLATFORM_FILE)"
chmod 600 "$PLATFORM_FILE" 2>/dev/null

# Mail the report (and the operator-only platform status) if EMAIL_TO is set; otherwise the files stay in REPORT_DIR.
if [ -z "$EMAIL_TO" ]; then
    echo "Forensic report saved to: $REPORT_FILE"
    echo "Platform status saved to: $PLATFORM_FILE (operator only)"
    echo "EMAIL_TO is not set, so nothing was mailed."
    exit 0
fi

(
    echo "To: $EMAIL_TO"
    echo "From: $EMAIL_FROM"
    echo "Subject: $EMAIL_SUBJECT"
    echo "MIME-Version: 1.0"
    echo "Content-Type: multipart/mixed; boundary=\"BOUNDARY\""
    echo ""
    echo "--BOUNDARY"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo ""
    echo "Zoraxy forensic report attached, and a separate OPERATOR-ONLY platform status (certificates, plugin, uptime checker)."
    echo "Share only the forensic report, and only after reading it; keep the platform status to yourself."
    echo "Generated on $(hostname) at $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "--BOUNDARY"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo "Content-Disposition: attachment; filename=\"$REPORT_FILENAME\""
    echo ""
    cat "$REPORT_FILE"
    echo ""
    if [ -s "$PLATFORM_FILE" ]; then
        echo "--BOUNDARY"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo "Content-Disposition: attachment; filename=\"$PLATFORM_FILENAME\""
        echo ""
        cat "$PLATFORM_FILE"
        echo ""
    fi
    echo "--BOUNDARY--"
) | "$SENDMAIL" -t

if [ $? -eq 0 ]; then
    echo "Forensic report generated and mailed to $EMAIL_TO"
    echo "Report saved to: $REPORT_FILE"
else
    echo "Error: failed to send mail via $SENDMAIL."
    echo "Report saved to: $REPORT_FILE"
    exit 1
fi

# End of script
