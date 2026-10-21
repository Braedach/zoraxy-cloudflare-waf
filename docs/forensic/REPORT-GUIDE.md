# How to read the Zoraxy forensic report (and how to brief an AI that writes the analysis)

Standing rules that stay true from week to week. They exist because the first AI-written analyses of these reports contained confident
errors: counts taken from a filtered section, a version carried over from last week, a scanner called a breach. Give this file to whoever,
human or AI, writes the analysis. It contains no site-specific figures.

## A. How the data is produced

1. **Cumulative, not weekly.** Each report covers the current month to date. Compare reports from the same month, or a month's last
   report. Do not subtract weeks without checking.
2. **State the script version and the Zoraxy version from the report header.** Never carry either forward from an earlier analysis: a
   release-candidate Zoraxy prints plain `3.3.5`, so take the release tag (`Zoraxy release installed`, from v2.9.1) and note that the
   weekly self-update can change it between reports.
3. **The exploit and whitelist sections are filtered views, not totals.** They print only matching lines. For totals use "Blocks by
   Zoraxy Layer (per day)" (v2.9.0 onwards). Before v2.9.0 there is no blacklist count at all, so say so instead of inferring one.
4. **Totals are request lines**, with a few UI-noise patterns excluded by design.
5. **Re-running an old month** needs the same script version to reproduce its figures; say if you cannot.

## B. Reading the log prefixes

- `[router:exploit-blocked]` is Zoraxy's built-in exploit detection returning 403.
- `[router:whitelist]` is an IP or country allow-list rejecting the request; it happens only on hosts that have one.
- `[router:blacklist]` is **Zoraxy's own access-rule blacklist**. The plugin fills that list, but this is a Zoraxy refusal, not a
  Cloudflare one. A scanner burst produces many of these in the seconds after the ban.
- `[router:ratelimit]` is a 429 from the rate limiter, which carries no host.
- **A request Cloudflare blocks or challenges never appears in this log.** Cloudflare counts live in its dashboard; any figure taken
  from a screenshot needs its date and time window stated.

## C. Interpretation rules

1. **Do not label an address a threat on volume alone.** Check its user agent and the hosts it requested. Your own mobile-carrier
   addresses and apps look like "unknown outside traffic" until you check.
2. **Private addresses in 401s and 429s are usually your own devices.** One browser tab retrying an expired session produced thousands
   of 401s. Check "Top 401 Clients" before calling a 401 spike an attack.
3. **A bot name in a user agent proves nothing.** Scanners rotate crawler names per request. Cloudflare's verified-bot flag is the test.
4. **Single-page apps answer 200 to almost any path.** A 200 on `/.env` is usually the app's index page, not a leak.
5. **Alternate-port requests**: read the per-port table (requests, proxied versus blocked, first and last seen). Do not assume they were
   blocked, and do not write that a sweep "continues" unless the first/last-seen times show fresh activity.
6. **Self-identifying scanners** (security vendors' crawlers, CVE detectors) are reconnaissance, not exploitation.
7. **An application's own front-end file can look like a probe.** For example a static `credentials.json` that lists credential types.
   Do not report it, and allow-list exact paths only, never prefixes.
8. **Blacklist hits right after a ban are expected.** A banned address still reaching the origin well after it is on the edge list
   would be a failure and should be flagged.

## D. Process rules

- Check every correction, count and claim against the new data. If a number cannot be verified, say so and leave it out.
- Keep resolved items out of the report; carry forward only live ones.
- Flag what you could not check instead of filling the gap.
- Never copy certificate dates, versions or rule lists from a previous revision; read them live.

## E. Briefing an AI

1. Give it the report, the log-prefix key above, these rules, and the Cloudflare snapshot date.
2. Ask it to quote the script and Zoraxy versions from the header, and to say which section each number came from.
3. Keep **code and report work in separate sessions**: they need different access and it keeps each conversation traceable.
4. Read the result against the raw report. Treat any claim it cannot point to a line for as unverified.
5. For a public edition, have it write fresh from the facts, give it an explicit list of what to omit, run an automated leak check over
   the final text, and read it yourself before it is shared.
