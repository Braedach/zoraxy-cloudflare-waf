# Upgrading to v0.4.0: several Cloudflare accounts and domains, and better scanner detection

This guide covers what v0.4.0 changes, how to install it, how to **mitigate** a problem without going back, how to **roll back**, and what was tested. Read "Is it a breaking change?" first.

> **One honest limit.** The multi-account feature (issue #5) has been exercised end to end against a **simulated** Cloudflare, not against real second and third accounts, because the maintainer has
> one account. If you use more than one account, start with **Dry run** on and tell us how it went (see "What to try and what to report"). If you use one account, nothing about accounts changes for you.

## What it adds

### 1. Several Cloudflare accounts and domains (issue #5)

In Cloudflare a **zone is simply one domain** (for example `example.com`; its subdomains belong to the same zone), and an **account** is a Cloudflare login that can hold many domains.
v0.4.0 protects up to **three accounts**, each with up to **five zones (domains)**: up to fifteen domains in all. On the settings page the Cloudflare section has three tabs,
**Cloudflare Account 1, 2 and 3**. Each tab has its own API token, Account ID, the Zone ID of each of its domains, IP list name, rule name and **block action** (for example
`block` on one account and `managed_challenge` on another). A blocked address goes to every enabled account and domain. One account failing never stops the others (the result
is **partial** and names the account). If you use only Cloudflare Account 1, **nothing changes**: same settings, same behaviour, same files.

### 2. Better detection of scanners

Chosen from seven months of real access logs from the maintainer's proxy (about 1,600 distinct external addresses, roughly 270 of which behaved as scanners):

- **Three new families of paths that only scanners ask for**, each with its own switch: *known exploit endpoints* (PHPUnit, Laravel Ignition, Yii debug, laravel-filemanager, a WordPress plugin hole,
  scanner "-notfound" canary paths), *PHP diagnostics pages* (`phpinfo` and friends) and *hosting-panel and debug endpoints* (cPanel proxy paths, `/server-status`, `/_profiler`,
  `/telescope/requests`, `/trace.axd`, `/@vite/env`). **Coverage: the quiet scanners.** A scanner that stays under the error threshold, such as a short sweep of known exploit paths, never produces 30 errors in a minute; these families ban it on the first request.
- **Two more families from v0.3.5**: AI-coding-agent configuration (`/.claude`, `/.cursor`, `/.mcp.json`) and CI definitions (`/.github/`, `/.gitlab/`, `/.circleci/`, ...), matched at the site root
  only so that a git forge showing a repository is not affected.
- **You decide.** The settings page has one tick box per family and a **never-ban list** (exact paths, or a prefix such as `/myapp/*`). Changes apply when you press Save, with no restart. A
  family that is switched off is named in a WARNING line in the journal at start-up and on every save.

### 3. Faster reaction

The log is now read every **0.5 seconds instead of 2 seconds**. A scanner sweep of about 54 paths lasts roughly four seconds, so the old poll let most of it through before the first request was even
read. Measured on a test bench, a request written to the log became a detection in **0.03 to 0.48 seconds (median 0.23 s)**. Reading the end of a file that has not grown costs next to nothing, and
replaying 143,000 real log lines through the detector showed no measurable extra cost from the new settings. (The time for Cloudflare to add the address to its list comes on top and was not part of this
measurement.)

## Is it a breaking change?

**For your settings, files and Cloudflare: no.** For what the plugin bans: **yes, in one way, on purpose.**

- **Settings.** Your existing `cloudflarewaf.json` loads unchanged. Cloudflare Account 1 *is* your existing token, account, zone and list settings; they stay at the top level
  of the file. New keys are written only when you use a new feature: a second account or domain (`additional_targets`, `extra_zone_ids`) or a switch or never-ban path
  (`probe_disabled_categories`, `probe_allow_paths`). An old file that is saved without using them gains none of these.
- **History and logs.** `zoraxy_actions.jsonl` and `zoraxy_bans.json` keep the same format. With one account the log lines and the `detail` text are as before; with several accounts the `detail`
  reads `Cloudflare Account 1: ok; Cloudflare Account 2: <reason>; ...` and each account's expiry is logged on its own line. The result can now also be **partial**.
- **Cloudflare.** The existing list and rule are found by name and re-used; nothing is recreated. A rule with the same name that is not the plugin's is never edited.
- **Detection is stricter by default.** More families are on, and one path that earlier versions deliberately ignored, `/phpinfo.php`, is now treated as a scanner request. If an application you run
  behind the proxy legitimately serves one of the paths, its visitors would be banned. See "Mitigation" for what to do, in under a minute.

## Before you start

1. A Cloudflare API token **per account**, each with `Account → Account Filter Lists → Edit` and `Zone → WAF → Edit` (scoped to that account and its domains).
2. The Account ID of each account and the Zone ID of each domain you want protected (Cloudflare dashboard: open the domain, **Overview** page, right-hand column, scroll down to **API**).
3. The **Free plan allows one IP list per account**. The plugin uses exactly one per account. If an account already holds another list it cannot create its own
   (Cloudflare error 10019); the plugin says so and the other accounts are unaffected.
4. Each domain needs one free custom-rule slot (Free plan: five per domain).

## Install (about five minutes)

Replace the paths with your own. `$PLUGIN_DIR` is the folder Zoraxy keeps this plugin in (the one containing `cloudflarewaf.json`).

1. **Back up first.** The binary, the settings and the plugin's records:
   ```bash
   cp -p "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf" /root/cloudflarewaf.before-0.4.0.bin
   cp -p "$PLUGIN_DIR/cloudflarewaf.json"                /root/cloudflarewaf.before-0.4.0.json
   cp -p "$PLUGIN_DIR/zoraxy_bans.json" "$PLUGIN_DIR/zoraxy_actions.jsonl" /root/ 2>/dev/null
   ```
   The settings file contains your API token: keep the copy private (`chmod 600`) and delete it when you no longer need it.
2. Download the binary for your CPU and the checksum file from the release page, and check it:
   ```bash
   ARCH=amd64        # or arm64, arm, 386
   curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/download/v0.4.0/cloudflarewaf_linux_$ARCH
   curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/download/v0.4.0/SHA256SUMS
   sha256sum --ignore-missing -c SHA256SUMS      # must print: cloudflarewaf_linux_<arch>: OK
   ```
3. Install it over the old binary by renaming (never copy over a running file):
   ```bash
   install -m 755 cloudflarewaf_linux_$ARCH "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new"
   mv "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new" "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"
   ```
4. Restart Zoraxy once. The plugin list shows version 0.4.0.
5. Set **Dry run** on first. Fill in Cloudflare Account 1 as before. Open the tab for each further account, tick **Enabled** on that tab, enter its token, Account ID and the Zone ID of
   each of its domains, and press **Test** (it checks every domain separately). Read "How this works" on the page for the details.
6. Open **Scanner path detection** on the settings page and check the families against what you run. Leave dry run on until the journal shows `would have added to` lines naming every account
   and nothing you recognise as a legitimate visitor. Then switch dry run off.

## Mitigation: if something goes wrong and you want to stay on v0.4.0

Everything here takes effect when you press Save; none of it needs a restart.

| Problem | What to do |
|---|---|
| A legitimate visitor or application is being banned. | Find the entry in **Recent actions** (or the journal: `grep -F "Zoraxy Cloudflare WAF plugin"`); its **reason** names the family and the path, for example `sensitive-path probe (ci-config): /.github/...`. Add that path to **Never ban these paths**, or untick the family under **Scanner path detection**, and Save. Then remove the address from the Cloudflare IP list (Manage Account, Configurations, Lists) and from your Zoraxy access rule. Bans expire on their own after the period you set (default 14 days). |
| You want the plugin to stop acting at once. | Untick **Enabled** and Save (nothing is acted on), or tick **Dry run** (decisions are logged, nothing is sent to Cloudflare or banned in Zoraxy). Bans already made stay until they expire or you remove them. |
| One Cloudflare account is failing. | The others still hold every ban. The action shows **partial** and names the account; fix its token, list or rule slot and press **Test** on its tab. An address that failed on one account is not retried there until the re-block cooldown (default 24 hours) passes. |
| You no longer want an account or domain protected. | Untick **Enabled** on that account's tab, or remove the Zone ID, and Save. The list and rule the plugin created there stay in Cloudflare (see "Rollback", step 3, to remove them). |
| The plugin will not start or the page will not load. | Read the journal for the reason. Restore the settings backup (step 1 of "Install") and restart Zoraxy. Last resort: rename `cloudflarewaf.json` aside; the plugin then starts disabled and in dry run with default settings (you will need to enter the token again). |
| Rule 3 (or any Cloudflare rule of yours) also blocks a path. | The plugin's switches do not change your Cloudflare rules. Change that rule in Cloudflare. |

## Rollback

1. Put the old binary back by renaming, then restart Zoraxy:
   ```bash
   install -m 755 /root/cloudflarewaf.before-0.4.0.bin "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new"
   mv "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new" "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"
   ```
   (No backup? The previous releases are on the releases page; v0.3.5 is the previous stable one.)
2. Optional: restore the settings backup (`cp -p /root/cloudflarewaf.before-0.4.0.json "$PLUGIN_DIR/cloudflarewaf.json"`). It is not required: older versions ignore the settings they do not know, run as
   a single account, and leave the new keys in the file untouched until you press Save on their settings page (that Save would drop the extra accounts and the switches; keep your backup).
3. What v0.4.0 left behind in **additional** accounts is not removed automatically: one IP list and one custom rule per domain, both named as you configured them (default list
   `zoraxy_cf_waf_blocklist`, rule `Zoraxy CF WAF Sync - managed IP blocklist`). Delete the rule first, then the list, in the Cloudflare dashboard if you do not want them. Entries those accounts
   already hold are **not** expired once you are back on v0.3.x (older versions only manage Cloudflare Account 1), so remove them by hand as well, or leave them: they only block the addresses they list.
4. Detection goes back to the earlier version's list of paths, so a path that v0.4.0 banned and the old version ignores is no longer banned.

## What was tested, and what was not

Built in small steps with a test for each behaviour, then exercised on a throwaway Zoraxy as release candidate rc2 before it became v0.4.0. No private data is in this document or in the repository: figures are aggregates and test addresses are from the documentation ranges.

- **Automated tests: 116, all passing with the race detector**, `gofmt` and `go vet` clean. Beyond the multi-account tests (every account and domain blocked; one failing account gives *partial*; a same-named
  foreign rule is never edited; dry run makes no Cloudflare call; expiry per list; bad input rejected; tokens redacted in logs), the detection work adds tests for every new family at three response
  statuses, ordinary paths that must never be flagged, each switch, the never-ban list (exact, prefix, encoded and case variants), validation of what an operator may enter, live reload, a settings
  file that must not gain keys, and that the settings page lists every family. Deliberately breaking the switch or never-ban code makes these tests fail.
- **Real traffic replay.** 48,867 real external requests (seven months, one proxy) were replayed through the detector: 14 sweeps in that data are caught only by the new families, none of them looks like an ordinary
  visitor, and the cost per log line is the same with and without the new settings.
- **End to end on a test bench** (a throwaway Zoraxy running the real plugin against a **simulated** Cloudflare with three accounts and four domains): all accounts blocked from one request; one account
  returning 403 (partial, then recovered on the next block); a foreign rule with the plugin's rule name (left alone, the others protected); an account already at its one-list limit (error 10019, named);
  dry run (no calls made); 14-day expiry on every account's list; all new families reaching every account; a family switched off and a never-ban path honoured; an upgrade from an old single-account settings
  file (no new keys beyond the usual defaults); the **documented rollback** to v0.3.5, both keeping the new settings file and restoring the old one (the old version started, read the history, re-used the existing
  list and rule without duplicating them, and blocked new addresses on account 1).
- **The settings page and its Save path** were driven as the page does it: the multi-account settings, tokens and labels survive a Save; the new settings persist, invalid entries are refused with a message
  and change nothing, and switching a family off or on takes effect on the next log line.
- **Proof of upgrade in production.** On 11 November 2026 the maintainer upgraded their own production proxy from v0.3.5 to v0.4.0 (the tested release candidate rc2) following this guide, with the previous binary and settings kept as the rollback. All 35 proxied host names and aliases (10 of them aliases) returned the same status as before, none slower than a second; the 39 existing bans and 148 history entries were restored; the new families were seen detecting live in the journal; no errors.
- **Not tested: real second and third Cloudflare accounts.** The simulated Cloudflare follows the same API calls the plugin already makes on a real account (verified daily on the maintainer's single
  account), but it is not Cloudflare. Please report how it goes for you.
- **Not tested: arm64, ARMv7 and 386 on real hardware** (cross-compiled only).
- Known behaviour: if one account is down when an address is blocked, that account does not get a retry for that address until the re-block cooldown (default 24 hours) passes; the other accounts hold it meanwhile.

## What to try and what to report

- Test each account and domain; trigger a harmless block (request `/.env` on one of your own sites from a spare address) and confirm the address appears in **every** account's list and that each domain has
  the managed rule.
- Try a wrong token on one tab: the block should show as **partial** naming that account, and the others should still hold it.
- Check the families under **Scanner path detection** against your own applications and tell us about any legitimate path that was flagged.
- Report on the issue: what worked, what did not, your Zoraxy version, and the plugin's journal lines for the failure. **Remove tokens, Account IDs, Zone IDs, addresses and host names before posting.**
  A short "worked for me with N accounts / M domains" is just as valuable as a bug report. A pull request with a fix or a test is welcome.
