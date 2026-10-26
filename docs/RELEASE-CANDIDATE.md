# Release candidate: several Cloudflare accounts and zones (v0.4.0-rc1)

> **RELEASE CANDIDATE: FOR TESTING, NOT FOR PRODUCTION.**
> This build is provided as-is, without warranty, to be tested by people who need the feature (issue #5). It has **not** been run against a
> real second or third Cloudflare account by the maintainer. If you run it on a Zoraxy that protects real sites, you do so at your own risk:
> a mistake in a block-list tool can block legitimate visitors or leave scanners unblocked. Prefer a spare or test Zoraxy; if you must use your
> live one, follow "Rollback" first so you can get back in minutes. It is published as a GitHub **pre-release**, is never offered by the Zoraxy
> plugin store, and is never the "latest" release.

## What it adds

Three Cloudflare accounts instead of one, each with up to five zones: up to **fifteen zones**. On the settings page the Cloudflare section has three tabs,
**Cloudflare Account 1, 2 and 3**. Each tab has its own API token, Account ID, zone IDs, IP list name, rule name and **block action** (for example
`block` on one account and `managed_challenge` on another). A blocked IP goes to every enabled account and zone. One account failing never stops the others.
If you use only Cloudflare Account 1, **nothing changes**: same settings, same behaviour, same files.

## Before you start

1. A Cloudflare API token **per account**, each with `Account → Account Filter Lists → Edit` and `Zone → WAF → Edit` (scoped to that account and its zones).
2. The Account ID and the zone IDs of each account (Cloudflare dashboard, the zone's Overview page, right-hand column).
3. The **Free plan allows one IP list per account**. The plugin uses exactly one per account. If an account already holds another list it cannot create its own
   (Cloudflare error 10019); the plugin says so and the other accounts are unaffected.
4. Each zone needs one free custom-rule slot (Free plan: five per zone).

## Install (about five minutes)

Replace the paths with your own. `$PLUGIN_DIR` is the folder Zoraxy keeps this plugin in (the one containing `cloudflarewaf.json`).

1. **Back up first.** Both the binary and the settings:
   ```bash
   cp "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf" /root/cloudflarewaf.before-rc1.bin
   cp -p "$PLUGIN_DIR/cloudflarewaf.json"            /root/cloudflarewaf.before-rc1.json
   ```
2. Download the RC binary for your CPU and the checksum file from the **pre-release** page (not "latest"), and check it:
   ```bash
   ARCH=amd64        # or arm64, arm, 386
   curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/download/v0.4.0-rc1/cloudflarewaf-rc1_linux_$ARCH
   curl -fLO https://github.com/Braedach/zoraxy-cloudflare-waf/releases/download/v0.4.0-rc1/SHA256SUMS
   sha256sum --ignore-missing -c SHA256SUMS      # must print: cloudflarewaf-rc1_linux_<arch>: OK
   ```
3. Install it over the old binary by renaming (never copy over a running file):
   ```bash
   install -m 755 cloudflarewaf-rc1_linux_$ARCH "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new"
   mv "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new" "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"
   ```
4. Restart Zoraxy once. The settings page now shows a red **RELEASE CANDIDATE** banner. The plugin list shows version 0.4.0.
5. Set **Dry run** on. Fill in Cloudflare Account 1 as before. Open the tab for each further account, tick **Enabled** on that tab, enter its token, Account ID and
   zone IDs, and press **Test** (it checks every zone of that account separately). Read "How this works" on the page for the details.
6. Leave dry run on until the journal shows `would have added to` lines naming every account. Then switch dry run off.

## What to try and what to report

- Test each account and zone; trigger a harmless block (request `/.env` on one of your own sites from a spare address) and confirm the IP appears in **every**
  account's list and that each zone has the managed rule.
- Try a wrong token on one tab: the block should show as **partial** naming that account, and the others should still hold it.
- Report on the issue: what worked, what did not, your Zoraxy version, and the plugin's journal lines for the failure. **Remove tokens, Account IDs and zone IDs
  before posting.** A short "worked for me with N accounts / M zones" is just as valuable as a bug report. A pull request with a fix or a test is welcome.

## Migrating from v0.3.3 / v0.3.4: will it break anything?

No. This was tested (see below) and designed so that it cannot:

- **Settings.** Your existing `cloudflarewaf.json` loads unchanged. Cloudflare Account 1 *is* your existing token, account, zone and list settings; they stay at the top level
  of the file. The new keys (`extra_zone_ids`, `additional_targets`) are written only once you use a second account or a second zone, and an unused tab is never stored.
- **History and logs.** `zoraxy_actions.jsonl` keeps the same format, so the old entries still load and show in Recent actions. With one account the log lines and the
  `detail` text are exactly as before. With several accounts the `detail` becomes `Cloudflare Account 1: ok; Cloudflare Account 2: <reason>; …` and each account's expiry
  is logged on its own line. The result can now also be **partial** (some accounts protected, one failed). The ban record `zoraxy_bans.json` is unchanged.
- **Cloudflare.** The existing list and rule are found by name and re-used; nothing is recreated. A rule with the same name that is not the plugin's is never edited.
- **Going back.** Older versions ignore the new settings, so they run as single-account, and they leave the new keys in the file untouched until you press Save on
  their settings page (that Save would drop the extra accounts; keep your backup).

## Rollback

1. Put the old binary back by renaming, then restart Zoraxy:
   ```bash
   install -m 755 /root/cloudflarewaf.before-rc1.bin "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new"
   mv "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf.new" "$PLUGIN_DIR/com.braedach.zoraxy.cloudflarewaf"
   ```
2. Optional: restore the settings backup (`cp -p /root/cloudflarewaf.before-rc1.json "$PLUGIN_DIR/cloudflarewaf.json"`). It is not required to run the old version.
3. What the RC left behind in **additional** accounts is not removed automatically: one IP list and one custom rule per zone, both named as you configured them (default list
   `zoraxy_cf_waf_blocklist`, rule `Zoraxy CF WAF Sync - managed IP blocklist`). Delete the rule first, then the list, in the Cloudflare dashboard if you do not want them.
   Entries expire on their own only while an RC (or later) build is running.

## What was tested, and what was not

Not pulled out of a hat: the change was built in small steps with a test for each behaviour, then exercised end to end on a throwaway Zoraxy before this candidate was cut.

- **Automated tests (114, with the race detector).** Every account and zone is blocked; one failing account gives *partial* while the others are protected; all failing gives an
  error; a same-named foreign rule in one zone is never edited and the other zones are still protected; each zone's rule ID is remembered separately; dry run names every list and makes
  no Cloudflare call; an account with no credentials is skipped; a full list stops only that account; expiry covers each distinct list once and a failing account does not stop the
  others; a v0.3.4 settings file loads unchanged and writes no new keys; bad input (zone and account IDs, labels, too many accounts or zones) is rejected; tokens are redacted in the log.
- **End-to-end on a test bench.** A throwaway Zoraxy with the real plugin, driven by synthetic scanner requests (documentation-range addresses) against a **simulated** Cloudflare
  with three accounts (four zones, one list each, rule slots, error codes): all accounts and zones blocked from one request; one account returning 403 (partial, then
  recovered on the next block); a foreign rule with our rule's name (left alone, other zones protected); an account already at its one-list limit (Cloudflare error 10019 reported by
  name); dry run (no calls made); 14-day expiry on every account's list; upgrade from a v0.3.4 settings and history file; and downgrade to v0.3.4 with the RC's settings file
  (loads, file untouched).
- **Not tested: real second and third Cloudflare accounts.** The simulated Cloudflare follows the same API calls the plugin already makes on a real account (verified daily on the
  maintainer's single account), but it is not Cloudflare. That is exactly why this candidate needs your feedback before it can become a release.
- Known behaviour: if one account is down when an IP is blocked, that account does not get a retry for that IP until the re-block cooldown (default 24 hours) passes; the other accounts hold it meanwhile.
