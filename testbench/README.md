# Test bench for release candidates and releases

Development tooling, never shipped. It lets a release be proven end to end on a **throwaway** Zoraxy with a **simulated** Cloudflare before it goes near a real proxy. It was used to prove v0.4.0.

- `fakecf/` is a small fake of the parts of the Cloudflare API the plugin uses, with several accounts, zones, list quotas and rule slots, and a control endpoint to make an account fail (see its header).
- `scripts/` holds the scenarios and helpers. They assume a Linux host with a throwaway Zoraxy installed as the systemd service `zoraxy-test` in `/srv/zoraxy`, the plugin in `/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf`, and `fakecf` listening on `127.0.0.1:9100`.
  **Never run them against a real proxy or real Cloudflare credentials.** All addresses used are from the documentation ranges and all tokens and IDs are fake.

## Setup

1. Build the bench binary of the version under test with the fake Cloudflare compiled in (the real release has no such URL):
   ```bash
   go build -trimpath -ldflags "-s -w -X github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare.apiBase=http://127.0.0.1:9100/client/v4" -o /srv/zoraxy/cfw-bench .
   ```
   (`apiBase` is a variable only for this; on an older tag change `const apiBase` to `var apiBase` first. For a release candidate add `-X main.buildLabel=rcN`.) Build the previous release the same way as `/srv/zoraxy/cfw-v035-bench` for the rollback scenario.
2. Build `fakecf` (`go build -o /srv/zoraxy/fakecf ./testbench/fakecf`) and copy `scripts/accounts.example.json` to `/srv/zoraxy/accounts.json` and `scripts/cfg-bench.example.json` to `/srv/zoraxy/cfg-bench.json` (three accounts, four domains, fake tokens).
3. Copy the scripts to `/srv/zoraxy` and make them executable. `feed.sh` appends one synthetic scanner request to the current month's Zoraxy log; `reset.sh` gives a fresh fake Cloudflare and fresh plugin state; `state.sh` prints what each fake account holds.

## Scenarios

| Script | What it proves |
|---|---|
| `scen.sh` | S2 to S7: one account returns 403 (partial, then recovered), a same-named foreign rule is left alone, an account already at its one-list limit, dry run makes no call, expiry. |
| `s7.sh` | Expiry across all accounts with the full wait (the first pass runs two minutes after start). |
| `scen2.sh` | The new families reach every account and domain; a switched-off family and a never-ban path are honoured; upgrade from an old single-account settings file adds no new keys. |
| `rb_rollback.sh` | The documented rollback to the previous release, keeping the new settings file and restoring the old one. |
| `save_roundtrip.py`, `live_reload.py` | Run **on the bench host**: drive the settings page's Save API as the page does (with the Zoraxy CSRF token): the multi-account settings survive a Save, invalid entries are refused, a saved switch takes effect on the next log line. |
| `inject_lines.py` | Appends real-format log lines and reports which were detected, with which label, and how long detection took. |

Replaying real logs through the detector is done with a throwaway Go test that reads a log file and counts candidates per family; keep any real logs out of the repository.
