# Testing

The suite needs no network and no Cloudflare or Zoraxy account: the Cloudflare and Zoraxy clients are tested against in-process fake servers that
record every request, so the tests can assert not only what the plugin sends but what it does **not** send.

```bash
gofmt -l .                          # must print nothing
go vet ./...
go test -race -count=1 ./...        # the race detector matters: detectors submit concurrently
go test -race -count=1 -v ./... | grep -c '^--- PASS'   # 63 at v0.3.2
```

**Result at v0.3.2 (re-run 21 October 2026, Go 1.24, clean checkout of the tag):** 63 passed, 0 failed, race detector clean, `gofmt` and `go vet` clean.
Release binaries for v0.3.1 and v0.3.2 also rebuild byte-for-byte identical to the published files (see the README, "Verifying a release").

## What the 63 tests prove

| Package | Tests | What they prove |
|---|---:|---|
| root (`config_test.go`) | 5 | Settings validation: list names and block actions are accepted or rejected as documented, the default configuration is valid, access-rule IDs are normalised, and the defaults give automatic expiry with the Zoraxy layer off. |
| `internal/logtail` | 8 | Detection. Sensitive paths are flagged **whatever the response status**; ordinary paths (`/.well-known/`, `config.json`, `robots.txt` and others) never are; only the request path counts, not the user-agent or host; the reason text is informative and bounded; the original exploit-pattern and error-burst detectors still work; odd or private lines never panic. An exact-path exception exists for one application's own front-end file, and its lookalikes are still flagged. |
| `internal/cloudflare` | 23 | The Cloudflare write path. A failed read **never** leads to a write; other rules are **never** resent; a rule with our name that we did not create is left untouched; rules are added with the single-rule call and edited by ID so a rename is a patch, not a duplicate; a paused rule stays paused; list items are added with the documented call; quota errors become a plain-language message; a non-IP list with our name is refused; pagination follows cursors and refuses runaway results rather than truncating; deletes refuse an empty set. |
| `internal/zoraxy` | 8 | The Zoraxy API client sends what Zoraxy reads, treats Zoraxy's HTTP-200-with-error replies as errors, explains a refused permission, parses the flags that decide whether a ban can work, never sends bad arguments, and sanitises comments. |
| `internal/blocker` | 19 at v0.3.2, 27 from v0.3.3 | The decision layer. Both layers succeed, fail or half-succeed independently and report `blocked`, `partial` or `error` correctly; Cloudflare alone and Zoraxy alone both work; dry-run touches nothing; a rule with its blacklist switched off is flagged. Expiry removes **only** old entries this plugin created, does nothing after a failed read, never creates a list, is capped per run, retries a failed removal, keeps a record of each Zoraxy ban, survives a corrupt record file, and reports an address removed from both layers once. From v0.3.3 the action history is tested too: it round-trips in order, stays within its size cap and rotates correctly, skips unreadable lines (including a crash-torn last line, without losing the next entry), is private (mode 0600), is restored after a simulated restart without suppressing any block, and a failing disk can never stop a ban. |

## How the fakes work

`internal/blocker/blocker_test.go` and the client tests start `httptest` servers that stand in for Cloudflare and Zoraxy. Each fake records every request
(method, path, body). A test sets up the routes it needs, runs the code, then asserts on the recorded calls, for example "no `PUT` was sent",
"exactly one `DELETE` with these IDs". Unknown routes fail the test, so an unintended call cannot go unnoticed.

## Checking a running installation

The unit tests cannot see your live accounts. To confirm a real installation, use the checklist in the README, "How to tell it is working": the journal shows
the loaded settings and hourly proof of life, and the Cloudflare list, the plugin's ban record and the selected Zoraxy blacklists agree.

## Adding a test

Put it next to the code it covers, use the existing fakes, and make it fail without your change (run it once with the change reverted). Anything that
touches the Cloudflare write path needs a test that proves what is **not** sent. See [CONTRIBUTING.md](../CONTRIBUTING.md).
