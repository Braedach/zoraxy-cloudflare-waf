# Contributing

Thank you for helping. This plugin changes a firewall unattended, so changes are held to a high bar: **safe, tested and boring beats clever.**

## Reporting a bug or asking for a feature

Open an issue. For a bug please include: the plugin version (`<binary> -introspect`), the Zoraxy version, what you expected and what happened, and the plugin's
journal lines (`journalctl -u zoraxy | grep -F "Zoraxy Cloudflare WAF plugin"`). **Remove anything secret first**: tokens, account and zone IDs, and addresses you
do not want public. Never paste `cloudflarewaf.json`. Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Pull requests

1. Open an issue first for anything beyond a small fix, so we agree the approach before you write it.
2. Before you push, all of this must pass:

   ```bash
   gofmt -l .                      # prints nothing
   go vet ./...
   go test -race -count=1 ./...
   ```
3. **Every behaviour change needs a test that fails without it.** Run the test once with your change reverted to prove it.
4. **The Cloudflare write path has hard rules** (they are tested; keep them so): a failed read never leads to a write; the plugin never resends or edits a rule
   it did not create; it never removes a list item it did not add; expiry only removes what this plugin created. A change that weakens one will not be merged.
5. **No secrets or private details** in code, tests, comments or commit messages: no real tokens, IDs, addresses or host names.
6. Update `CHANGELOG.md` (what changed **and why**) and the README if behaviour changes. Do not bump the version or tag a release in a pull request; the
   maintainer does that.
7. Keep commits small and the description honest about what is and is not verified.

## Releases (maintainer)

Version in `main.go` and `.introspect`, a `CHANGELOG.md` entry that states why, then tag, `./build.sh release`, and publish the four binaries plus
`SHA256SUMS`. Builds are reproducible with Go 1.24; verify that a rebuild of the tag matches before publishing. Tags and published files are never moved or
replaced.

## Conduct

Be kind and assume good faith. Bug reports and questions are welcome at any level of experience.
