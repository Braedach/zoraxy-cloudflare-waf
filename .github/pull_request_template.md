## What and why

## Checklist
- [ ] `gofmt -l .` prints nothing; `go vet ./...` and `go test -race -count=1 ./...` pass
- [ ] Every behaviour change has a test that fails without it
- [ ] The Cloudflare write-path rules in CONTRIBUTING.md still hold
- [ ] No secrets, IDs, addresses or host names anywhere in the change
- [ ] CHANGELOG.md says what changed **and why**; README updated if behaviour changed
- [ ] I have not bumped the version or tagged a release
