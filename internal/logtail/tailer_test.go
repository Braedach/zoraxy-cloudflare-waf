package logtail

import (
	"fmt"
	"strings"
	"testing"
)

// Real Zoraxy access-log line shape:
// [ts] [router:...] [origin:host] [client: ip] [useragent: ...] METHOD /path STATUS
func line(ip, ua, method, path string, status int) string {
	return fmt.Sprintf("[2026-09-21 06:00:00.000000] [router:host-http] [origin:app.example.com] [client: %s] [useragent: %s] %s %s %d\n",
		ip, ua, method, path, status)
}

func collect(lines ...string) []Candidate {
	var got []Candidate
	t := New(Config{WindowSeconds: 60, Threshold: 30}, func(c Candidate) { got = append(got, c) })
	for _, l := range lines {
		t.handleLine(l)
	}
	return got
}

func TestProbePaths_Flagged_RegardlessOfStatus(t *testing.T) {
	paths := []string{
		"/.git/config", "/.git/HEAD", "/.git/config?x=1", "/.svn/entries", "/.hg/store",
		"/.env", "/.env.local", "/.env.production", "/.env/",
		"/.aws/credentials", "/.docker/config.json", "/.kube/config", "/.ssh/id_rsa",
		"/.config/gcloud/application_default_credentials.json", "/.anthropic/config.json", "/.vscode/sftp.json",
		"/.netrc", "/.npmrc", "/.pypirc", "/.htpasswd", "/.bash_history", "/.DS_Store",
		"/.boto", "/.s3cfg", "/.amplifyrc",
		"/.claude/settings.json", "/.claude/settings.local.json", "/.claude.json", "/.cursor/mcp.json", "/.cursor/", "/.mcp.json",
		"/.github/workflows/ci.yml", "/.github/", "/.gitlab/ci", "/.circleci/config.yml", "/.gitlab-ci.yml", "/.travis.yml",
		"/%2eclaude/settings.json", "/.claude/settings.json?x=1",
		"/credentials.json", "/gcp-credentials.json", "/google-credentials.json", "/client_secret.json",
		"/service-account.json", "/serviceaccount.yaml", "/id_rsa", "/id_ed25519",
		"/%2e%67it/config",     // percent-encoded ".git"
		"/%2E%65nv",            // percent-encoded ".env"
		"/sub/dir/.git/config", // not only at the root
	}
	for _, status := range []int{200, 307, 404} { // SPA fallbacks answer 200/307, real 404s answer 404
		for _, p := range paths {
			got := collect(line("203.0.113.9", "Mozilla/5.0", "GET", p, status))
			if len(got) != 1 {
				t.Errorf("%s (status %d): expected 1 candidate, got %d", p, status, len(got))
				continue
			}
			// (a few paths, e.g. /.env.production, are also caught by the older exploit-pattern rule first - either is fine)
			isProbe := strings.HasPrefix(got[0].Reason, "sensitive-path probe (") || got[0].Reason == "exploit-pattern-match in request line"
			if got[0].IP != "203.0.113.9" || !isProbe {
				t.Errorf("%s: unexpected candidate %+v", p, got[0])
			}
		}
	}
}

func TestProbePaths_LegitimatePathsAreNeverFlagged(t *testing.T) {
	paths := []string{
		"/", "/index.html", "/api/items?filter=1", "/login", "/static/app.js", "/favicon.ico", "/robots.txt",
		"/.well-known/webfinger?resource=acct:a@b", "/.well-known/nodeinfo", "/.well-known/acme-challenge/abc123",
		"/.well-known/security.txt", "/.well-known/matrix/server",
		"/.gitignore", "/.gitattributes", "/.gitlab-ci", "/claude/settings.json", "/cursor/mcp.json", "/github/workflows",
		"/owner/repo/src/branch/main/.github/workflows/ci.yml", "/group/project/-/blob/main/.gitlab-ci.yml",
		"/o/r/raw/branch/main/.claude/settings.json", "/o/r/src/branch/main/.cursor/rules/x.mdc", "/o/r/blob/main/.mcp.json",
		"/o/r/src/branch/main/.boto", "/o/r/tree/main/.circleci/config.yml", // a git forge showing a repository: not a scanner
		"/.claudeish", "/.cursorrules-doc", "/mcp.json", "/.githubusercontent", "/s3cfg", "/.boto3",
		"/environment", "/.environment", "/.envrc", "/app.env.js",
		"/config.json", "/manifest.json", "/package.json",
		"/phpinfo.php", "/wp-login.php", "/xmlrpc.php", // deliberately not covered - see probePatterns
		"/backup.zip", "/dump.tar.gz", "/db.sql.gz",
		"/api/credentialsbackup", "/users/credentials", // no .json/.xml/... extension
		"/ssh/keys", "/identity", "/docs/ssh-keys-guide",
	}
	for _, p := range paths {
		if got := collect(line("203.0.113.9", "Mozilla/5.0", "GET", p, 200)); len(got) != 0 {
			t.Errorf("%s must not be flagged, got %+v", p, got)
		}
	}
}

func TestProbePaths_OnlyTheRequestPathCounts(t *testing.T) {
	// the sensitive string sits in the user agent / origin, not in the request
	l := "[2026-09-21 06:00:00.000000] [router:host-http] [origin:x.example.com/.git/config] [client: 203.0.113.9] " +
		"[useragent: scanner (GET /.git/config 200)] GET / 200\n"
	if got := collect(l); len(got) != 0 {
		t.Errorf("text outside the request must not match, got %+v", got)
	}
}

func TestProbePaths_ReasonIsInformativeAndBounded(t *testing.T) {
	got := collect(line("203.0.113.9", "x", "GET", "/.git/config", 200))
	if len(got) != 1 || got[0].Reason != "sensitive-path probe (vcs): /.git/config" {
		t.Fatalf("unexpected reason: %+v", got)
	}
	long := "/.env/" + strings.Repeat("a", 500)
	got = collect(line("203.0.113.9", "x", "GET", long, 404))
	if len(got) != 1 || len(got[0].Reason) > 120 || !strings.HasSuffix(got[0].Reason, "...") {
		t.Fatalf("reason must be truncated: %+v", got)
	}
}

func TestExistingDetectionsStillWork(t *testing.T) {
	// exploit pattern in the request line
	got := collect(line("203.0.113.9", "x", "GET", "/../../etc/passwd", 404))
	if len(got) != 1 || got[0].Reason != "exploit-pattern-match in request line" {
		t.Errorf("exploit pattern: %+v", got)
	}

	// 4xx/5xx threshold: exactly one candidate when the 30th error lands, none for 2xx traffic
	var lines []string
	for i := 0; i < 35; i++ {
		lines = append(lines, line("198.51.100.4", "x", "GET", fmt.Sprintf("/missing-%d", i), 404))
	}
	got = collect(lines...)
	if len(got) != 1 || !strings.HasPrefix(got[0].Reason, "more than 30 4xx/5xx") {
		t.Errorf("threshold: %+v", got)
	}
	lines = nil
	for i := 0; i < 100; i++ {
		lines = append(lines, line("198.51.100.5", "x", "GET", fmt.Sprintf("/page-%d", i), 200))
	}
	if got := collect(lines...); len(got) != 0 {
		t.Errorf("clean traffic flagged: %+v", got)
	}
}

func TestPrivateAndOddLinesAreHandledWithoutPanic(t *testing.T) {
	for _, l := range []string{"", "garbage\n", "[client: ]\n", "[client: 1.2.3.4] no request here\n"} {
		_ = collect(l) // must not panic
	}
}

// n8n's editor requests /types/credentials.json on every page load; that must not get its user banned.
// The exception is exact: lookalikes are still flagged.
func TestKnownLegitimatePaths_N8nTypesFileIsNotFlagged(t *testing.T) {
	for _, p := range []string{"/types/credentials.json", "/types/credentials.json?v=1"} {
		if got := collect(line("203.0.113.9", "Mozilla/5.0", "GET", p, 200)); len(got) != 0 {
			t.Errorf("%s is n8n's own file and must not be flagged, got %+v", p, got)
		}
	}
}

func TestKnownLegitimatePaths_LookalikesAreStillFlagged(t *testing.T) {
	for _, p := range []string{
		"/credentials.json",            // the classic scanner target
		"/x/types/credentials.json",    // different directory
		"/api/types/credentials.json",  // different directory
		"/types/Credentials.json",      // case variant is not n8n's path
		"/types/credentials.yaml",      // different extension
		"/types/credentials.json.yaml", // longer name
		"/types/service-account.json",  // other credential-named file in the same directory
		"/types/%63redentials.json",    // encoded form: judged on the decoded path, not exempt
		"/types/credentials.json/../../credentials.json",
	} {
		got := collect(line("203.0.113.9", "Mozilla/5.0", "GET", p, 200))
		if len(got) != 1 {
			t.Errorf("%s must still be flagged, got %+v", p, got)
		}
	}
}

// ---- operator settings: category switches and the never-ban list ----

func collectWith(ps *ProbeSettings, lines ...string) []Candidate {
	var got []Candidate
	t := New(Config{WindowSeconds: 60, Threshold: 30}, func(c Candidate) { got = append(got, c) })
	t.SetProbeSettings(ps)
	for _, l := range lines {
		t.handleLine(l)
	}
	return got
}

func mustSettings(t *testing.T, disabled, allow []string) *ProbeSettings {
	t.Helper()
	d, a, err := NormaliseProbeSettings(disabled, allow)
	if err != nil {
		t.Fatalf("NormaliseProbeSettings(%v, %v): %v", disabled, allow, err)
	}
	return NewProbeSettings(d, a)
}

func TestProbeCategories_ListIsStableAndComplete(t *testing.T) {
	want := []string{"vcs", "dotenv", "tool-or-cloud-dir", "credential-dotfile", "agent-config", "ci-config", "credential-file", "ssh-key"}
	got := ProbeCategories()
	if len(got) != len(want) {
		t.Fatalf("categories = %v, want %v (the settings page lists these; update both)", got, want)
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("category %q missing from %v", w, got)
		}
	}
}

func TestProbeSettings_NilAndZeroBehaveAsBefore(t *testing.T) {
	for name, ps := range map[string]*ProbeSettings{"nil": nil, "empty": mustSettings(t, nil, nil)} {
		for _, p := range []string{"/.git/config", "/.env", "/.docker/config.json", "/.npmrc", "/.claude/settings.json", "/.github/workflows/ci.yml", "/credentials.json", "/id_rsa"} {
			if got := collectWith(ps, line("203.0.113.9", "UA", "GET", p, 200)); len(got) != 1 {
				t.Errorf("%s settings: %s should still be flagged, got %d candidates", name, p, len(got))
			}
		}
	}
}

func TestProbeSettings_DisablingACategorySkipsOnlyThatCategory(t *testing.T) {
	ps := mustSettings(t, []string{"ci-config", "agent-config"}, nil)
	for _, p := range []string{"/.github/workflows/ci.yml", "/.gitlab-ci.yml", "/.claude/settings.json", "/.mcp.json"} {
		if got := collectWith(ps, line("203.0.113.9", "UA", "GET", p, 200)); len(got) != 0 {
			t.Errorf("%s is in a switched-off category and must not be flagged, got %+v", p, got)
		}
	}
	for _, p := range []string{"/.git/config", "/.env", "/.npmrc", "/.aws/credentials", "/id_rsa", "/credentials.json", "/%2eclaude/x"} {
		want := 1
		if p == "/%2eclaude/x" {
			want = 0 // decoded form is agent-config, which is off
		}
		if got := collectWith(ps, line("203.0.113.9", "UA", "GET", p, 200)); len(got) != want {
			t.Errorf("%s: want %d candidate(s) with only ci-config and agent-config off, got %d", p, want, len(got))
		}
	}
}

func TestProbeSettings_NeverBanListExactAndPrefix(t *testing.T) {
	ps := mustSettings(t, nil, []string{"/.github/workflows/ci.yml", "/portal/.docker/*", "/.well-known-ish/.env"})
	allowed := []string{
		"/.github/workflows/ci.yml", "/.github/workflows/ci.yml?ref=main",
		"/portal/.docker/config.json", "/portal/.docker/a/b/c",
	}
	for _, p := range allowed {
		if got := collectWith(ps, line("203.0.113.9", "UA", "GET", p, 200)); len(got) != 0 {
			t.Errorf("%s is on the never-ban list and must not be flagged, got %+v", p, got)
		}
	}
	stillFlagged := []string{
		"/.github/workflows/ci.yml/extra", // exact entry is not a prefix
		"/.github/workflows/other.yml",    // a different file
		"/.GITHUB/workflows/ci.yml",       // matching is on the raw path, case-sensitive
		"/%2egithub/workflows/ci.yml",     // encoded variant is never allow-listed
		"/portal/.docker",                 // the prefix needs the slash
		"/other/.docker/config.json",      // different prefix
		"/.git/config", "/.env", "/.docker/config.json",
	}
	for _, p := range stillFlagged {
		if got := collectWith(ps, line("203.0.113.9", "UA", "GET", p, 200)); len(got) != 1 {
			t.Errorf("%s must still be flagged, got %d candidates", p, len(got))
		}
	}
}

func TestProbeSettings_NeverBanDoesNotCoverExploitPatterns(t *testing.T) {
	ps := mustSettings(t, nil, []string{"/app/*"})
	for _, p := range []string{"/app/../../etc/passwd", "/app/x?cmd=id", "/app/actuator/env"} {
		got := collectWith(ps, line("203.0.113.9", "UA", "GET", p, 200))
		if len(got) != 1 || got[0].Reason != "exploit-pattern-match in request line" {
			t.Errorf("%s: exploit patterns are outside the never-ban list, got %+v", p, got)
		}
	}
}

func TestProbeSettings_NeverBanDoesNotStopTheErrorThreshold(t *testing.T) {
	ps := mustSettings(t, nil, []string{"/app/*"})
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, line("203.0.113.9", "UA", "GET", "/app/missing", 404))
	}
	got := collectWith(ps, lines...)
	if len(got) != 1 || !strings.Contains(got[0].Reason, "4xx/5xx") {
		t.Errorf("30 errors from one client must still trip the threshold, got %+v", got)
	}
}

func TestProbeSettings_LiveReloadTakesEffectOnTheNextLine(t *testing.T) {
	var got []Candidate
	tl := New(Config{WindowSeconds: 60, Threshold: 30}, func(c Candidate) { got = append(got, c) })
	l := line("203.0.113.9", "UA", "GET", "/.github/workflows/ci.yml", 200)
	tl.handleLine(l)
	tl.SetProbeSettings(mustSettings(t, []string{"ci-config"}, nil))
	tl.handleLine(l)
	tl.SetProbeSettings(mustSettings(t, nil, nil))
	tl.handleLine(l)
	if len(got) != 2 {
		t.Errorf("flagged, switched off, flagged again: want 2 candidates, got %d", len(got))
	}
}

func TestProbeSettings_ConcurrentReloadIsRaceFree(t *testing.T) {
	tl := New(Config{WindowSeconds: 60, Threshold: 1000000}, func(Candidate) {})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if i%2 == 0 {
				tl.SetProbeSettings(NewProbeSettings([]string{"vcs"}, []string{"/a/*"}))
			} else {
				tl.SetProbeSettings(nil)
			}
		}
	}()
	for i := 0; i < 500; i++ {
		tl.handleLine(line("203.0.113.9", "UA", "GET", "/.git/config", 200))
	}
	<-done
}

func TestNormaliseProbeSettings_Validation(t *testing.T) {
	bad := []struct {
		name     string
		disabled []string
		allow    []string
	}{
		{"unknown category", []string{"vcss"}, nil},
		{"relative path", nil, []string{"myapp/x"}},
		{"bare wildcard", nil, []string{"/*"}},
		{"bare star", nil, []string{"*"}},
		{"slash only prefix", nil, []string{"/*"}},
		{"wildcard in the middle", nil, []string{"/a/*/b"}},
		{"query string", nil, []string{"/a?x=1"}},
		{"fragment", nil, []string{"/a#x"}},
		{"space", nil, []string{"/a b"}},
		{"control character", nil, []string{"/a\x00b"}},
		{"too long", nil, []string{"/" + strings.Repeat("a", maxProbeAllowLen)}},
	}
	for _, c := range bad {
		if _, _, err := NormaliseProbeSettings(c.disabled, c.allow); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
	var many []string
	for i := 0; i <= maxProbeAllowEntries; i++ {
		many = append(many, fmt.Sprintf("/p%d/x", i))
	}
	if _, _, err := NormaliseProbeSettings(nil, many); err == nil {
		t.Errorf("%d entries should be refused", len(many))
	}

	d, a, err := NormaliseProbeSettings([]string{" ci-config ", "ci-config", "", "vcs"}, []string{" /a/b ", "/a/b", "", "/c/*"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d, ",") != "ci-config,vcs" || strings.Join(a, ",") != "/a/b,/c/*" {
		t.Errorf("trim and de-duplicate failed: %v %v", d, a)
	}
	if d, a, err := NormaliseProbeSettings(nil, nil); err != nil || len(d) != 0 || len(a) != 0 {
		t.Errorf("empty input must be valid and empty: %v %v %v", d, a, err)
	}
}

func BenchmarkHandleLine_Probe(b *testing.B) {
	for name, ps := range map[string]*ProbeSettings{
		"no-settings":      nil,
		"4-off-20-allowed": NewProbeSettings([]string{"vcs", "dotenv", "ci-config", "agent-config"}, []string{"/a/*", "/b/*", "/c/*", "/d/*", "/e/*", "/f/*", "/g/*", "/h/*", "/i/*", "/j/*", "/k/x", "/l/x", "/m/x", "/n/x", "/o/x", "/p/x", "/q/x", "/r/x", "/s/x", "/t/x"}),
	} {
		for kind, l := range map[string]string{
			"ordinary": line("203.0.113.9", "Mozilla/5.0", "GET", "/static/app.js", 200),
			"probe":    line("203.0.113.9", "Mozilla/5.0", "GET", "/.claude/settings.json", 200),
		} {
			b.Run(name+"/"+kind, func(b *testing.B) {
				tl := New(Config{WindowSeconds: 60, Threshold: 1 << 30}, func(Candidate) {})
				tl.SetProbeSettings(ps)
				for i := 0; i < b.N; i++ {
					tl.handleLine(l)
				}
			})
		}
	}
}
