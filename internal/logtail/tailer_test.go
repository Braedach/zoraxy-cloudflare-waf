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
		"/.gitignore", "/.github/workflows/ci.yml", "/.gitattributes",
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
