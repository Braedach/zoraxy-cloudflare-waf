package zoraxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type seen struct {
	Method, Path, Auth, ContentType string
	Query, Form                     url.Values
}

func fakeZoraxy(t *testing.T, routes map[string]func(w http.ResponseWriter)) (*Client, func() []seen) {
	t.Helper()
	var mu sync.Mutex
	var reqs []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		mu.Lock()
		reqs = append(reqs, seen{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.URL.Query(), form})
		mu.Unlock()
		h, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		h(w)
	}))
	t.Cleanup(srv.Close)
	c := New(81, "secret-key")
	c.BaseURL = srv.URL
	return c, func() []seen { mu.Lock(); defer mu.Unlock(); return append([]seen(nil), reqs...) }
}

func respond(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestBanIP_SendsWhatZoraxyReads(t *testing.T) {
	c, got := fakeZoraxy(t, map[string]func(http.ResponseWriter){"POST " + PathBlacklistAdd: respond(`"OK"`)})
	if err := c.BanIP(context.Background(), "default", "203.0.113.9", "zoraxy-cloudflare-waf: probe <script>x</script>\n/.git/config"); err != nil {
		t.Fatal(err)
	}
	r := got()[0]
	if r.Auth != "Bearer secret-key" {
		t.Errorf("auth header: %q", r.Auth)
	}
	if !strings.HasPrefix(r.ContentType, "application/x-www-form-urlencoded") {
		t.Errorf("content type: %q", r.ContentType)
	}
	if r.Form.Get("ip") != "203.0.113.9" || r.Form.Get("id") != "default" {
		t.Errorf("ip/id must be in the form body: %v", r.Form)
	}
	// Zoraxy reads the comment from the query string, and the text must be sanitised
	cm := r.Query.Get("comment")
	if cm == "" || strings.ContainsAny(cm, "<>\n") {
		t.Errorf("comment must be in the query and sanitised: %q", cm)
	}
}

func TestZoraxyErrorsArrive_AsHTTP200WithErrorBody(t *testing.T) {
	c, _ := fakeZoraxy(t, map[string]func(http.ResponseWriter){
		"POST " + PathBlacklistAdd: respond(`{"error":"access rule not found"}`),
	})
	err := c.BanIP(context.Background(), "nope", "203.0.113.9", "x")
	if err == nil || !strings.Contains(err.Error(), "access rule not found") {
		t.Fatalf("expected Zoraxy's error message, got %v", err)
	}
}

func TestUnexpectedSuccessBodyIsAnError(t *testing.T) {
	c, _ := fakeZoraxy(t, map[string]func(http.ResponseWriter){"POST " + PathBlacklistAdd: respond(`"maybe"`)})
	if err := c.BanIP(context.Background(), "default", "203.0.113.9", "x"); err == nil {
		t.Fatal("anything other than \"OK\" must not count as success")
	}
}

func TestRefusedByAuth_ExplainsThePermissionProblem(t *testing.T) {
	for _, status := range []int{401, 403} {
		c, _ := fakeZoraxy(t, map[string]func(http.ResponseWriter){
			"GET " + PathAccessList: func(w http.ResponseWriter) { w.WriteHeader(status) },
		})
		_, err := c.ListAccessRules(context.Background())
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != status || !strings.Contains(err.Error(), "permissions") {
			t.Errorf("status %d: got %v", status, err)
		}
	}
}

func TestListAccessRules_ParsesTheFlagsThatDecideWhetherABanCanWork(t *testing.T) {
	c, got := fakeZoraxy(t, map[string]func(http.ResponseWriter){"GET " + PathAccessList: respond(`[
	 {"ID":"default","Name":"Default","Desc":"","BlacklistEnabled":true,"WhitelistEnabled":false,"WhitelistAllowLocalAndLoopback":false,"TrustProxyHeadersOnly":false,"BlackListIP":{}},
	 {"ID":"e8f2","Name":"Australia Only","BlacklistEnabled":false,"WhitelistEnabled":true,"WhitelistAllowLocalAndLoopback":true,"TrustProxyHeadersOnly":true}]`)})
	rules, err := c.ListAccessRules(context.Background())
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	if !rules[0].BlacklistEnabled || rules[1].BlacklistEnabled || !rules[1].TrustProxyHeadersOnly || !rules[1].WhitelistAllowLocalAndLoopback || rules[1].Name != "Australia Only" {
		t.Errorf("flags not parsed: %+v", rules)
	}
	if got()[0].Auth != "Bearer secret-key" {
		t.Error("list call must be authenticated")
	}
}

func TestUnbanAndListBanned(t *testing.T) {
	c, got := fakeZoraxy(t, map[string]func(http.ResponseWriter){
		"POST " + PathBlacklistRemove: respond(`"OK"`),
		"GET " + PathBlacklistList:    respond(`["203.0.113.9","198.51.100.4"]`),
	})
	if err := c.UnbanIP(context.Background(), "e8f2", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	ips, err := c.ListBannedIPs(context.Background(), "e8f2")
	if err != nil || len(ips) != 2 {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	reqs := got()
	if reqs[0].Form.Get("ip") != "203.0.113.9" || reqs[0].Form.Get("id") != "e8f2" {
		t.Errorf("unban form: %v", reqs[0].Form)
	}
	if reqs[1].Query.Get("type") != "ip" || reqs[1].Query.Get("id") != "e8f2" {
		t.Errorf("list query: %v", reqs[1].Query)
	}
}

func TestBadArgumentsNeverReachZoraxy(t *testing.T) {
	c, got := fakeZoraxy(t, map[string]func(http.ResponseWriter){})
	cases := []struct{ rule, ip string }{
		{"default", "203.0.113.0/24"}, // a range, not a single IP
		{"default", "not-an-ip"},
		{"default", ""},
		{"", "203.0.113.9"},
		{"bad rule!", "203.0.113.9"},
		{"../../x", "203.0.113.9"},
	}
	for _, tc := range cases {
		if err := c.BanIP(context.Background(), tc.rule, tc.ip, "x"); err == nil {
			t.Errorf("BanIP(%q,%q) should be refused", tc.rule, tc.ip)
		}
		if err := c.UnbanIP(context.Background(), tc.rule, tc.ip); err == nil {
			t.Errorf("UnbanIP(%q,%q) should be refused", tc.rule, tc.ip)
		}
	}
	if len(got()) != 0 {
		t.Fatalf("no request may be sent for bad arguments, got %d", len(got()))
	}
}

func TestSanitizeComment(t *testing.T) {
	if got := SanitizeComment("a\tb\n<img src=x>  c"); got != "a b img src=x c" {
		t.Errorf("got %q", got)
	}
	if got := SanitizeComment(strings.Repeat("x", 500)); len([]rune(got)) != 150 {
		t.Errorf("length %d", len([]rune(got)))
	}
}
