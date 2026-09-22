package blocker

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/ipfilter"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/zoraxy"
)

// ---- fake servers that record every request ----

type req struct{ Method, Path, RawQuery, Body string }

type fake struct {
	mu     sync.Mutex
	reqs   []req
	routes map[string]http.HandlerFunc
}

func newFake(t *testing.T, routes map[string]http.HandlerFunc) (*fake, *httptest.Server) {
	t.Helper()
	f := &fake{routes: routes}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, req{r.Method, r.URL.Path, r.URL.RawQuery, string(b)})
		f.mu.Unlock()
		h, ok := f.routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fake) count(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (f *fake) all(method, path string) []req {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []req
	for _, r := range f.reqs {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func (f *fake) total() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }

func cfOK(result string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":` + result + `}`))
	}
}

func cfFail(status, code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"success":false,"errors":[{"code":%d,"message":"nope"}],"result":null}`, code)))
	}
}

func zxOK(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }
}

const (
	entrypoint = "/zones/z/rulesets/phases/http_request_firewall_custom/entrypoint"
	ourRule    = `{"id":"OURS","description":"WAF","expression":"(ip.src in $mylist)","action":"block","enabled":true}`
)

// happyCF routes for a full successful Cloudflare block.
func happyCF() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /accounts/a/rules/lists":           cfOK(`[{"id":"L1","name":"mylist","kind":"ip","num_items":3}]`),
		"GET /accounts/a/rules/lists/L1":        cfOK(`{"id":"L1","name":"mylist","num_items":3}`),
		"GET " + entrypoint:                     cfOK(`{"id":"RS1","phase":"http_request_firewall_custom","rules":[` + ourRule + `]}`),
		"POST /accounts/a/rules/lists/L1/items": cfOK(`{"operation_id":"op"}`),
	}
}

type harness struct {
	b        *Blocker
	cf, zx   *fake
	bans     *BanStore
	settings *settings
}

type settings struct {
	enabled, dryRun, zoraxyOn, cfConfigured, zoraxyAvailable bool
	rules                                                    []string
	expiryDays                                               int
}

func build(t *testing.T, cfRoutes, zxRoutes map[string]http.HandlerFunc, s *settings) *harness {
	t.Helper()
	cfFake, cfSrv := newFake(t, cfRoutes)
	zxFake, zxSrv := newFake(t, zxRoutes)
	bans := LoadBanStore(filepath.Join(t.TempDir(), "bans.json"))
	deps := Deps{
		GetEnabled:         func() bool { return s.enabled },
		GetDryRun:          func() bool { return s.dryRun },
		GetTTL:             func() time.Duration { return time.Hour },
		GetIPListName:      func() string { return "mylist" },
		GetBlockAction:     func() string { return "block" },
		GetRuleDescription: func() string { return "WAF" },
		GetManagedRuleID:   func() string { return "OURS" },
		SetManagedRuleID:   func(string) {},
		GetMaxListItems:    func() int { return 10000 },
		NewCFClient: func() (*cloudflare.Client, bool) {
			if !s.cfConfigured {
				return nil, false
			}
			c := cloudflare.New("a", "z", "tok")
			c.Base = cfSrv.URL
			return c, true
		},
		GetExpiryDays:       func() int { return s.expiryDays },
		GetZoraxyBanEnabled: func() bool { return s.zoraxyOn },
		GetZoraxyRules:      func() []string { return s.rules },
		NewZoraxyClient: func() (*zoraxy.Client, bool) {
			if !s.zoraxyAvailable {
				return nil, false
			}
			c := zoraxy.New(81, "key")
			c.BaseURL = zxSrv.URL
			return c, true
		},
		Bans: bans,
	}
	return &harness{b: New(deps, ipfilter.NewChecker()), cf: cfFake, zx: zxFake, bans: bans, settings: s}
}

func live() *settings {
	return &settings{enabled: true, cfConfigured: true, zoraxyAvailable: true, rules: []string{"default"}, expiryDays: 14}
}

func (h *harness) submit(ip string) Action {
	h.b.Submit(context.Background(), Candidate{IP: ip, Reason: "sensitive-path probe (vcs): /.git/config", Source: "logtail"})
	hist := h.b.History()
	return hist[len(hist)-1]
}

func zxRoutes(rules string, addResp string) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /plugin/api/access/list":          zxOK(rules),
		"POST /plugin/api/blacklist/ip/add":    zxOK(addResp),
		"POST /plugin/api/blacklist/ip/remove": zxOK(`"OK"`),
	}
}

const defaultRule = `[{"ID":"default","Name":"Default","BlacklistEnabled":true}]`

// ---- Submit: layers ----

func TestSubmit_CloudflareOnly_KeepsTheOriginalResults(t *testing.T) {
	s := live()
	h := build(t, happyCF(), zxRoutes(defaultRule, `"OK"`), s)
	if a := h.submit("203.0.113.9"); a.Result != "blocked" || a.Detail != "" {
		t.Fatalf("got %+v", a)
	}
	if h.zx.total() != 0 {
		t.Errorf("Zoraxy layer is off - it must not be called, got %d requests", h.zx.total())
	}
	if h.cf.count("POST", "/accounts/a/rules/lists/L1/items") != 1 {
		t.Error("expected one Cloudflare add")
	}
}

func TestSubmit_BothLayers_Blocked_AndTheBanIsRecordedForExpiry(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	h := build(t, happyCF(), zxRoutes(defaultRule, `"OK"`), s)
	a := h.submit("203.0.113.9")
	if a.Result != "blocked" || !strings.Contains(a.Detail, "banned in 1 access rule(s)") || !strings.Contains(a.Detail, "cloudflare: ok") {
		t.Fatalf("got %+v", a)
	}
	adds := h.zx.all("POST", "/plugin/api/blacklist/ip/add")
	if len(adds) != 1 {
		t.Fatalf("expected one Zoraxy ban, got %d", len(adds))
	}
	form, _ := url.ParseQuery(adds[0].Body)
	if form.Get("ip") != "203.0.113.9" || form.Get("id") != "default" {
		t.Errorf("ban form: %v", form)
	}
	if h.bans.Len() != 1 {
		t.Error("the ban must be recorded so it can expire")
	}
}

func TestSubmit_CloudflareQuotaError_ButZoraxyBanWorks_IsPartial(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	cf := happyCF()
	cf["GET /accounts/a/rules/lists"] = cfOK(`[{"id":"X","name":"myip","kind":"ip","num_items":1}]`)
	cf["POST /accounts/a/rules/lists"] = cfFail(400, 10019)
	h := build(t, cf, zxRoutes(defaultRule, `"OK"`), s)
	a := h.submit("203.0.113.9")
	if a.Result != "partial" || !strings.Contains(a.Detail, "maximum number of custom lists") || !strings.Contains(a.Detail, "zoraxy: banned in 1") {
		t.Fatalf("got %+v", a)
	}
	if h.bans.Len() != 1 {
		t.Error("the Zoraxy ban that worked must still be tracked")
	}
}

func TestSubmit_ZoraxyFails_ButCloudflareWorks_IsPartial(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	h := build(t, happyCF(), zxRoutes(defaultRule, `{"error":"access rule not found"}`), s)
	a := h.submit("203.0.113.9")
	if a.Result != "partial" || !strings.Contains(a.Detail, "cloudflare: ok") || !strings.Contains(a.Detail, "access rule not found") {
		t.Fatalf("got %+v", a)
	}
	if h.bans.Len() != 0 {
		t.Error("a failed ban must not be recorded")
	}
}

func TestSubmit_BothFail_IsAnError(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	s.zoraxyAvailable = false
	cf := happyCF()
	cf["POST /accounts/a/rules/lists/L1/items"] = cfFail(500, 1000)
	h := build(t, cf, zxRoutes(defaultRule, `"OK"`), s)
	if a := h.submit("203.0.113.9"); a.Result != "error" || !strings.Contains(a.Detail, "Zoraxy API not available") {
		t.Fatalf("got %+v", a)
	}
}

func TestSubmit_WithoutCloudflareCredentials_ZoraxyAloneIsEnough(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	s.cfConfigured = false
	h := build(t, map[string]http.HandlerFunc{}, zxRoutes(defaultRule, `"OK"`), s)
	a := h.submit("203.0.113.9")
	if a.Result != "blocked" || strings.Contains(a.Detail, "cloudflare") {
		t.Fatalf("got %+v", a)
	}
	// and with the Zoraxy layer off too, it is still the original error
	s.zoraxyOn = false
	if a := h.submit("203.0.113.10"); a.Result != "error" || !strings.Contains(a.Detail, "credentials not configured") {
		t.Fatalf("got %+v", a)
	}
}

func TestSubmit_WarnsWhenTheChosenRuleHasItsBlacklistOff(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	s.rules = []string{"au"}
	h := build(t, happyCF(), zxRoutes(`[{"ID":"au","Name":"Australia Only","BlacklistEnabled":false}]`, `"OK"`), s)
	a := h.submit("203.0.113.9")
	if a.Result != "blocked" || !strings.Contains(a.Detail, `"Australia Only" has its blacklist switched OFF`) {
		t.Fatalf("got %+v", a)
	}
}

func TestSubmit_DryRunTouchesNothing(t *testing.T) {
	s := live()
	s.dryRun = true
	s.zoraxyOn = true
	h := build(t, map[string]http.HandlerFunc{}, map[string]http.HandlerFunc{}, s)
	a := h.submit("203.0.113.9")
	if a.Result != "dry-run" || !strings.Contains(a.Detail, "would ban in Zoraxy") {
		t.Fatalf("got %+v", a)
	}
	if h.cf.total()+h.zx.total() != 0 || h.bans.Len() != 0 {
		t.Fatal("dry run must not call Cloudflare or Zoraxy or record bans")
	}
}

// ---- expiry ----

var now = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func iso(daysAgo int) string {
	return now.Add(-time.Duration(daysAgo) * 24 * time.Hour).Format(time.RFC3339)
}

func item(id, ip, comment, modified string) string {
	return fmt.Sprintf(`{"id":%q,"ip":%q,"comment":%q,"created_on":%q,"modified_on":%q}`, id, ip, comment, modified, modified)
}

func expiryCF(items ...string) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /accounts/a/rules/lists":             cfOK(`[{"id":"L1","name":"mylist","kind":"ip"}]`),
		"GET /accounts/a/rules/lists/L1/items":    cfOK("[" + strings.Join(items, ",") + "]"),
		"DELETE /accounts/a/rules/lists/L1/items": cfOK(`{"operation_id":"op"}`),
	}
}

func TestPrune_RemovesOnlyOldEntriesTheProxyCreated(t *testing.T) {
	s := live()
	h := build(t, expiryCF(
		item("old-ours", "203.0.113.1", "zoraxy/logtail: probe", iso(20)),
		item("new-ours", "203.0.113.2", "zoraxy/logtail: probe", iso(3)),
		item("old-manual", "203.0.113.3", "blocked by hand", iso(400)),
		item("old-nocomment", "203.0.113.4", "", iso(400)),
		item("old-ours-badtime", "203.0.113.5", "zoraxy/logtail: probe", "not-a-time"),
	), map[string]http.HandlerFunc{}, s)
	h.b.PruneExpired(context.Background(), now)

	dels := h.cf.all("DELETE", "/accounts/a/rules/lists/L1/items")
	if len(dels) != 1 {
		t.Fatalf("expected one delete, got %d", len(dels))
	}
	if !strings.Contains(dels[0].Body, "old-ours") || strings.Contains(dels[0].Body, "new-ours") ||
		strings.Contains(dels[0].Body, "old-manual") || strings.Contains(dels[0].Body, "old-nocomment") || strings.Contains(dels[0].Body, "badtime") {
		t.Errorf("only the old, plugin-created entry may be deleted: %s", dels[0].Body)
	}
	hist := h.b.History()
	if len(hist) != 1 || hist[0].Result != "expired" || !strings.Contains(hist[0].Detail, "203.0.113.1") {
		t.Errorf("expected an 'expired' action: %+v", hist)
	}
}

func TestPrune_DoesNothingWhenItShouldNot(t *testing.T) {
	for name, mutate := range map[string]func(*settings){
		"expiry off":  func(s *settings) { s.expiryDays = 0 },
		"disabled":    func(s *settings) { s.enabled = false },
		"dry run":     func(s *settings) { s.dryRun = true },
		"no cf creds": func(s *settings) { s.cfConfigured = false },
	} {
		t.Run(name, func(t *testing.T) {
			s := live()
			mutate(s)
			h := build(t, expiryCF(item("old", "203.0.113.1", "zoraxy/logtail: x", iso(90))), map[string]http.HandlerFunc{}, s)
			h.b.PruneExpired(context.Background(), now)
			if h.cf.total() != 0 {
				t.Fatalf("no Cloudflare calls expected, got %d", h.cf.total())
			}
		})
	}
}

func TestPrune_AReadFailureDeletesNothing(t *testing.T) {
	s := live()
	cf := expiryCF()
	cf["GET /accounts/a/rules/lists/L1/items"] = cfFail(500, 1000)
	h := build(t, cf, map[string]http.HandlerFunc{}, s)
	h.b.PruneExpired(context.Background(), now)
	if n := h.cf.count("DELETE", "/accounts/a/rules/lists/L1/items"); n != 0 {
		t.Fatalf("a failed read must never lead to a delete, got %d", n)
	}
}

func TestPrune_NeverCreatesAListAndSkipsAMissingOne(t *testing.T) {
	s := live()
	h := build(t, map[string]http.HandlerFunc{"GET /accounts/a/rules/lists": cfOK(`[]`)}, map[string]http.HandlerFunc{}, s)
	h.b.PruneExpired(context.Background(), now)
	if h.cf.count("POST", "/accounts/a/rules/lists") != 0 || h.cf.count("DELETE", "/accounts/a/rules/lists/L1/items") != 0 {
		t.Fatal("pruning must not create anything")
	}
}

func TestPrune_IsCappedPerRun(t *testing.T) {
	s := live()
	var items []string
	for i := 0; i < 250; i++ {
		items = append(items, item(fmt.Sprintf("id%03d", i), fmt.Sprintf("203.0.113.%d", i%250), "zoraxy/logtail: x", iso(60)))
	}
	h := build(t, expiryCF(items...), map[string]http.HandlerFunc{}, s)
	h.b.PruneExpired(context.Background(), now)
	dels := h.cf.all("DELETE", "/accounts/a/rules/lists/L1/items")
	total := 0
	for _, d := range dels {
		total += strings.Count(d.Body, `"id"`)
	}
	if total != maxPrunePerRun || len(dels) != 2 {
		t.Fatalf("expected %d ids in 2 batches, got %d ids in %d requests", maxPrunePerRun, total, len(dels))
	}
}

func TestPrune_ZoraxyBansExpireIndependently_AndOnlyOursAreTouched(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	h := build(t, expiryCF(), zxRoutes(defaultRule, `"OK"`), s)
	_ = h.bans.Record("203.0.113.1", []string{"default", "au"}, now.Add(-20*24*time.Hour))
	_ = h.bans.Record("203.0.113.2", []string{"default"}, now.Add(-2*24*time.Hour))
	h.b.PruneExpired(context.Background(), now)

	rem := h.zx.all("POST", "/plugin/api/blacklist/ip/remove")
	if len(rem) != 2 {
		t.Fatalf("expected 2 unbans (203.0.113.1 in 2 rules), got %d", len(rem))
	}
	for _, r := range rem {
		if !strings.Contains(r.Body, "203.0.113.1") {
			t.Errorf("only the expired ban may be removed: %s", r.Body)
		}
	}
	if h.bans.Len() != 1 {
		t.Errorf("the expired record should be gone and the recent one kept, have %d", h.bans.Len())
	}
	if len(h.zx.all("GET", "/plugin/api/blacklist/list")) != 0 {
		t.Error("expiry must not enumerate Zoraxy's whole blacklist")
	}
}

func TestPrune_AFailedUnbanKeepsTheRecordToRetry(t *testing.T) {
	s := live()
	s.zoraxyOn = true
	zx := zxRoutes(defaultRule, `"OK"`)
	zx["POST /plugin/api/blacklist/ip/remove"] = zxOK(`{"error":"boom"}`)
	h := build(t, expiryCF(), zx, s)
	_ = h.bans.Record("203.0.113.1", []string{"default"}, now.Add(-20*24*time.Hour))
	h.b.PruneExpired(context.Background(), now)
	if h.bans.Len() != 1 {
		t.Fatal("the record must be kept so the removal is retried")
	}
}

func TestBanStore_PersistsAndSurvivesCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	s := LoadBanStore(path)
	if err := s.Record("203.0.113.1", []string{"default"}, now); err != nil {
		t.Fatal(err)
	}
	if again := LoadBanStore(path); again.Len() != 1 {
		t.Fatal("bans must persist across a reload")
	}
	// a corrupt file is moved aside, not silently overwritten
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	bad := LoadBanStore(path)
	if bad.Len() != 0 {
		t.Fatal("corrupt store must start empty")
	}
	matches, _ := filepath.Glob(path + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("the corrupt file should be kept aside, found %v", matches)
	}
}

func TestPrune_SaysSoWhenNothingIsDue(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	s := live()
	h := build(t, expiryCF(item("new", "203.0.113.2", "zoraxy/logtail: x", iso(1)), item("manual", "203.0.113.3", "by hand", iso(300))),
		map[string]http.HandlerFunc{}, s)
	h.b.PruneExpired(context.Background(), now)
	if !strings.Contains(buf.String(), "checked 2 Cloudflare list item(s), 1 added by this plugin, none older than 14 days") {
		t.Fatalf("expected a visible 'nothing due' line, got %q", buf.String())
	}
	if h.cf.count("DELETE", "/accounts/a/rules/lists/L1/items") != 0 {
		t.Fatal("nothing due means nothing deleted")
	}
}
