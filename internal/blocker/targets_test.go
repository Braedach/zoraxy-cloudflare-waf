package blocker

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/ipfilter"
)

// ---- several Cloudflare targets (accounts and zones) ----

func entry(zone string) string {
	return "/zones/" + zone + "/rulesets/phases/http_request_firewall_custom/entrypoint"
}

// acctRoutes is a healthy Cloudflare account "acct" holding one list ("mylist") and, for each zone, a ruleset that already
// contains the plugin's rule (ID "OURS").
func acctRoutes(acct string, zones ...string) map[string]http.HandlerFunc {
	r := map[string]http.HandlerFunc{
		"GET /accounts/" + acct + "/rules/lists":           cfOK(`[{"id":"L1","name":"mylist","kind":"ip","num_items":3}]`),
		"GET /accounts/" + acct + "/rules/lists/L1":        cfOK(`{"id":"L1","name":"mylist","num_items":3}`),
		"POST /accounts/" + acct + "/rules/lists/L1/items": cfOK(`{"operation_id":"op"}`),
	}
	for _, z := range zones {
		r["GET "+entry(z)] = cfOK(`{"id":"RS-` + z + `","phase":"http_request_firewall_custom","rules":[` + ourRule + `]}`)
	}
	return r
}

type tspec struct {
	label, account, list string
	zones                []string
	routes               map[string]http.HandlerFunc
}

type multi struct {
	b     *Blocker
	fakes map[string]*fake // by account
	mu    sync.Mutex
	rules map[string]string // "label/zone" -> rule ID persisted by SetRuleID
}

func buildMulti(t *testing.T, s *settings, specs ...tspec) *multi {
	t.Helper()
	m := &multi{fakes: map[string]*fake{}, rules: map[string]string{}}
	var targets []Target
	for _, sp := range specs {
		sp := sp
		f, srv := newFake(t, sp.routes)
		m.fakes[sp.account] = f
		list := sp.list
		if list == "" {
			list = "mylist"
		}
		targets = append(targets, Target{
			Label: sp.label, AccountKey: sp.account, IPListName: list, BlockAction: "block", RuleName: "WAF", MaxListItems: 10000,
			Zones: sp.zones,
			NewClient: func(zone string) (*cloudflare.Client, bool) {
				c := cloudflare.New(sp.account, zone, "tok")
				c.Base = srv.URL
				return c, true
			},
			GetRuleID: func(zone string) string {
				m.mu.Lock()
				defer m.mu.Unlock()
				if id, ok := m.rules[sp.label+"/"+zone]; ok {
					return id
				}
				return "OURS"
			},
			SetRuleID: func(zone, id string) {
				m.mu.Lock()
				m.rules[sp.label+"/"+zone] = id
				m.mu.Unlock()
			},
		})
	}
	deps := Deps{
		GetEnabled: func() bool { return s.enabled }, GetDryRun: func() bool { return s.dryRun },
		GetTTL:        func() time.Duration { return time.Hour },
		GetTargets:    func() []Target { return targets },
		GetExpiryDays: func() int { return s.expiryDays },
		Bans:          LoadBanStore(filepath.Join(t.TempDir(), "bans.json")),
	}
	m.b = New(deps, ipfilter.NewChecker())
	return m
}

func (m *multi) submit(ip string) Action {
	m.b.Submit(context.Background(), Candidate{IP: ip, Reason: "sensitive-path probe (vcs): /.git/config", Source: "logtail"})
	h := m.b.History()
	return h[len(h)-1]
}

func TestMulti_EveryAccountAndZoneGetsTheBlock(t *testing.T) {
	m := buildMulti(t, live(),
		tspec{label: "primary", account: "a", zones: []string{"z1", "z2"}, routes: acctRoutes("a", "z1", "z2")},
		tspec{label: "Account 2", account: "b", zones: []string{"z3"}, routes: acctRoutes("b", "z3")})
	a := m.submit("203.0.113.9")
	if a.Result != "blocked" || a.Detail != "primary: ok; Account 2: ok" {
		t.Fatalf("got %+v", a)
	}
	for acct, f := range m.fakes {
		if n := f.count("POST", "/accounts/"+acct+"/rules/lists/L1/items"); n != 1 {
			t.Errorf("account %s: expected exactly one list add, got %d", acct, n)
		}
	}
	// The rule is ensured once per zone, never twice and never in a zone that is not configured.
	for _, z := range []string{"z1", "z2"} {
		if n := m.fakes["a"].count("GET", entry(z)); n != 1 {
			t.Errorf("zone %s: expected one rule read, got %d", z, n)
		}
	}
	if n := m.fakes["b"].count("GET", entry("z3")); n != 1 {
		t.Errorf("zone z3: expected one rule read, got %d", n)
	}
}

func TestMulti_OneAccountFailing_NeverStopsTheOthers(t *testing.T) {
	bad := acctRoutes("b", "z3")
	bad["GET /accounts/b/rules/lists"] = cfFail(403, 10000)
	m := buildMulti(t, live(),
		tspec{label: "primary", account: "a", zones: []string{"z1"}, routes: acctRoutes("a", "z1")},
		tspec{label: "Account 2", account: "b", zones: []string{"z3"}, routes: bad})
	a := m.submit("203.0.113.9")
	if a.Result != "partial" || !strings.Contains(a.Detail, "primary: ok") || !strings.Contains(a.Detail, "Account 2: ") || strings.Contains(a.Detail, "Account 2: ok") {
		t.Fatalf("expected a partial result naming the failing account: %+v", a)
	}
	if n := m.fakes["a"].count("POST", "/accounts/a/rules/lists/L1/items"); n != 1 {
		t.Errorf("the healthy account must still get the block, got %d adds", n)
	}
	if n := m.fakes["b"].count("POST", "/accounts/b/rules/lists/L1/items"); n != 0 {
		t.Errorf("the failing account must not be written to, got %d adds", n)
	}
}

func TestMulti_EveryAccountFailing_IsAnError(t *testing.T) {
	ba, bb := acctRoutes("a", "z1"), acctRoutes("b", "z3")
	ba["GET /accounts/a/rules/lists"] = cfFail(500, 1)
	bb["GET /accounts/b/rules/lists"] = cfFail(500, 1)
	m := buildMulti(t, live(),
		tspec{label: "primary", account: "a", zones: []string{"z1"}, routes: ba},
		tspec{label: "Account 2", account: "b", zones: []string{"z3"}, routes: bb})
	if a := m.submit("203.0.113.9"); a.Result != "error" {
		t.Fatalf("got %+v", a)
	}
}

func TestMulti_AZoneWhereSomeoneElsesRuleHasOurName_IsPartialButTheOtherZonesAreProtected(t *testing.T) {
	r := acctRoutes("a", "z1")
	// zone z2 has a rule with our name that does not reference our list: it is someone else's and must be left alone
	r["GET "+entry("z2")] = cfOK(`{"id":"RS-z2","phase":"http_request_firewall_custom","rules":[{"id":"THEIRS","description":"WAF","expression":"(http.host eq \"x.example\")","action":"block","enabled":true}]}`)
	m := buildMulti(t, live(), tspec{label: "", account: "a", zones: []string{"z1", "z2"}, routes: r})
	// give z2 no stored rule ID so the name check applies
	m.rules["/z2"] = ""
	a := m.submit("203.0.113.9")
	if a.Result != "partial" || !strings.Contains(a.Detail, "zone z2") {
		t.Fatalf("expected partial naming zone z2: %+v", a)
	}
	if n := m.fakes["a"].count("POST", "/accounts/a/rules/lists/L1/items"); n != 1 {
		t.Errorf("zone z1 is protected by the list, so the address must be added, got %d adds", n)
	}
	for _, rq := range m.fakes["a"].reqs {
		if rq.Method == "PUT" || rq.Method == "PATCH" || rq.Method == "DELETE" {
			t.Errorf("someone else's rule must never be written to: %s %s", rq.Method, rq.Path)
		}
	}
}

func TestMulti_EveryZoneConflicting_AddsNothingAndIsAnError(t *testing.T) {
	r := acctRoutes("a")
	for _, z := range []string{"z1", "z2"} {
		r["GET "+entry(z)] = cfOK(`{"id":"RS-` + z + `","phase":"http_request_firewall_custom","rules":[{"id":"THEIRS","description":"WAF","expression":"(http.host eq \"x.example\")","action":"block","enabled":true}]}`)
	}
	m := buildMulti(t, live(), tspec{label: "", account: "a", zones: []string{"z1", "z2"}, routes: r})
	m.rules["/z1"], m.rules["/z2"] = "", ""
	a := m.submit("203.0.113.9")
	if a.Result != "error" {
		t.Fatalf("got %+v", a)
	}
	if n := m.fakes["a"].count("POST", "/accounts/a/rules/lists/L1/items"); n != 0 {
		t.Errorf("a list nothing references must not be filled, got %d adds", n)
	}
}

func TestMulti_AMissingRuleIsCreatedInThatZoneAndItsIDIsRemembered(t *testing.T) {
	r := acctRoutes("a", "z1")
	r["GET "+entry("z2")] = cfOK(`{"id":"RS-z2","phase":"http_request_firewall_custom","rules":[]}`)
	r["POST /zones/z2/rulesets/RS-z2/rules"] = cfOK(`{"id":"RS-z2","rules":[{"id":"NEW2","description":"WAF","expression":"(ip.src in $mylist)","action":"block","enabled":true}]}`)
	m := buildMulti(t, live(), tspec{label: "Account 2", account: "a", zones: []string{"z1", "z2"}, routes: r})
	m.rules["Account 2/z2"] = "" // nothing stored yet for z2
	if a := m.submit("203.0.113.9"); a.Result != "blocked" {
		t.Fatalf("got %+v", a)
	}
	if got := m.rules["Account 2/z2"]; got != "NEW2" {
		t.Errorf("the new rule's ID must be remembered for its own zone, got %q", got)
	}
	if got := m.rules["Account 2/z1"]; got != "" {
		t.Errorf("z1's stored ID must be untouched, got %q", got)
	}
}

func TestMulti_DryRunNamesEveryListAndTouchesNothing(t *testing.T) {
	s := live()
	s.dryRun = true
	m := buildMulti(t, s,
		tspec{label: "primary", account: "a", zones: []string{"z1"}, routes: map[string]http.HandlerFunc{}},
		tspec{label: "Account 2", account: "b", zones: []string{"z3"}, list: "otherlist", routes: map[string]http.HandlerFunc{}})
	a := m.submit("203.0.113.9")
	if a.Result != "dry-run" || !strings.Contains(a.Detail, "primary:mylist") || !strings.Contains(a.Detail, "Account 2:otherlist") {
		t.Fatalf("got %+v", a)
	}
	for acct, f := range m.fakes {
		if f.total() != 0 {
			t.Errorf("dry run must not call Cloudflare (account %s: %d requests)", acct, f.total())
		}
	}
}

func TestMulti_ATargetWithoutCredentialsIsSimplySkipped(t *testing.T) {
	var targets []Target
	s := live()
	f, srv := newFake(t, acctRoutes("a", "z1"))
	targets = append(targets,
		Target{Label: "primary", AccountKey: "a", IPListName: "mylist", BlockAction: "block", RuleName: "WAF", MaxListItems: 10000, Zones: []string{"z1"},
			NewClient: func(z string) (*cloudflare.Client, bool) {
				c := cloudflare.New("a", z, "t")
				c.Base = srv.URL
				return c, true
			},
			GetRuleID: func(string) string { return "OURS" }, SetRuleID: func(string, string) {}},
		Target{Label: "Account 2", AccountKey: "b", IPListName: "mylist", BlockAction: "block", RuleName: "WAF", Zones: []string{"z3"},
			NewClient: func(string) (*cloudflare.Client, bool) { return nil, false },
			GetRuleID: func(string) string { return "" }, SetRuleID: func(string, string) {}})
	b := New(Deps{GetEnabled: func() bool { return s.enabled }, GetDryRun: func() bool { return false }, GetTTL: func() time.Duration { return time.Hour },
		GetTargets: func() []Target { return targets }}, ipfilter.NewChecker())
	b.Submit(context.Background(), Candidate{IP: "203.0.113.9", Reason: "x", Source: "logtail"})
	h := b.History()
	if a := h[len(h)-1]; a.Result != "blocked" {
		t.Fatalf("an unconfigured extra account must not turn a good block into a failure: %+v", a)
	}
	if f.count("POST", "/accounts/a/rules/lists/L1/items") != 1 {
		t.Error("the configured account must still be blocked")
	}
}

func TestMulti_OneAccountsListFull_OthersStillBlock(t *testing.T) {
	full := acctRoutes("b", "z3")
	full["GET /accounts/b/rules/lists/L1"] = cfOK(`{"id":"L1","name":"mylist","num_items":10000}`)
	m := buildMulti(t, live(),
		tspec{label: "primary", account: "a", zones: []string{"z1"}, routes: acctRoutes("a", "z1")},
		tspec{label: "Account 2", account: "b", zones: []string{"z3"}, routes: full})
	a := m.submit("203.0.113.9")
	if a.Result != "partial" || !strings.Contains(a.Detail, "10000/10000") {
		t.Fatalf("got %+v", a)
	}
	if m.fakes["b"].count("POST", "/accounts/b/rules/lists/L1/items") != 0 {
		t.Error("a full list must not be added to")
	}
}

// ---- expiry across several lists ----

func TestMulti_PruneVisitsEachDistinctListOnce(t *testing.T) {
	old := item("old", "203.0.113.1", "zoraxy/logtail: probe", iso(20))
	routesFor := func(acct string) map[string]http.HandlerFunc {
		return map[string]http.HandlerFunc{
			"GET /accounts/" + acct + "/rules/lists":             cfOK(`[{"id":"L1","name":"mylist","kind":"ip"}]`),
			"GET /accounts/" + acct + "/rules/lists/L1/items":    cfOK("[" + old + "]"),
			"DELETE /accounts/" + acct + "/rules/lists/L1/items": cfOK(`{"operation_id":"op"}`),
		}
	}
	// two targets in account "a" sharing one list, and one in account "b"
	m := buildMulti(t, live(),
		tspec{label: "primary", account: "a", zones: []string{"z1"}, routes: routesFor("a")},
		tspec{label: "Account 2", account: "a", zones: []string{"z2"}, routes: routesFor("a")},
		tspec{label: "Account 3", account: "b", zones: []string{"z3"}, routes: routesFor("b")})
	m.b.PruneExpired(context.Background(), now)
	// fakes is keyed by account, so m.fakes["a"] is the server of the SECOND target for account a: it shares the first target's list,
	// so it must not be touched at all (the list was already pruned through the first target).
	if n := m.fakes["a"].total(); n != 0 {
		t.Errorf("a list shared by two targets must be pruned once, but the second target's server saw %d requests", n)
	}
	h := m.b.History()
	if len(h) != 1 || h[0].Result != "expired" || !strings.Contains(h[0].Detail, "203.0.113.1") {
		t.Fatalf("expected one expired action listing the address once: %+v", h)
	}
	if n := m.fakes["b"].count("DELETE", "/accounts/b/rules/lists/L1/items"); n != 1 {
		t.Errorf("account b's list must be pruned once, got %d", n)
	}
}

func TestMulti_PruneOneFailingAccountDeletesNothingThereButOthersAreStillPruned(t *testing.T) {
	old := item("old", "203.0.113.1", "zoraxy/logtail: probe", iso(20))
	good := map[string]http.HandlerFunc{
		"GET /accounts/a/rules/lists":             cfOK(`[{"id":"L1","name":"mylist","kind":"ip"}]`),
		"GET /accounts/a/rules/lists/L1/items":    cfOK("[" + old + "]"),
		"DELETE /accounts/a/rules/lists/L1/items": cfOK(`{"operation_id":"op"}`),
	}
	bad := map[string]http.HandlerFunc{"GET /accounts/b/rules/lists": cfFail(500, 1)}
	m := buildMulti(t, live(),
		tspec{label: "primary", account: "a", zones: []string{"z1"}, routes: good},
		tspec{label: "Account 2", account: "b", zones: []string{"z3"}, routes: bad})
	m.b.PruneExpired(context.Background(), now)
	if n := m.fakes["a"].count("DELETE", "/accounts/a/rules/lists/L1/items"); n != 1 {
		t.Errorf("the healthy account must still be pruned, got %d deletes", n)
	}
	if n := m.fakes["b"].count("DELETE", "/accounts/b/rules/lists/L1/items"); n != 0 {
		t.Errorf("a failing read must delete nothing, got %d", n)
	}
}

// With no GetTargets the plugin is the single-account plugin it always was.
func TestSingleAccount_WithoutGetTargets_UsesTheLegacyDependencies(t *testing.T) {
	h := build(t, happyCF(), zxRoutes(defaultRule, `"OK"`), live())
	if ts := h.b.targets(); len(ts) != 1 || ts[0].Label != "" || len(ts[0].Zones) != 1 {
		t.Fatalf("expected the one legacy target, got %+v", ts)
	}
}
