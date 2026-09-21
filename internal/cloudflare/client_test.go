package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---- a fake Cloudflare API that records every request ----

type recorded struct{ Method, Path, Body string }

type fakeCF struct {
	t      *testing.T
	mu     sync.Mutex
	reqs   []recorded
	routes map[string]http.HandlerFunc // key: "METHOD /path"
}

func newFake(t *testing.T, routes map[string]http.HandlerFunc) (*Client, *fakeCF) {
	t.Helper()
	f := &fakeCF{t: t, routes: routes}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, string(body)})
		f.mu.Unlock()
		h, ok := f.routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			fail(500)(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New("acct", "zone", "tok")
	c.Base = srv.URL
	return c, f
}

func (f *fakeCF) writes() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recorded
	for _, r := range f.reqs {
		if r.Method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeCF) find(method, path string) *recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.reqs {
		if f.reqs[i].Method == method && f.reqs[i].Path == path {
			return &f.reqs[i]
		}
	}
	return nil
}

func ok(result string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":` + result + `}`))
	}
}

func fail(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"nope"}],"result":null}`))
	}
}

func drop(w http.ResponseWriter, r *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

const (
	entrypoint = "/zones/zone/rulesets/phases/http_request_firewall_custom/entrypoint"
	rulesPath  = "/zones/zone/rulesets/RS1/rules"
)

// four "operator" rules with fields our own rule struct does not model (action_parameters, logging, a
// disabled rule) - they must never be re-sent.
const operatorRules = `[
 {"id":"A1","description":"Google Cloud Services","expression":"(ip.geoip.asnum eq 15169)","action":"skip","action_parameters":{"ruleset":"current"},"logging":{"enabled":true},"enabled":true},
 {"id":"A2","description":"Block Crawlers","expression":"(cf.client.bot)","action":"block","action_parameters":{"response":{"status_code":403,"content":"no","content_type":"text/plain"}},"enabled":true},
 {"id":"A3","description":"Paused rule","expression":"(http.host eq \"x\")","action":"block","enabled":false},
 {"id":"A4","description":"Allow office","expression":"(ip.src eq 203.0.113.7)","action":"skip","action_parameters":{"ruleset":"current"},"enabled":true}
]`

func rulesetJSON(rules string) string {
	return `{"id":"RS1","phase":"http_request_firewall_custom","rules":` + rules + `}`
}

func writeRules(t *testing.T, body string) []rule {
	t.Helper()
	var v struct {
		Rules []rule `json:"rules"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("bad body %q: %v", body, err)
	}
	return v.Rules
}

// ---- EnsureBlockRule ----

func TestEnsureBlockRule_AddsWithSingleRulePost_NeverResendsOtherRules(t *testing.T) {
	added := `[` + strings.Trim(operatorRules, "[]") + `,{"id":"NEW1","description":"Zoraxy WAF","expression":"(ip.src in $mylist)","action":"managed_challenge","enabled":true}]`
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET " + entrypoint: ok(rulesetJSON(operatorRules)),
		"POST " + rulesPath: ok(rulesetJSON(added)),
	})
	id, err := c.EnsureBlockRule(context.Background(), "mylist", "managed_challenge", "Zoraxy WAF", "")
	if err != nil || id != "NEW1" {
		t.Fatalf("got id=%q err=%v, want NEW1", id, err)
	}
	w := f.writes()
	if len(w) != 1 || w[0].Method != http.MethodPost || w[0].Path != rulesPath {
		t.Fatalf("expected exactly one POST to %s, got %+v", rulesPath, w)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(w[0].Body), &body)
	if body["expression"] != "(ip.src in $mylist)" || body["action"] != "managed_challenge" || body["description"] != "Zoraxy WAF" || body["enabled"] != true {
		t.Errorf("unexpected POST body: %s", w[0].Body)
	}
	for _, other := range []string{"Google Cloud Services", "Block Crawlers", "action_parameters", "Paused rule", "rules"} {
		if strings.Contains(w[0].Body, other) {
			t.Errorf("POST body must contain only our rule, but contains %q: %s", other, w[0].Body)
		}
	}
}

func TestEnsureBlockRule_ReadFailureWritesNothing(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500":  fail(500),
		"403":  fail(403),
		"429":  fail(429),
		"drop": drop,
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			c, f := newFake(t, map[string]http.HandlerFunc{"GET " + entrypoint: h})
			id, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", "")
			if err == nil || id != "" {
				t.Fatalf("expected an error and no id, got id=%q err=%v", id, err)
			}
			if !strings.Contains(err.Error(), "not writing anything") {
				t.Errorf("error should say nothing was written: %v", err)
			}
			if w := f.writes(); len(w) != 0 {
				t.Fatalf("a failed read must not lead to any write, got %+v", w)
			}
		})
	}
}

func TestEnsureBlockRule_FreshZone_CreatesEntrypointWithOnlyOurRule(t *testing.T) {
	created := `{"id":"RS9","phase":"http_request_firewall_custom","rules":[{"id":"N1","description":"Zoraxy WAF","expression":"(ip.src in $mylist)","action":"block"}]}`
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET " + entrypoint:        fail(404),
		"GET /zones/zone/rulesets": ok(`[{"id":"M1","phase":"http_request_firewall_managed"},{"id":"T1","phase":"http_ratelimit"}]`),
		"PUT " + entrypoint:        ok(created),
	})
	id, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", "")
	if err != nil || id != "N1" {
		t.Fatalf("got id=%q err=%v, want N1", id, err)
	}
	w := f.writes()
	if len(w) != 1 || w[0].Method != http.MethodPut {
		t.Fatalf("expected exactly one PUT, got %+v", w)
	}
	if rules := writeRules(t, w[0].Body); len(rules) != 1 || rules[0].Expression != "(ip.src in $mylist)" {
		t.Errorf("first-rule PUT must contain only our rule: %s", w[0].Body)
	}
}

func TestEnsureBlockRule_Spurious404_DoesNotOverwriteExistingRuleset(t *testing.T) {
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET " + entrypoint:        fail(404),
		"GET /zones/zone/rulesets": ok(`[{"id":"RS1","phase":"http_request_firewall_custom","kind":"zone"}]`),
	})
	_, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", "")
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("no write allowed, got %+v", w)
	}
}

func TestEnsureBlockRule_404ButCannotListRulesets_WritesNothing(t *testing.T) {
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET " + entrypoint:        fail(404),
		"GET /zones/zone/rulesets": fail(500),
	})
	if _, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", ""); err == nil {
		t.Fatal("expected an error")
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("no write allowed, got %+v", w)
	}
}

func TestEnsureBlockRule_SameNameForeignRule_IsAConflict_AndUntouched(t *testing.T) {
	rules := `[{"id":"F1","description":"Zoraxy WAF","expression":"(http.host eq \"mine.example\")","action":"skip","action_parameters":{"ruleset":"current"},"enabled":true}]`
	c, f := newFake(t, map[string]http.HandlerFunc{"GET " + entrypoint: ok(rulesetJSON(rules))})
	_, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", "")
	var conflict *RuleConflictError
	if !errors.As(err, &conflict) || conflict.RuleID != "F1" {
		t.Fatalf("expected RuleConflictError for F1, got %v", err)
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("a foreign rule must never be modified, got %+v", w)
	}
}

func TestEnsureBlockRule_ListNamePrefixIsNotAReference(t *testing.T) {
	// $mylist_v2 is a different list from $mylist
	rules := `[{"id":"F1","description":"Zoraxy WAF","expression":"(ip.src in $mylist_v2)","action":"block","enabled":true}]`
	c, f := newFake(t, map[string]http.HandlerFunc{"GET " + entrypoint: ok(rulesetJSON(rules))})
	_, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", "")
	var conflict *RuleConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if len(f.writes()) != 0 {
		t.Fatal("no writes expected")
	}
}

func TestEnsureBlockRule_AdoptsOwnRuleByName_PatchesOnlyIt_KeepsPausedState(t *testing.T) {
	rules := `[{"id":"A1","description":"Other","expression":"(x)","action":"skip","enabled":true},
	           {"id":"OURS","description":"Zoraxy WAF","expression":"(ip.src in $mylist)","action":"block","enabled":false}]`
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET " + entrypoint:                         ok(rulesetJSON(rules)),
		"PATCH /zones/zone/rulesets/RS1/rules/OURS": ok(rulesetJSON(rules)),
	})
	id, err := c.EnsureBlockRule(context.Background(), "mylist", "managed_challenge", "Zoraxy WAF", "")
	if err != nil || id != "OURS" {
		t.Fatalf("got id=%q err=%v", id, err)
	}
	w := f.writes()
	if len(w) != 1 || w[0].Method != http.MethodPatch || w[0].Path != "/zones/zone/rulesets/RS1/rules/OURS" {
		t.Fatalf("expected one PATCH of our rule, got %+v", w)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(w[0].Body), &body)
	if body["action"] != "managed_challenge" || body["enabled"] != false {
		t.Errorf("action must change and a paused rule must stay paused: %s", w[0].Body)
	}
}

func TestEnsureBlockRule_ByStoredID_UpToDate_NoWrites(t *testing.T) {
	rules := `[{"id":"OURS","description":"Zoraxy WAF","expression":"(ip.src in $mylist)","action":"block","enabled":true}]`
	c, f := newFake(t, map[string]http.HandlerFunc{"GET " + entrypoint: ok(rulesetJSON(rules))})
	id, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "Zoraxy WAF", "OURS")
	if err != nil || id != "OURS" || len(f.writes()) != 0 {
		t.Fatalf("id=%q err=%v writes=%+v", id, err, f.writes())
	}
}

func TestEnsureBlockRule_ByStoredID_RenameIsAPatchNotADuplicate(t *testing.T) {
	rules := `[{"id":"OURS","description":"Old name","expression":"(ip.src in $mylist)","action":"block","enabled":true}]`
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET " + entrypoint:                         ok(rulesetJSON(rules)),
		"PATCH /zones/zone/rulesets/RS1/rules/OURS": ok(rulesetJSON(rules)),
	})
	id, err := c.EnsureBlockRule(context.Background(), "mylist", "block", "New name", "OURS")
	if err != nil || id != "OURS" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if w := f.writes(); len(w) != 1 || w[0].Method != http.MethodPatch {
		t.Fatalf("expected a single PATCH, got %+v", w)
	}
}

// ---- lists ----

func TestAddIP_UsesDocumentedPostWithArrayBody(t *testing.T) {
	c, f := newFake(t, map[string]http.HandlerFunc{
		"POST /accounts/acct/rules/lists/L1/items": ok(`{"operation_id":"op1"}`),
	})
	if err := c.AddIP(context.Background(), "L1", "203.0.113.9", "zoraxy/logtail: probe"); err != nil {
		t.Fatal(err)
	}
	w := f.find(http.MethodPost, "/accounts/acct/rules/lists/L1/items")
	if w == nil {
		t.Fatal("no POST recorded")
	}
	var items []map[string]string
	if err := json.Unmarshal([]byte(w.Body), &items); err != nil || len(items) != 1 || items[0]["ip"] != "203.0.113.9" || items[0]["comment"] != "zoraxy/logtail: probe" {
		t.Errorf("body must be a JSON array of {ip,comment}: %s (%v)", w.Body, err)
	}
}

func TestEnsureIPList_ReusesExisting_CreatesWhenMissing(t *testing.T) {
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET /accounts/acct/rules/lists": ok(`[{"id":"L1","name":"mylist","num_items":3}]`),
	})
	if id, err := c.EnsureIPList(context.Background(), "mylist"); err != nil || id != "L1" || len(f.writes()) != 0 {
		t.Fatalf("reuse failed: id=%q err=%v writes=%+v", id, err, f.writes())
	}

	c2, f2 := newFake(t, map[string]http.HandlerFunc{
		"GET /accounts/acct/rules/lists":  ok(`[]`),
		"POST /accounts/acct/rules/lists": ok(`{"id":"L2","name":"mylist"}`),
	})
	if id, err := c2.EnsureIPList(context.Background(), "mylist"); err != nil || id != "L2" {
		t.Fatalf("create failed: id=%q err=%v", id, err)
	}
	if w := f2.writes(); len(w) != 1 || !strings.Contains(w[0].Body, `"kind":"ip"`) {
		t.Errorf("expected one create with kind ip, got %+v", w)
	}
}

// ---- Test Connection ----

func TestTestCapabilities(t *testing.T) {
	verify := "GET /user/tokens/verify"
	lists := "GET /accounts/acct/rules/lists"

	t.Run("conflict is reported", func(t *testing.T) {
		rules := `[{"id":"F1","description":"Zoraxy WAF","expression":"(x)","action":"block"},{"id":"F2","description":"Other","expression":"(y)","action":"block"}]`
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`), lists: ok(`[]`), "GET " + entrypoint: ok(rulesetJSON(rules))})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "")
		if !r.TokenValid || !r.ListsAccess || !r.WAFAccess || !r.RuleNameConflict || r.RuleCount != 2 {
			t.Errorf("unexpected report: %+v", r)
		}
	})
	t.Run("our own rule is not a conflict", func(t *testing.T) {
		rules := `[{"id":"OURS","description":"Zoraxy WAF","expression":"(ip.src in $mylist)","action":"block"}]`
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`), lists: ok(`[{"id":"L1","name":"mylist","num_items":7}]`), "GET " + entrypoint: ok(rulesetJSON(rules))})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "OURS")
		if r.RuleNameConflict || !r.ListExists || r.ListItemCount != 7 {
			t.Errorf("unexpected report: %+v", r)
		}
	})
	t.Run("404 entrypoint means a fresh zone, still access", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`), lists: ok(`[]`), "GET " + entrypoint: fail(404)})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "")
		if !r.WAFAccess || r.RuleNameConflict || r.RuleCount != 0 {
			t.Errorf("unexpected report: %+v", r)
		}
	})
	t.Run("403 entrypoint means the token lacks WAF access", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`), lists: ok(`[]`), "GET " + entrypoint: fail(403)})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "")
		if r.WAFAccess || !strings.Contains(r.WAFError, "HTTP 403") {
			t.Errorf("unexpected report: %+v", r)
		}
	})
}

func TestReferencesList(t *testing.T) {
	cases := []struct {
		expr, list string
		want       bool
	}{
		{"(ip.src in $mylist)", "mylist", true},
		{"ip.src in $mylist and http.host eq \"a\"", "mylist", true},
		{"(ip.src in $mylist_v2)", "mylist", false},
		{"(ip.src in $mylistx)", "mylist", false},
		{"(ip.src in $other)", "mylist", false},
		{"(x)", "mylist", false},
		{"(ip.src in $mylist)", "", false},
	}
	for _, c := range cases {
		if got := referencesList(c.expr, c.list); got != c.want {
			t.Errorf("referencesList(%q, %q) = %v, want %v", c.expr, c.list, got, c.want)
		}
	}
}

// ---- list quota, list overview ----

func failCode(status, code int, msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":` + itoa(code) + `,"message":"` + msg + `"}],"result":null}`))
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestEnsureIPList_QuotaReached_GivesAFriendlyError(t *testing.T) {
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET /accounts/acct/rules/lists":  ok(`[{"id":"L1","name":"myip","kind":"ip","num_items":1,"num_referencing_filters":2}]`),
		"POST /accounts/acct/rules/lists": failCode(400, 10019, "This account is at the maximum number of lists"),
	})
	_, err := c.EnsureIPList(context.Background(), "mylist")
	var quota *ListQuotaError
	if !errors.As(err, &quota) {
		t.Fatalf("expected ListQuotaError, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{`"mylist"`, "10019", "myip (ip, 1 item(s), used by 2 rule(s))", "ANY zone", "never an allow list"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message should mention %q: %s", want, msg)
		}
	}
	if w := f.writes(); len(w) != 1 || w[0].Method != http.MethodPost {
		t.Errorf("only the single refused create is expected, got %+v", w)
	}
}

func TestEnsureIPList_OtherCreateErrorsStayGeneric(t *testing.T) {
	c, _ := newFake(t, map[string]http.HandlerFunc{
		"GET /accounts/acct/rules/lists":  ok(`[]`),
		"POST /accounts/acct/rules/lists": failCode(400, 10001, "something else"),
	})
	_, err := c.EnsureIPList(context.Background(), "mylist")
	var quota *ListQuotaError
	if err == nil || errors.As(err, &quota) {
		t.Fatalf("expected a generic error, got %v", err)
	}
}

func TestEnsureIPList_NonIPListWithThatNameIsRefused(t *testing.T) {
	c, f := newFake(t, map[string]http.HandlerFunc{
		"GET /accounts/acct/rules/lists": ok(`[{"id":"H1","name":"mylist","kind":"hostname","num_items":3}]`),
	})
	id, err := c.EnsureIPList(context.Background(), "mylist")
	if err == nil || id != "" || !strings.Contains(err.Error(), "not an IP list") {
		t.Fatalf("expected a kind error, got id=%q err=%v", id, err)
	}
	if len(f.writes()) != 0 {
		t.Fatal("no writes expected")
	}
}

func TestTestCapabilities_ListOverview(t *testing.T) {
	verify := "GET /user/tokens/verify"
	listsRoute := "GET /accounts/acct/rules/lists"
	ours := `{"id":"OURS","description":"Zoraxy WAF","expression":"(ip.src in $mylist)","action":"block","enabled":true}`
	allow := `{"id":"AL","description":"Allow me","expression":"(ip.src in $myip)","action":"skip","enabled":true}`

	t.Run("account lists are summarised; our list missing", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`),
			listsRoute:          ok(`[{"id":"L1","name":"myip","kind":"ip","num_items":1,"num_referencing_filters":1}]`),
			"GET " + entrypoint: ok(rulesetJSON(`[` + allow + `]`))})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "")
		if r.ListCount != 1 || len(r.Lists) != 1 || r.Lists[0].Name != "myip" || r.Lists[0].Kind != "ip" || r.Lists[0].ReferencedBy != 1 {
			t.Errorf("unexpected overview: %+v", r)
		}
		if r.ListExists || r.ListUsedByOtherRules {
			t.Errorf("our list doesn't exist yet: %+v", r)
		}
	})
	t.Run("our own list used only by our own rule is fine", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`),
			listsRoute:          ok(`[{"id":"L2","name":"mylist","kind":"ip","num_items":7,"num_referencing_filters":1}]`),
			"GET " + entrypoint: ok(rulesetJSON(`[` + ours + `]`))})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "OURS")
		if !r.ListExists || r.ListKind != "ip" || r.ListReferencedBy != 1 || r.ListUsedByOtherRules {
			t.Errorf("unexpected: %+v", r)
		}
	})
	t.Run("pointing at someone else's allow list is flagged", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`),
			listsRoute:          ok(`[{"id":"L1","name":"myip","kind":"ip","num_items":1,"num_referencing_filters":1}]`),
			"GET " + entrypoint: ok(rulesetJSON(`[` + allow + `]`))})
		r := c.TestCapabilities(context.Background(), "myip", "Zoraxy WAF", "")
		if !r.ListExists || !r.ListUsedByOtherRules {
			t.Errorf("a list used by a rule that is not ours must be flagged: %+v", r)
		}
	})
	t.Run("our list also used by another zone's rule is flagged", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`),
			listsRoute:          ok(`[{"id":"L2","name":"mylist","kind":"ip","num_items":7,"num_referencing_filters":2}]`),
			"GET " + entrypoint: ok(rulesetJSON(`[` + ours + `]`))})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "OURS")
		if !r.ListUsedByOtherRules {
			t.Errorf("referenced by 2 but only 1 is ours: %+v", r)
		}
	})
	t.Run("fresh zone (404 entrypoint) with a list that something references", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`),
			listsRoute:          ok(`[{"id":"L1","name":"myip","kind":"ip","num_items":1,"num_referencing_filters":1}]`),
			"GET " + entrypoint: fail(404)})
		r := c.TestCapabilities(context.Background(), "myip", "Zoraxy WAF", "")
		if !r.ListUsedByOtherRules {
			t.Errorf("unexpected: %+v", r)
		}
	})
	t.Run("wrong kind is reported", func(t *testing.T) {
		c, _ := newFake(t, map[string]http.HandlerFunc{verify: ok(`{}`),
			listsRoute:          ok(`[{"id":"H1","name":"mylist","kind":"hostname","num_items":3}]`),
			"GET " + entrypoint: fail(404)})
		r := c.TestCapabilities(context.Background(), "mylist", "Zoraxy WAF", "")
		if r.ListKind != "hostname" {
			t.Errorf("unexpected: %+v", r)
		}
	})
}
