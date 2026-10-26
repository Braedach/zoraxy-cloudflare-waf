// Command fakecf is a small fake of the parts of the Cloudflare API this plugin uses, for the release-candidate test bench
// (a throwaway Zoraxy on a test host). It models several ACCOUNTS, each with its own token, zones, list quota and rule slots, so
// multi-account behaviour can be exercised without real accounts, and it can be told to fail an account on demand. It is
// development tooling: it is not part of the plugin and is never shipped.
//
//	fakecf -listen 127.0.0.1:9100 -config accounts.json
//
// accounts.json: {"accounts":{"<account id>":{"token":"...","zones":["<zone id>"],"list_quota":1,"rule_slots":5,"lists":["existing_list"]}}}
// Control: POST /_ctl {"account":"<id>","fail":"403|500|none"}   GET /_state
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type item struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Comment  string `json:"comment"`
	Created  string `json:"created_on"`
	Modified string `json:"modified_on"`
}

type list struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Items []item `json:"-"`
}

type rule struct {
	ID          string `json:"id"`
	Expression  string `json:"expression"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

type ruleset struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Rules []rule `json:"rules"`
}

type account struct {
	Token     string   `json:"token"`
	Zones     []string `json:"zones"`
	ListQuota int      `json:"list_quota"`
	RuleSlots int      `json:"rule_slots"`
	Lists     []string `json:"lists"` // lists that already exist (so a Free account can be "full")

	fail  string
	lists []*list
}

type server struct {
	mu       sync.Mutex
	accounts map[string]*account
	zones    map[string]string   // zone -> account
	rulesets map[string]*ruleset // zone -> custom-phase ruleset (absent = none yet)
	seq      int
}

func (s *server) id(p string) string { s.seq++; return fmt.Sprintf("%s%04d", p, s.seq) }

func reply(w http.ResponseWriter, status int, result any, errs ...[2]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]any{"success": status < 300, "errors": []any{}, "result": result}
	if status >= 300 {
		var es []any
		for _, e := range errs {
			es = append(es, map[string]any{"code": e[0], "message": e[1]})
		}
		body["errors"], body["result"] = es, nil
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (s *server) accountFor(r *http.Request, id string) (*account, int) {
	a := s.accounts[id]
	if a == nil {
		return nil, http.StatusNotFound
	}
	if r.Header.Get("Authorization") != "Bearer "+a.Token {
		return nil, http.StatusForbidden
	}
	switch a.fail {
	case "403":
		return nil, http.StatusForbidden
	case "500":
		return nil, http.StatusInternalServerError
	}
	return a, 0
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	log.Printf("%s %s %s", r.Method, r.URL.RequestURI(), strings.TrimSpace(string(body)))
	p := strings.TrimPrefix(r.URL.Path, "/client/v4")
	seg := strings.Split(strings.Trim(p, "/"), "/")

	switch {
	case p == "/user/tokens/verify":
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		for _, a := range s.accounts {
			if a.Token == tok && a.fail == "" {
				reply(w, 200, map[string]string{"status": "active"})
				return
			}
		}
		reply(w, 401, nil, [2]any{1000, "Invalid API Token"})
	case len(seg) >= 4 && seg[0] == "accounts" && seg[2] == "rules" && seg[3] == "lists":
		s.lists(w, r, body, seg)
	case len(seg) >= 2 && seg[0] == "zones":
		s.zone(w, r, body, seg)
	default:
		reply(w, 404, nil, [2]any{7003, "no route for " + p})
	}
}

func (s *server) lists(w http.ResponseWriter, r *http.Request, body []byte, seg []string) {
	a, bad := s.accountFor(r, seg[1])
	if bad != 0 {
		reply(w, bad, nil, [2]any{9109, "Unauthorized to access requested resource"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	refs := func(name string) int {
		n := 0
		for z, acct := range s.zones {
			if acct != seg[1] || s.rulesets[z] == nil {
				continue
			}
			for _, rl := range s.rulesets[z].Rules {
				if strings.Contains(rl.Expression, "$"+name) {
					n++
				}
			}
		}
		return n
	}
	switch {
	case len(seg) == 4 && r.Method == http.MethodGet:
		var out []map[string]any
		for _, l := range a.lists {
			out = append(out, map[string]any{"id": l.ID, "name": l.Name, "kind": l.Kind, "num_items": len(l.Items), "num_referencing_filters": refs(l.Name)})
		}
		reply(w, 200, out)
	case len(seg) == 4 && r.Method == http.MethodPost:
		var req struct{ Name, Kind string }
		_ = json.Unmarshal(body, &req)
		if a.ListQuota > 0 && len(a.lists) >= a.ListQuota {
			reply(w, 400, nil, [2]any{10019, "This account is at the maximum number of lists."})
			return
		}
		l := &list{ID: s.id("L"), Name: req.Name, Kind: "ip"}
		a.lists = append(a.lists, l)
		reply(w, 200, map[string]any{"id": l.ID, "name": l.Name, "kind": l.Kind})
	default:
		var l *list
		for _, c := range a.lists {
			if len(seg) >= 5 && c.ID == seg[4] {
				l = c
			}
		}
		if l == nil {
			reply(w, 404, nil, [2]any{10002, "list not found"})
			return
		}
		switch {
		case len(seg) == 5 && r.Method == http.MethodGet:
			reply(w, 200, map[string]any{"id": l.ID, "name": l.Name, "kind": l.Kind, "num_items": len(l.Items), "num_referencing_filters": refs(l.Name)})
		case len(seg) == 6 && seg[5] == "items" && r.Method == http.MethodPost:
			var add []struct{ IP, Comment string }
			_ = json.Unmarshal(body, &add)
			for _, x := range add {
				found := false
				for i := range l.Items {
					if l.Items[i].IP == x.IP {
						l.Items[i].Modified, l.Items[i].Comment, found = now, x.Comment, true
					}
				}
				if !found {
					l.Items = append(l.Items, item{ID: s.id("I"), IP: x.IP, Comment: x.Comment, Created: now, Modified: now})
				}
			}
			reply(w, 200, map[string]string{"operation_id": s.id("op")})
		case len(seg) == 6 && seg[5] == "items" && r.Method == http.MethodGet:
			reply(w, 200, l.Items)
		case len(seg) == 6 && seg[5] == "items" && r.Method == http.MethodDelete:
			var del struct{ Items []struct{ ID string } }
			_ = json.Unmarshal(body, &del)
			drop := map[string]bool{}
			for _, d := range del.Items {
				drop[d.ID] = true
			}
			var keep []item
			for _, it := range l.Items {
				if !drop[it.ID] {
					keep = append(keep, it)
				}
			}
			l.Items = keep
			reply(w, 200, map[string]string{"operation_id": s.id("op")})
		default:
			reply(w, 404, nil, [2]any{7003, "no route"})
		}
	}
}

func (s *server) zone(w http.ResponseWriter, r *http.Request, body []byte, seg []string) {
	acct := s.zones[seg[1]]
	a, bad := s.accountFor(r, acct)
	if acct == "" || bad != 0 {
		status := bad
		if acct == "" {
			status = http.StatusForbidden
		}
		reply(w, status, nil, [2]any{9109, "Unauthorized to access requested resource"})
		return
	}
	z := seg[1]
	rs := s.rulesets[z]
	const entry = "phases/http_request_firewall_custom/entrypoint"
	switch {
	case len(seg) == 5 && strings.Join(seg[3:], "/") == entry && r.Method == http.MethodGet:
		if rs == nil {
			reply(w, 404, nil, [2]any{10003, "no ruleset"})
			return
		}
		reply(w, 200, rs)
	case len(seg) == 3 && seg[2] == "rulesets" && r.Method == http.MethodGet:
		var out []any
		if rs != nil {
			out = append(out, map[string]string{"id": rs.ID, "phase": rs.Phase})
		}
		reply(w, 200, out)
	case len(seg) == 5 && strings.Join(seg[3:], "/") == entry && r.Method == http.MethodPut:
		var req struct{ Rules []rule }
		_ = json.Unmarshal(body, &req)
		rs = &ruleset{ID: s.id("RS"), Phase: "http_request_firewall_custom"}
		for _, x := range req.Rules {
			x.ID = s.id("R")
			rs.Rules = append(rs.Rules, x)
		}
		s.rulesets[z] = rs
		reply(w, 200, rs)
	case len(seg) == 5 && seg[2] == "rulesets" && seg[4] == "rules" && r.Method == http.MethodPost && rs != nil && rs.ID == seg[3]:
		if a.RuleSlots > 0 && len(rs.Rules) >= a.RuleSlots {
			reply(w, 400, nil, [2]any{20120, "exceeded the maximum number of rules for this plan"})
			return
		}
		var x rule
		_ = json.Unmarshal(body, &x)
		x.ID = s.id("R")
		rs.Rules = append(rs.Rules, x)
		reply(w, 200, rs)
	case len(seg) == 6 && seg[2] == "rulesets" && seg[4] == "rules" && r.Method == http.MethodPatch && rs != nil:
		var x rule
		_ = json.Unmarshal(body, &x)
		for i := range rs.Rules {
			if rs.Rules[i].ID == seg[5] {
				x.ID = rs.Rules[i].ID
				rs.Rules[i] = x
			}
		}
		reply(w, 200, rs)
	default:
		reply(w, 404, nil, [2]any{7003, "no route"})
	}
}

func (s *server) state(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{}
	for id, a := range s.accounts {
		ls := map[string]any{}
		for _, l := range a.lists {
			var ips []string
			for _, it := range l.Items {
				ips = append(ips, it.IP)
			}
			ls[l.Name] = map[string]any{"items": ips}
		}
		zs := map[string]any{}
		for _, z := range a.Zones {
			if rs := s.rulesets[z]; rs != nil {
				zs[z] = rs.Rules
			} else {
				zs[z] = nil
			}
		}
		out[id] = map[string]any{"lists": ls, "zones": zs, "fail": a.fail}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) control(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req struct {
		Account, Fail, SeedRule, Zone, Expression, Description, AgeList, AgeIP string
		AgeDays                                                                int
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)
	a := s.accounts[req.Account]
	if a == nil {
		http.Error(w, "unknown account", 400)
		return
	}
	switch {
	case req.SeedRule != "": // put someone else's rule in a zone (to test conflicts)
		rs := s.rulesets[req.Zone]
		if rs == nil {
			rs = &ruleset{ID: s.id("RS"), Phase: "http_request_firewall_custom"}
			s.rulesets[req.Zone] = rs
		}
		rs.Rules = append(rs.Rules, rule{ID: s.id("R"), Expression: req.Expression, Action: "block", Description: req.Description})
	case req.AgeList != "": // make a list item old (to test expiry)
		for _, l := range a.lists {
			if l.Name == req.AgeList {
				for i := range l.Items {
					if l.Items[i].IP == req.AgeIP {
						old := time.Now().UTC().Add(-time.Duration(req.AgeDays) * 24 * time.Hour).Format(time.RFC3339)
						l.Items[i].Created, l.Items[i].Modified = old, old
					}
				}
			}
		}
	default:
		a.fail = req.Fail
		if a.fail == "none" {
			a.fail = ""
		}
	}
	fmt.Fprintln(w, "ok")
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to listen on")
	cfg := flag.String("config", "accounts.json", "accounts file")
	flag.Parse()
	raw, err := os.ReadFile(*cfg)
	if err != nil {
		log.Fatal(err)
	}
	var f struct{ Accounts map[string]*account }
	if err := json.Unmarshal(raw, &f); err != nil {
		log.Fatal(err)
	}
	s := &server{accounts: f.Accounts, zones: map[string]string{}, rulesets: map[string]*ruleset{}}
	for id, a := range s.accounts {
		for _, z := range a.Zones {
			s.zones[z] = id
		}
		for _, name := range a.Lists {
			a.lists = append(a.lists, &list{ID: s.id("L"), Name: name, Kind: "ip"})
		}
	}
	http.HandleFunc("/client/v4/", s.handle)
	http.HandleFunc("/_state", s.state)
	http.HandleFunc("/_ctl", s.control)
	log.Printf("fakecf listening on %s with %d account(s)", *listen, len(s.accounts))
	log.Fatal(http.ListenAndServe(*listen, nil))
}
