package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	acctA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	acctB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	acctC = "cccccccccccccccccccccccccccccccc"
	zone1 = "11111111111111111111111111111111"
	zone2 = "22222222222222222222222222222222"
	zone3 = "33333333333333333333333333333333"
	zone4 = "44444444444444444444444444444444"
)

func tmpStore(t *testing.T, content string) *configStore {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cloudflarewaf.json")
	if content != "" {
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := loadConfigStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// ---- compatibility with every earlier version ----

func TestConfig_AFileWrittenByV034LoadsUnchanged(t *testing.T) {
	old := `{"enabled":true,"dry_run":false,"cloudflare_api_token":"tok","cloudflare_account_id":"` + acctA + `","cloudflare_zone_id":"` + zone1 + `",
	"ip_list_name":"zoraxy_cf_waf_blocklist","rule_description":"Zoraxy CF WAF Sync - managed IP blocklist","managed_rule_id":"RULE1","block_action":"managed_challenge",
	"max_ip_list_items":10000,"zoraxy_log_dir":"/srv/zoraxy/log","ratelimit_window_seconds":60,"ratelimit_threshold":30,"react_to_blacklist_event":true,
	"block_ttl_hours":24,"block_expiry_days":14,"zoraxy_ban_enabled":true,"zoraxy_access_rules":["default","abc"]}`
	c := tmpStore(t, old).get()
	if !c.Enabled || c.DryRun || c.BlockAction != "managed_challenge" || c.ManagedRuleID != "RULE1" || !c.Configured() {
		t.Fatalf("legacy fields must load as before: %+v", c)
	}
	if c.AdditionalTargets != nil || c.ExtraZoneIDs != nil || c.ExtraManagedRuleIDs != nil {
		t.Errorf("a legacy config has no extra targets or zones: %+v", c)
	}
	if !c.AnyCloudflareConfigured() {
		t.Error("the primary account alone is a usable Cloudflare target")
	}
}

func TestConfig_NoNewKeysAreWrittenUntilTheyAreUsed(t *testing.T) {
	raw, _ := json.Marshal(defaultConfig())
	for _, k := range []string{"additional_targets", "extra_zone_ids", "extra_managed_rule_ids"} {
		if strings.Contains(string(raw), k) {
			t.Errorf("a single-account config must not gain the key %q (an older version and the file on disk stay identical)", k)
		}
	}
}

func TestConfig_TheLegacyFieldsStayInPlaceWhenTargetsAreAdded(t *testing.T) {
	c := defaultConfig()
	c.CloudflareAPIToken, c.CloudflareAccountID, c.CloudflareZoneID, c.ManagedRuleID = "tok", acctA, zone1, "R1"
	c.AdditionalTargets = []TargetConfig{{Label: "Account 2", AccountID: acctB, ZoneIDs: []string{zone3}, APIToken: "t2"}}
	raw, _ := json.Marshal(c)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"cloudflare_api_token": "tok", "cloudflare_account_id": acctA, "cloudflare_zone_id": zone1, "managed_rule_id": "R1"} {
		if generic[k] != want {
			t.Errorf("downgrade safety: %s must stay a top-level legacy field, got %v", k, generic[k])
		}
	}
	// and an older version reading the file ignores what it does not know
	var old struct {
		Token string `json:"cloudflare_api_token"`
	}
	if err := json.Unmarshal(raw, &old); err != nil || old.Token != "tok" {
		t.Fatalf("an older reader must still work: %v %+v", err, old)
	}
}

// ---- validation ----

func baseCfg() Config {
	c := defaultConfig()
	c.CloudflareAPIToken, c.CloudflareAccountID, c.CloudflareZoneID = "tok", acctA, zone1
	return c
}

func TestNormalise_AdditionalAccountsGetDefaultsAndLabels(t *testing.T) {
	in := baseCfg()
	in.AdditionalTargets = []TargetConfig{{AccountID: acctB, APIToken: "t2", ZoneIDs: []string{zone2}}, {AccountID: acctC, APIToken: "t3", ZoneIDs: []string{zone3}}}
	if err := normaliseTargets(&in, baseCfg()); err != nil {
		t.Fatal(err)
	}
	a, b := in.AdditionalTargets[0], in.AdditionalTargets[1]
	if a.Label != "Cloudflare Account 2" || b.Label != "Cloudflare Account 3" || a.BlockAction != "block" || a.IPListName != defaultConfig().IPListName || a.MaxIPListItems != 10000 {
		t.Errorf("defaults: %+v / %+v", a, b)
	}
}

func TestNormalise_Rejects(t *testing.T) {
	good := func() Config {
		c := baseCfg()
		c.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctB, APIToken: "t2", ZoneIDs: []string{zone2}}}
		return c
	}
	cases := map[string]func(*Config){
		"three additional accounts": func(c *Config) {
			c.AdditionalTargets = append(c.AdditionalTargets, TargetConfig{AccountID: acctC, APIToken: "x", ZoneIDs: []string{zone3}}, TargetConfig{AccountID: acctC, APIToken: "x", ZoneIDs: []string{zone4}})
		},
		"a duplicate label": func(c *Config) {
			c.AdditionalTargets = append(c.AdditionalTargets, TargetConfig{Label: "second", AccountID: acctC, APIToken: "x", ZoneIDs: []string{zone3}})
		},
		"the reserved label of account 1": func(c *Config) { c.AdditionalTargets[0].Label = "cloudflare account 1" },
		"a label that is too long":   func(c *Config) { c.AdditionalTargets[0].Label = strings.Repeat("x", 31) },
		"a bad account id":           func(c *Config) { c.AdditionalTargets[0].AccountID = "not an id/../x" },
		"a bad zone id":              func(c *Config) { c.AdditionalTargets[0].ZoneIDs = []string{"zone with spaces"} },
		"too many zones":             func(c *Config) { c.AdditionalTargets[0].ZoneIDs = []string{zone1, zone2, zone3, zone4, acctA, acctB} },
		"a bad list name":            func(c *Config) { c.AdditionalTargets[0].IPListName = "has space" },
		"a bad block action":         func(c *Config) { c.AdditionalTargets[0].BlockAction = "skip" },
		"enabling an incomplete account": func(c *Config) {
			c.AdditionalTargets[0].Enabled = true
			c.AdditionalTargets[0].ZoneIDs = nil
		},
		"a bad extra primary zone": func(c *Config) { c.ExtraZoneIDs = []string{"../x"} },
		"too many primary zones":   func(c *Config) { c.ExtraZoneIDs = []string{zone2, zone3, zone4, acctB, acctC} },
	}
	for name, mutate := range cases {
		c := good()
		mutate(&c)
		if err := normaliseTargets(&c, baseCfg()); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	c := good()
	if err := normaliseTargets(&c, baseCfg()); err != nil {
		t.Fatalf("the base case must pass: %v", err)
	}
}

func TestNormalise_ExtraPrimaryZonesAreDedupedAndNeverRepeatThePrimary(t *testing.T) {
	in := baseCfg()
	in.ExtraZoneIDs = []string{zone1, zone2, " " + zone2 + " ", "", zone3}
	if err := normaliseTargets(&in, baseCfg()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(in.ExtraZoneIDs, ","); got != zone2+","+zone3 {
		t.Errorf("got %s", got)
	}
}

func TestNormalise_ABlankTokenKeepsTheStoredOneOnlyForTheSameAccount(t *testing.T) {
	cur := baseCfg()
	cur.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctB, APIToken: "stored", ZoneIDs: []string{zone2}}}

	same := baseCfg()
	same.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctB, ZoneIDs: []string{zone2}}}
	if err := normaliseTargets(&same, cur); err != nil || same.AdditionalTargets[0].APIToken != "stored" {
		t.Fatalf("same account, blank token: the stored token must be kept (%v)", err)
	}

	other := baseCfg()
	other.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctC, ZoneIDs: []string{zone2}}}
	if err := normaliseTargets(&other, cur); err != nil || other.AdditionalTargets[0].APIToken != "" {
		t.Fatalf("a changed account must never inherit another account's token (%v, %q)", err, other.AdditionalTargets[0].APIToken)
	}
	other.AdditionalTargets[0].Enabled = true
	if err := normaliseTargets(&other, cur); err == nil {
		t.Error("enabling an account that has no token must be refused")
	}
}

func TestNormalise_ManagedRuleIDsFollowTheirZones(t *testing.T) {
	cur := baseCfg()
	cur.ExtraZoneIDs = []string{zone2, zone3}
	cur.ExtraManagedRuleIDs = map[string]string{zone2: "R2", zone3: "R3"}
	cur.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctB, APIToken: "t", ZoneIDs: []string{zone2, zone3}, ManagedRuleIDs: map[string]string{zone2: "B2", zone3: "B3"}}}

	in := baseCfg()
	in.ExtraZoneIDs = []string{zone3} // zone2 removed
	in.ExtraManagedRuleIDs = map[string]string{"forged": "X"}
	in.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctB, APIToken: "t", ZoneIDs: []string{zone3}, ManagedRuleIDs: map[string]string{"forged": "Y"}}}
	if err := normaliseTargets(&in, cur); err != nil {
		t.Fatal(err)
	}
	if len(in.ExtraManagedRuleIDs) != 1 || in.ExtraManagedRuleIDs[zone3] != "R3" {
		t.Errorf("only zones still configured keep their rule ID, and the form can never set one: %v", in.ExtraManagedRuleIDs)
	}
	if got := in.AdditionalTargets[0].ManagedRuleIDs; len(got) != 1 || got[zone3] != "B3" {
		t.Errorf("same for an additional account: %v", got)
	}
}

func TestConfigured_ZoraxyOnlyOrAnyCloudflareTargetIsEnough(t *testing.T) {
	c := defaultConfig()
	if c.AnyCloudflareConfigured() {
		t.Error("an empty config is not configured")
	}
	c.AdditionalTargets = []TargetConfig{{AccountID: acctB, APIToken: "t", ZoneIDs: []string{zone2}}}
	if c.AnyCloudflareConfigured() {
		t.Error("a disabled additional account does not count")
	}
	c.AdditionalTargets[0].Enabled = true
	if !c.AnyCloudflareConfigured() {
		t.Error("an enabled, complete additional account counts even without a primary")
	}
}

// ---- turning the settings into blocker targets ----

func TestCloudflareTargets_OnePrimaryAccountBehavesLikeBefore(t *testing.T) {
	cs := tmpStore(t, "")
	c := baseCfg()
	c.ManagedRuleID = "R1"
	_ = cs.set(c)
	ts := cloudflareTargets(cs)
	if len(ts) != 1 || ts[0].Label != "" || len(ts[0].Zones) != 1 || ts[0].Zones[0] != zone1 || ts[0].GetRuleID(zone1) != "R1" {
		t.Fatalf("unexpected %+v", ts)
	}
	cl, ok := ts[0].NewClient("")
	if !ok || cl.ZoneID != zone1 || cl.AccountID != acctA {
		t.Errorf("a blank zone means the primary zone: %+v %v", cl, ok)
	}
}

func TestCloudflareTargets_ExtraZonesAndAdditionalAccounts(t *testing.T) {
	cs := tmpStore(t, "")
	c := baseCfg()
	c.ExtraZoneIDs = []string{zone2}
	c.AdditionalTargets = []TargetConfig{
		{Label: "Second", Enabled: true, AccountID: acctB, APIToken: "t2", ZoneIDs: []string{zone3}, IPListName: "list_b", BlockAction: "challenge", RuleDescription: "R", MaxIPListItems: 5},
		{Label: "Third", Enabled: false, AccountID: acctC, APIToken: "t3", ZoneIDs: []string{zone4}},
	}
	_ = cs.set(c)
	ts := cloudflareTargets(cs)
	if len(ts) != 2 {
		t.Fatalf("a disabled account must not become a target: %d", len(ts))
	}
	if ts[0].Label != "Cloudflare Account 1" || strings.Join(ts[0].Zones, ",") != zone1+","+zone2 {
		t.Errorf("primary: %+v", ts[0])
	}
	if ts[1].Label != "Second" || ts[1].BlockAction != "challenge" || ts[1].IPListName != "list_b" || ts[1].MaxListItems != 5 {
		t.Errorf("the block action and list are per account: %+v", ts[1])
	}
	// rule IDs are remembered per zone, in the right place, and persisted
	ts[0].SetRuleID(zone1, "P1")
	ts[0].SetRuleID(zone2, "P2")
	ts[1].SetRuleID(zone3, "S3")
	got := cs.get()
	if got.ManagedRuleID != "P1" || got.ExtraManagedRuleIDs[zone2] != "P2" || got.AdditionalTargets[0].ManagedRuleIDs[zone3] != "S3" {
		t.Errorf("rule IDs stored in the wrong place: %+v", got)
	}
	if again := cloudflareTargets(cs); again[0].GetRuleID(zone2) != "P2" || again[1].GetRuleID(zone3) != "S3" {
		t.Error("stored rule IDs must be read back")
	}
	reload := tmpStoreAt(t, cs.path)
	if reload.get().AdditionalTargets[0].ManagedRuleIDs[zone3] != "S3" {
		t.Error("rule IDs must survive a restart")
	}
}

func tmpStoreAt(t *testing.T, path string) *configStore {
	t.Helper()
	cs, err := loadConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestRedactedConfig_NeverShowsAnyToken_AndNeverTouchesTheStoredCopy(t *testing.T) {
	c := baseCfg()
	c.AdditionalTargets = []TargetConfig{{Label: "Second", AccountID: acctB, APIToken: "SECRET-2", ZoneIDs: []string{zone2}}}
	r := redactedConfig(c)
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "SECRET-2") || strings.Contains(string(raw), `"tok"`) {
		t.Errorf("a token leaked into the page's config: %s", raw)
	}
	if c.AdditionalTargets[0].APIToken != "SECRET-2" || c.CloudflareAPIToken != "tok" {
		t.Error("redaction must work on a copy")
	}
}

func TestNormalise_AnUnusedTabIsNotStored(t *testing.T) {
	in := baseCfg()
	in.AdditionalTargets = []TargetConfig{{}, {}}
	if err := normaliseTargets(&in, baseCfg()); err != nil {
		t.Fatal(err)
	}
	if in.AdditionalTargets != nil {
		t.Errorf("two empty tabs must leave no trace in the config: %+v", in.AdditionalTargets)
	}
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "additional_targets") {
		t.Error("the key must not be written")
	}

	// a filled second tab keeps its position even when the first is empty
	in2 := baseCfg()
	in2.AdditionalTargets = []TargetConfig{{}, {AccountID: acctC, APIToken: "t", ZoneIDs: []string{zone3}}}
	if err := normaliseTargets(&in2, baseCfg()); err != nil {
		t.Fatal(err)
	}
	if len(in2.AdditionalTargets) != 2 || in2.AdditionalTargets[1].AccountID != acctC || in2.AdditionalTargets[1].Label != "Cloudflare Account 3" {
		t.Errorf("tab positions must be kept: %+v", in2.AdditionalTargets)
	}
}
