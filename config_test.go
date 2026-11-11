package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/logtail"
)

func TestValidIPListName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"zoraxy_cf_waf_blocklist", true},
		{"Zoraxy_CF_WAF", true},
		{"a", true},
		{"list123", true},
		{strings.Repeat("a", 50), true},
		{strings.Repeat("a", 51), false},
		{"Zoraxy Cloudflare WAF", false},
		{"zoraxy-cf-waf", false},
		{"", false},
		{"bad$name", false},
		{"trailing\n", false},
	}
	for _, c := range cases {
		if got := validIPListName(c.name); got != c.want {
			t.Errorf("validIPListName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidBlockAction(t *testing.T) {
	for _, ok := range []string{"block", "managed_challenge", "js_challenge", "challenge", "log"} {
		if !validBlockAction(ok) {
			t.Errorf("validBlockAction(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "skip", "BLOCK", "block ", "allow"} {
		if validBlockAction(bad) {
			t.Errorf("validBlockAction(%q) = true, want false", bad)
		}
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	c := defaultConfig()
	if !validIPListName(c.IPListName) || !validBlockAction(c.BlockAction) {
		t.Errorf("defaults must pass their own validation: list=%q action=%q", c.IPListName, c.BlockAction)
	}
}

func TestNormaliseAccessRules(t *testing.T) {
	got, err := normaliseAccessRules([]string{" default ", "e8f2de9c-558c-43aa-9826-0b3ca7f40de0", "default", ""})
	if err != nil || len(got) != 2 || got[0] != "default" {
		t.Fatalf("got %v err=%v", got, err)
	}
	for _, bad := range []string{"a b", "../x", "x;y", strings.Repeat("a", 101)} {
		if _, err := normaliseAccessRules([]string{bad}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	many := make([]string, 25)
	for i := range many {
		many[i] = "r" + strings.Repeat("x", i+1)
	}
	if _, err := normaliseAccessRules(many); err == nil {
		t.Error("more than 20 rules should be rejected")
	}
}

func TestDefaultsGiveExpiryAndKeepZoraxyBanOff(t *testing.T) {
	c := defaultConfig()
	if c.BlockExpiryDays != 14 || c.ZoraxyBanEnabled || len(c.ZoraxyAccessRules) != 1 || c.ZoraxyAccessRules[0] != "default" {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestConfig_MissingProbeSettingsMeansEverythingOn(t *testing.T) {
	// A config file written by v0.3.5 or earlier has neither field.
	dir := t.TempDir()
	path := dir + "/cloudflarewaf.json"
	if err := os.WriteFile(path, []byte(`{"enabled": false, "dry_run": true, "ratelimit_threshold": 30}`), 0600); err != nil {
		t.Fatal(err)
	}
	cs, err := loadConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cs.get()
	if len(c.ProbeDisabledCategories) != 0 || len(c.ProbeAllowPaths) != 0 {
		t.Fatalf("old config must load with every category on and nothing allowed, got %v / %v", c.ProbeDisabledCategories, c.ProbeAllowPaths)
	}
	d, a, err := logtail.NormaliseProbeSettings(c.ProbeDisabledCategories, c.ProbeAllowPaths)
	if err != nil || len(d) != 0 || len(a) != 0 {
		t.Fatalf("old config must validate: %v %v %v", d, a, err)
	}
}

func TestConfig_ProbeSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cloudflarewaf.json"
	cs, err := loadConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cs.get()
	c.ProbeDisabledCategories = []string{"ci-config"}
	c.ProbeAllowPaths = []string{"/myapp/*", "/types/credentials.json"}
	if err := cs.set(c); err != nil {
		t.Fatal(err)
	}
	cs2, err := loadConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cs2.get()
	if strings.Join(got.ProbeDisabledCategories, ",") != "ci-config" || strings.Join(got.ProbeAllowPaths, ",") != "/myapp/*,/types/credentials.json" {
		t.Errorf("settings did not survive a save and reload: %v / %v", got.ProbeDisabledCategories, got.ProbeAllowPaths)
	}
}

// The settings page lists the probe categories itself; this keeps that list and the detector's in step.
func TestSettingsPage_ListsEveryProbeCategory(t *testing.T) {
	page, err := wwwFS.ReadFile("www/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range logtail.ProbeCategories() {
		if !strings.Contains(string(page), `id: "`+c+`"`) {
			t.Errorf("settings page has no switch for probe category %q", c)
		}
	}
}

// The help must say what a Cloudflare zone is: people who have never used the API do not know it is a domain.
func TestSettingsPage_ExplainsThatAZoneIsADomain(t *testing.T) {
	page, err := wwwFS.ReadFile("www/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Zone = a domain.", "Zone ID (the ID of your domain in Cloudflare)", "More domains (zones) in this account"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("settings page no longer contains %q", want)
		}
	}
}

// A settings file that does not use the new probe settings must not gain keys when the plugin saves it (the release-candidate
// documentation promises new keys appear only when a new feature is used).
func TestConfig_SavingDoesNotAddProbeKeysUnlessUsed(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cloudflarewaf.json"
	if err := os.WriteFile(path, []byte(`{"enabled": true, "dry_run": true}`), 0600); err != nil {
		t.Fatal(err)
	}
	cs, err := loadConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.set(cs.get()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, k := range []string{"probe_disabled_categories", "probe_allow_paths", "additional_targets", "extra_zone_ids"} {
		if strings.Contains(string(raw), k) {
			t.Errorf("saving an old settings file added the key %q:\n%s", k, raw)
		}
	}
	c := cs.get()
	c.ProbeAllowPaths = []string{"/a/*"}
	if err := cs.set(c); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), "probe_allow_paths") {
		t.Errorf("a configured never-ban list must be saved:\n%s", raw)
	}
}
