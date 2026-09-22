package main

import (
	"strings"
	"testing"
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
