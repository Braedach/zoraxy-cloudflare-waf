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
