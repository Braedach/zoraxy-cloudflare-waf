package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Config is this plugin's own persistent settings. Zoraxy's ConfigureSpec only carries
// the port/API-key/zoraxy-port triple (see mod/zoraxy_plugin/zoraxy_plugin.go) - anything
// plugin-specific is on us to store, exactly like the upnp example plugin does with its
// own upnp.json next to the binary.
type Config struct {
	// Enabled gates whether detections turn into Cloudflare API calls at all. Defaults to
	// false so installing the plugin never starts mutating a live zone by itself.
	Enabled bool `json:"enabled"`

	// DryRun logs what *would* be blocked without calling Cloudflare. Defaults to true so
	// the first real run against production logs is always observe-only until reviewed.
	DryRun bool `json:"dry_run"`

	CloudflareAPIToken  string `json:"cloudflare_api_token"`
	CloudflareAccountID string `json:"cloudflare_account_id"`
	CloudflareZoneID    string `json:"cloudflare_zone_id"`

	// IPListName is the single Cloudflare IP List this plugin owns. One custom rule
	// referencing "ip.src in $<IPListName>" covers unlimited IPs from one rule slot -
	// see README for why this matters on a 5-rule plan. Cloudflare list names must be
	// alphanumeric/underscore only, max 50 chars.
	IPListName string `json:"ip_list_name"`

	// RuleDescription is what shows up in the "Name" column of Cloudflare's Security
	// Rules dashboard (the Ruleset Engine API has no separate "name" field - description
	// *is* the display name). User-editable; the plugin tracks its own rule by
	// ManagedRuleID once created, so renaming this here safely updates the existing rule
	// instead of creating a duplicate.
	RuleDescription string `json:"rule_description"`

	// ManagedRuleID is the Cloudflare-assigned ID of the custom rule this plugin created,
	// persisted after first creation so subsequent syncs update it by ID rather than by
	// matching description text (robust against the rule being renamed by hand in the
	// Cloudflare dashboard). Not user-edited - the UI shows it read-only.
	ManagedRuleID string `json:"managed_rule_id,omitempty"`

	// BlockAction is the Cloudflare action applied by the custom rule this plugin
	// ensures exists - one of validBlockActions.
	BlockAction string `json:"block_action"`

	// MaxIPListItems is this plugin's OWN pre-flight guard against Cloudflare's list
	// size cap, checked before every add so a full list fails softly (recorded as
	// "skipped-list-full" in the action log) instead of erroring against the API. Default
	// matches the documented Free/Pro/Business account-wide cap of 10,000 items across
	// all custom lists (developers.cloudflare.com/waf/tools/lists/lists-api/) - raise it
	// only if your plan's actual limit is higher; this does not change what Cloudflare
	// itself enforces, it only makes our own behavior fail predictably.
	MaxIPListItems int `json:"max_ip_list_items"`

	// ZoraxyLogDir is where Zoraxy writes zr_YYYY-M.log files (see
	// Proxmox/LXC/Scripts/forensic-report-zoraxy-v2.sh in the homelab repo for the
	// format this plugin's log tailer parses).
	ZoraxyLogDir string `json:"zoraxy_log_dir"`

	// RateLimitWindowSeconds / RateLimitThreshold: a client IP that racks up more than
	// Threshold matched "noisy" status codes (4xx/5xx) within Window seconds triggers a
	// block candidate. Exploit-pattern matches (path traversal, injection probes, etc.)
	// always trigger immediately regardless of this threshold.
	RateLimitWindowSeconds int `json:"ratelimit_window_seconds"`
	RateLimitThreshold     int `json:"ratelimit_threshold"`

	// ReactToBlacklistEvent subscribes to Zoraxy's own blacklistedIpBlocked event so an
	// IP Zoraxy already blocked via its access-rule blacklist gets mirrored into
	// Cloudflare immediately, without waiting on the log tailer's polling interval.
	ReactToBlacklistEvent bool `json:"react_to_blacklist_event"`

	// BlockTTLHours: how long this plugin remembers it already actioned an IP before
	// it's willing to action it again (dedup, not an unblock - Cloudflare list removal
	// is a separate, manual/future feature).
	BlockTTLHours int `json:"block_ttl_hours"`
}

// validBlockActions are the Cloudflare custom-rule actions this plugin will put on its managed rule.
// "log" only works on Enterprise plans and blocks nothing; "skip" is deliberately absent (it is an
// allow-list action and needs action_parameters this plugin doesn't send).
var validBlockActions = []string{"block", "managed_challenge", "js_challenge", "challenge", "log"}

func validBlockAction(a string) bool {
	for _, v := range validBlockActions {
		if a == v {
			return true
		}
	}
	return false
}

func defaultConfig() Config {
	return Config{
		Enabled:                false,
		DryRun:                 true,
		IPListName:             "zoraxy_cf_waf_blocklist",
		RuleDescription:        "Zoraxy CF WAF Sync - managed IP blocklist",
		BlockAction:            "block",
		MaxIPListItems:         10000,
		ZoraxyLogDir:           "/srv/zoraxy/log",
		RateLimitWindowSeconds: 60,
		RateLimitThreshold:     30,
		ReactToBlacklistEvent:  true,
		BlockTTLHours:          24,
	}
}

// Configured reports whether enough is filled in to talk to Cloudflare at all. The UI
// uses this to gate the "Enabled" toggle behind a successful Test Connection first -
// see main.go's /ui/api/test handler.
func (c Config) Configured() bool {
	return c.CloudflareAPIToken != "" && c.CloudflareAccountID != "" && c.CloudflareZoneID != ""
}

// configStore guards Config with a mutex since it's read by the log tailer / event
// handler goroutines and written by the UI's save-config handler concurrently.
type configStore struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func loadConfigStore(path string) (*configStore, error) {
	cs := &configStore{path: path, cfg: defaultConfig()}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := cs.save(); err != nil {
			return nil, fmt.Errorf("writing default config: %w", err)
		}
		return cs, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := defaultConfig()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cs.cfg = cfg
	return cs, nil
}

func (cs *configStore) get() Config {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg
}

func (cs *configStore) set(cfg Config) error {
	cs.mu.Lock()
	cs.cfg = cfg
	cs.mu.Unlock()
	return cs.save()
}

func (cs *configStore) save() error {
	cs.mu.RLock()
	raw, err := json.MarshalIndent(cs.cfg, "", "  ")
	cs.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(cs.path, raw, 0600)
}
