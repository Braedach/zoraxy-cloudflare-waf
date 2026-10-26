package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
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

	// ZoraxyLogDir is where Zoraxy writes its zr_YYYY-M.log access logs - the files this
	// plugin's log tailer parses.
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
	// it's willing to action it again (dedup only - it does not remove anything).
	BlockTTLHours int `json:"block_ttl_hours"`

	// BlockExpiryDays: blocks this plugin created are removed automatically once they are older than this
	// many days (0 = never expire). Many scanners use rented/ephemeral cloud addresses that are later reused
	// by legitimate services, so a permanent block slowly turns into a false positive. Only entries the plugin
	// itself added are ever removed - never anything an operator put in the list or in Zoraxy by hand.
	BlockExpiryDays int `json:"block_expiry_days"`

	// ZoraxyBanEnabled additionally bans each blocked IP in Zoraxy's own access-rule blacklist, on top of
	// Cloudflare. It needs the plugin's Zoraxy API permissions (declared in the introspection) and only has an
	// effect for rules whose blacklist is switched on AND that see the real client IP - behind a tunnel that
	// means the tunnel's address must be a trusted proxy in Zoraxy (see the README).
	ZoraxyBanEnabled bool `json:"zoraxy_ban_enabled"`

	// ZoraxyAccessRules lists the Zoraxy access-rule IDs bans are added to ("default" is Zoraxy's default rule).
	ZoraxyAccessRules []string `json:"zoraxy_access_rules"`

	// ExtraZoneIDs are more zones in the PRIMARY account that get the same managed rule (same token, same IP list, same action).
	// Empty means the single-zone behaviour every earlier version had.
	ExtraZoneIDs []string `json:"extra_zone_ids,omitempty"`

	// ExtraManagedRuleIDs holds the rule ID the plugin created in each extra zone (zone ID -> rule ID); bookkeeping owned by the
	// blocker, like ManagedRuleID.
	ExtraManagedRuleIDs map[string]string `json:"extra_managed_rule_ids,omitempty"`

	// AdditionalTargets are further Cloudflare accounts (up to maxAdditionalTargets), each with its own token, IP list, zones
	// and block action. The primary account is always the flat fields above, so a config written by an earlier version loads
	// unchanged and an older version loading this file simply ignores this field.
	AdditionalTargets []TargetConfig `json:"additional_targets,omitempty"`
}

const (
	maxAdditionalTargets = 2 // primary + two
	maxZonesPerTarget    = 5 // the primary zone plus up to four more
	maxLabelLength       = 30
)

// TargetConfig is one additional Cloudflare account the plugin protects.
type TargetConfig struct {
	Label           string            `json:"label"`
	Enabled         bool              `json:"enabled"`
	APIToken        string            `json:"cloudflare_api_token"`
	AccountID       string            `json:"cloudflare_account_id"`
	ZoneIDs         []string          `json:"zone_ids"`
	IPListName      string            `json:"ip_list_name"`
	RuleDescription string            `json:"rule_description"`
	BlockAction     string            `json:"block_action"`
	MaxIPListItems  int               `json:"max_ip_list_items"`
	ManagedRuleIDs  map[string]string `json:"managed_rule_ids,omitempty"` // zone ID -> rule ID (bookkeeping)
}

// Configured reports whether this target has what it needs to talk to Cloudflare.
func (t TargetConfig) Configured() bool {
	return t.APIToken != "" && t.AccountID != "" && len(t.ZoneIDs) > 0
}

// cloudflareIDRe is deliberately lenient (Cloudflare IDs are 32 hex characters today): it only keeps junk, spaces and URL
// fragments out of a value that is interpolated into API paths.
var cloudflareIDRe = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)

// AnyCloudflareConfigured reports whether at least one Cloudflare target (the primary, or an enabled additional one) is usable.
func (c Config) AnyCloudflareConfigured() bool {
	if c.Configured() {
		return true
	}
	for _, t := range c.AdditionalTargets {
		if t.Enabled && t.Configured() {
			return true
		}
	}
	return false
}

// normaliseTargets validates and tidies the multi-target part of an incoming config and carries bookkeeping the form never sends
// (stored tokens, managed rule IDs) forward from the current config. It does not touch the single-account fields.
func normaliseTargets(in *Config, current Config) error {
	// Extra zones of the primary account.
	zones, err := normaliseZoneIDs(in.ExtraZoneIDs, in.CloudflareZoneID)
	if err != nil {
		return fmt.Errorf("extra zones: %w", err)
	}
	if len(zones)+1 > maxZonesPerTarget {
		return fmt.Errorf("too many zones for the primary account (%d, max %d)", len(zones)+1, maxZonesPerTarget)
	}
	in.ExtraZoneIDs = zones
	in.ExtraManagedRuleIDs = keepRuleIDs(current.ExtraManagedRuleIDs, zones)

	if len(in.AdditionalTargets) > maxAdditionalTargets {
		return fmt.Errorf("too many additional accounts (%d, max %d)", len(in.AdditionalTargets), maxAdditionalTargets)
	}
	labels := map[string]bool{"primary": true}
	for i := range in.AdditionalTargets {
		t := &in.AdditionalTargets[i]
		t.Label = strings.TrimSpace(t.Label)
		if t.Label == "" {
			t.Label = fmt.Sprintf("Account %d", i+2)
		}
		if len(t.Label) > maxLabelLength {
			return fmt.Errorf("account %d: label is longer than %d characters", i+2, maxLabelLength)
		}
		if labels[strings.ToLower(t.Label)] {
			return fmt.Errorf("account %d: the label %q is already used", i+2, t.Label)
		}
		labels[strings.ToLower(t.Label)] = true

		t.AccountID = strings.TrimSpace(t.AccountID)
		if t.AccountID != "" && !cloudflareIDRe.MatchString(t.AccountID) {
			return fmt.Errorf("account %d (%s): the account ID does not look like a Cloudflare ID", i+2, t.Label)
		}
		zs, err := normaliseZoneIDs(t.ZoneIDs, "")
		if err != nil {
			return fmt.Errorf("account %d (%s): %w", i+2, t.Label, err)
		}
		if len(zs) > maxZonesPerTarget {
			return fmt.Errorf("account %d (%s): too many zones (%d, max %d)", i+2, t.Label, len(zs), maxZonesPerTarget)
		}
		t.ZoneIDs = zs

		// A blank token means "keep the stored one", but only for the same account: never carry a token to a different account.
		var old *TargetConfig
		if i < len(current.AdditionalTargets) {
			old = &current.AdditionalTargets[i]
		}
		if t.APIToken == "" && old != nil && old.AccountID == t.AccountID {
			t.APIToken = old.APIToken
		}
		if old != nil {
			t.ManagedRuleIDs = keepRuleIDs(old.ManagedRuleIDs, t.ZoneIDs)
		} else {
			t.ManagedRuleIDs = nil
		}

		if t.IPListName == "" {
			t.IPListName = defaultConfig().IPListName
		}
		if !validIPListName(t.IPListName) {
			return fmt.Errorf("account %d (%s): invalid list name %q (letters, digits and underscores only, max 50)", i+2, t.Label, t.IPListName)
		}
		if t.RuleDescription == "" {
			t.RuleDescription = defaultConfig().RuleDescription
		}
		if t.BlockAction == "" {
			t.BlockAction = defaultConfig().BlockAction
		}
		if !validBlockAction(t.BlockAction) {
			return fmt.Errorf("account %d (%s): invalid block action %q: must be one of %s", i+2, t.Label, t.BlockAction, strings.Join(validBlockActions, ", "))
		}
		if t.MaxIPListItems <= 0 {
			t.MaxIPListItems = defaultConfig().MaxIPListItems
		}
		if t.Enabled && !t.Configured() {
			return fmt.Errorf("cannot enable account %d (%s): its token, account ID and at least one zone ID must all be set first", i+2, t.Label)
		}
	}
	// A tab the user never filled in is not stored, so a single-account config stays exactly what it always was on disk.
	for n := len(in.AdditionalTargets); n > 0 && in.AdditionalTargets[n-1].isBlank(); n-- {
		in.AdditionalTargets = in.AdditionalTargets[:n-1]
	}
	if len(in.AdditionalTargets) == 0 {
		in.AdditionalTargets = nil
	}
	return nil
}

// isBlank reports whether nothing the user typed is in this target (the defaults normaliseTargets fills in do not count).
func (t TargetConfig) isBlank() bool {
	return !t.Enabled && t.APIToken == "" && t.AccountID == "" && len(t.ZoneIDs) == 0 && strings.HasPrefix(t.Label, "Account ")
}

// normaliseZoneIDs trims, validates and de-duplicates zone IDs, dropping any that equal skip (the primary zone).
func normaliseZoneIDs(in []string, skip string) ([]string, error) {
	seen := map[string]bool{strings.TrimSpace(skip): true}
	var out []string
	for _, z := range in {
		z = strings.TrimSpace(z)
		if z == "" || seen[z] {
			continue
		}
		if !cloudflareIDRe.MatchString(z) {
			return nil, fmt.Errorf("%q does not look like a Cloudflare zone ID", z)
		}
		seen[z] = true
		out = append(out, z)
	}
	return out, nil
}

// keepRuleIDs carries managed rule IDs forward for the zones that are still configured.
func keepRuleIDs(old map[string]string, zones []string) map[string]string {
	var out map[string]string
	for _, z := range zones {
		if id := old[z]; id != "" {
			if out == nil {
				out = map[string]string{}
			}
			out[z] = id
		}
	}
	return out
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

// ipListNameRe is Cloudflare's rule for custom list names (letters, digits, underscore, max 50). The name
// is interpolated into the rule expression as `ip.src in $<name>`, so a space or other character makes
// the expression invalid and the first real block fail.
var ipListNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,50}$`)

func validIPListName(n string) bool { return ipListNameRe.MatchString(n) }

// accessRuleIDRe matches the IDs Zoraxy uses for access rules ("default" or a UUID).
var accessRuleIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// normaliseAccessRules trims, de-duplicates and validates access-rule IDs.
func normaliseAccessRules(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, id := range in {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		if !accessRuleIDRe.MatchString(id) {
			return nil, fmt.Errorf("invalid Zoraxy access rule id %q", id)
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) > 20 {
		return nil, fmt.Errorf("too many Zoraxy access rules selected (%d, max 20)", len(out))
	}
	return out, nil
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
		BlockExpiryDays:        14,
		ZoraxyBanEnabled:       false,
		ZoraxyAccessRules:      []string{"default"},
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

// update applies f to a copy of the config and saves the result, holding the lock so concurrent bookkeeping writes (rule IDs) cannot lose each other.
func (cs *configStore) update(f func(*Config)) error {
	cs.mu.Lock()
	f(&cs.cfg)
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
