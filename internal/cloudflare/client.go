// Package cloudflare is a deliberately small client for exactly the two things this
// plugin needs: maintaining one IP List, and making sure exactly one custom rule
// references it. It is not a general Cloudflare SDK.
//
// Design note: we block via a single IP List + a single custom rule
// ("ip.src in $<list>") rather than one custom rule per IP. Custom rules are capped
// (5 on the plans this homelab is on, per the Security Rules screenshot reviewed when
// this plugin was scoped) - a list can hold thousands of entries behind that one rule.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

type Client struct {
	AccountID string
	ZoneID    string
	Token     string
	HTTP      *http.Client
}

func New(accountID, zoneID, token string) *Client {
	return &Client{
		AccountID: accountID,
		ZoneID:    zoneID,
		Token:     token,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
	}
}

type apiResponse struct {
	Success bool             `json:"success"`
	Errors  []apiResponseErr `json:"errors"`
	Result  json.RawMessage  `json:"result"`
}

type apiResponseErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) do(ctx context.Context, method, url string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var parsed apiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("cloudflare api: non-JSON response (status %d): %s", resp.StatusCode, string(raw))
	}
	if !parsed.Success {
		return fmt.Errorf("cloudflare api error (status %d): %+v", resp.StatusCode, parsed.Errors)
	}
	if out != nil && len(parsed.Result) > 0 {
		return json.Unmarshal(parsed.Result, out)
	}
	return nil
}

// VerifyToken confirms the token is valid at all (it may still lack the specific scopes
// this client needs - TestCapabilities below tests those individually). Corresponds to
// the "API token" test in Cloudflare's dashboard.
func (c *Client) VerifyToken(ctx context.Context) error {
	url := apiBase + "/user/tokens/verify"
	return c.do(ctx, http.MethodGet, url, nil, nil)
}

// probe is like do, but reports the raw HTTP status instead of collapsing everything into
// one error - needed to tell "403, this token can't see this" apart from "404, this
// resource genuinely doesn't exist yet" (a fresh zone with zero custom rules returns 404
// for the phase entrypoint even with a fully-permissioned token).
func (c *Client) probe(ctx context.Context, method, url string) (status int, success bool, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, false, err
	}
	var parsed apiResponse
	_ = json.Unmarshal(raw, &parsed) // best-effort; status code is the primary signal here
	return resp.StatusCode, parsed.Success, nil
}

// CapabilityReport is the result of TestCapabilities: what the configured token can
// actually do, checked live against Cloudflare, for the plugin UI's "Test Connection"
// button. This is what gates the Enabled toggle - see main.go's /ui/api/test handler.
type CapabilityReport struct {
	TokenValid  bool   `json:"token_valid"`
	TokenError  string `json:"token_error,omitempty"`
	ListsAccess bool   `json:"lists_access"` // needs "Account > Account Filter Lists > Edit"
	ListsError  string `json:"lists_error,omitempty"`
	WAFAccess   bool   `json:"waf_access"` // needs "Zone > WAF > Edit"
	WAFError    string `json:"waf_error,omitempty"`

	// ListExists / ListItemCount are only populated when listName is non-empty and the
	// list already exists (a not-yet-created list isn't an error - EnsureIPList creates
	// it on first real block).
	ListExists    bool `json:"list_exists"`
	ListItemCount int  `json:"list_item_count,omitempty"`
}

// TestCapabilities checks token validity and both required scopes without mutating
// anything - the lists check is a plain GET (list access, not creation), and the WAF
// check is a plain GET of the custom-rules phase entrypoint. If listName is non-empty and
// already exists, also reports its current item count (see Config.MaxIPListItems).
func (c *Client) TestCapabilities(ctx context.Context, listName string) CapabilityReport {
	var report CapabilityReport

	if err := c.VerifyToken(ctx); err != nil {
		report.TokenError = err.Error()
		return report // every other call will also fail with an invalid token, don't bother
	}
	report.TokenValid = true

	listsURL := fmt.Sprintf("%s/accounts/%s/rules/lists", apiBase, c.AccountID)
	var lists []ipList
	if err := c.do(ctx, http.MethodGet, listsURL, nil, &lists); err != nil {
		report.ListsError = err.Error()
	} else {
		report.ListsAccess = true
		if listName != "" {
			for _, l := range lists {
				if l.Name == listName {
					report.ListExists = true
					report.ListItemCount = l.NumItems
					break
				}
			}
		}
	}

	wafURL := fmt.Sprintf("%s/zones/%s/rulesets/phases/http_request_firewall_custom/entrypoint", apiBase, c.ZoneID)
	if status, success, err := c.probe(ctx, http.MethodGet, wafURL); err != nil {
		report.WAFError = err.Error()
	} else if success || status == http.StatusNotFound {
		// 404 here means "this zone has no custom rules yet", not "no access" - a
		// correctly-scoped token gets 404 on a fresh zone just as often as 200.
		report.WAFAccess = true
	} else {
		report.WAFError = fmt.Sprintf("HTTP %d - check the token has Zone > WAF > Edit for this zone", status)
	}

	return report
}

type ipList struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	NumItems int    `json:"num_items"`
}

// ListIPListItemCount returns the current number of items in the given list, so callers
// can pre-flight check against Cloudflare's list-size cap before attempting an add (see
// Config.MaxIPListItems).
func (c *Client) ListIPListItemCount(ctx context.Context, listID string) (int, error) {
	var l ipList
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s", apiBase, c.AccountID, listID)
	if err := c.do(ctx, http.MethodGet, url, nil, &l); err != nil {
		return 0, fmt.Errorf("getting list %s: %w", listID, err)
	}
	return l.NumItems, nil
}

// EnsureIPList returns the ID of the IP list named listName, creating it if it doesn't
// exist yet.
func (c *Client) EnsureIPList(ctx context.Context, listName string) (string, error) {
	var lists []ipList
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", apiBase, c.AccountID)
	if err := c.do(ctx, http.MethodGet, url, nil, &lists); err != nil {
		return "", fmt.Errorf("listing ip lists: %w", err)
	}
	for _, l := range lists {
		if l.Name == listName {
			return l.ID, nil
		}
	}

	created := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Kind        string `json:"kind"`
	}{
		Name:        listName,
		Description: "Managed by zoraxy-cloudflare-waf - do not edit membership manually, it will be overwritten.",
		Kind:        "ip",
	}
	var result ipList
	if err := c.do(ctx, http.MethodPost, url, created, &result); err != nil {
		return "", fmt.Errorf("creating ip list %q: %w", listName, err)
	}
	return result.ID, nil
}

type listItemPatch struct {
	Append []listItem `json:"append,omitempty"`
	Remove []string   `json:"remove,omitempty"`
}

type listItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

type bulkOperation struct {
	OperationID string `json:"operation_id"`
}

// AddIP appends ip to the list, with comment as the audit trail visible in the
// Cloudflare dashboard (e.g. "zoraxy log-threshold: 42 4xx in 60s"). This is async on
// Cloudflare's side; we fire the patch and don't block on the bulk_operations result -
// the recent-actions log in this plugin's own UI is the source of truth for "did my
// plugin try to block this", the Cloudflare dashboard is the source of truth for whether
// it landed.
func (c *Client) AddIP(ctx context.Context, listID, ip, comment string) error {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", apiBase, c.AccountID, listID)
	patch := listItemPatch{Append: []listItem{{IP: ip, Comment: comment}}}
	var op bulkOperation
	if err := c.do(ctx, http.MethodPatch, url, patch, &op); err != nil {
		return fmt.Errorf("adding %s to list: %w", ip, err)
	}
	return nil
}

func (c *Client) RemoveIP(ctx context.Context, listID, ip string) error {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", apiBase, c.AccountID, listID)
	patch := listItemPatch{Remove: []string{ip}}
	var op bulkOperation
	if err := c.do(ctx, http.MethodPatch, url, patch, &op); err != nil {
		return fmt.Errorf("removing %s from list: %w", ip, err)
	}
	return nil
}

type ruleset struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Rules []rule `json:"rules"`
}

type rule struct {
	ID          string `json:"id,omitempty"`
	Expression  string `json:"expression"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// EnsureBlockRule makes sure exactly one custom rule exists on the zone's
// http_request_firewall_custom phase referencing listName, with the given action
// ("block" or "managed_challenge") and description (shown as the rule's "Name" in
// Cloudflare's dashboard - the Ruleset Engine API has no separate name field). It never
// touches any other rule in that phase - your existing manually-authored rules (Google
// Cloud Services, Block Crawlers, etc.) are left exactly as-is.
//
// existingRuleID, if non-empty (Config.ManagedRuleID from a previous call), is matched
// first so renaming `description` later updates the same rule instead of creating a
// duplicate. If empty (first run, or the persisted ID went stale - e.g. someone deleted
// the rule by hand), falls back to matching by description text, then creates a new rule
// if neither matches. Returns the rule's ID so the caller can persist it.
func (c *Client) EnsureBlockRule(ctx context.Context, listName, action, description, existingRuleID string) (string, error) {
	const phase = "http_request_firewall_custom"

	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", apiBase, c.ZoneID, phase)

	var rs ruleset
	err := c.do(ctx, http.MethodGet, url, nil, &rs)
	notFound := err != nil // a zone with zero custom rules yet returns a 404 for the phase entrypoint

	expression := fmt.Sprintf("(ip.src in $%s)", listName)

	if notFound {
		// No entrypoint ruleset exists yet on this zone for this phase - create one with
		// just our rule.
		return c.createEntrypoint(ctx, phase, expression, action, description)
	}

	var match *rule
	if existingRuleID != "" {
		for i := range rs.Rules {
			if rs.Rules[i].ID == existingRuleID {
				match = &rs.Rules[i]
				break
			}
		}
	}
	if match == nil {
		for i := range rs.Rules {
			if rs.Rules[i].Description == description {
				match = &rs.Rules[i]
				break
			}
		}
	}

	if match == nil {
		return c.appendRule(ctx, phase, rs.Rules, expression, action, description)
	}
	if match.Expression == expression && match.Action == action && match.Description == description {
		return match.ID, nil // already correct, nothing to do
	}
	return c.updateRule(ctx, phase, rs.Rules, match.ID, expression, action, description)
}

// updateRule returns the (unchanged) ruleID once the PUT succeeds - the Ruleset Engine
// API preserves rule IDs across an update-in-place PUT of the whole rule list.
func (c *Client) updateRule(ctx context.Context, phase string, existing []rule, ruleID, expression, action, description string) (string, error) {
	updated := make([]rule, 0, len(existing))
	for _, r := range existing {
		if r.ID == ruleID {
			r.Expression = expression
			r.Action = action
			r.Description = description
		}
		updated = append(updated, r)
	}
	if err := c.putEntrypoint(ctx, phase, updated); err != nil {
		return "", err
	}
	return ruleID, nil
}

func (c *Client) appendRule(ctx context.Context, phase string, existing []rule, expression, action, description string) (string, error) {
	updated := append(existing, rule{Expression: expression, Action: action, Description: description})
	if err := c.putEntrypoint(ctx, phase, updated); err != nil {
		return "", err
	}
	return c.findRuleID(ctx, phase, description)
}

func (c *Client) createEntrypoint(ctx context.Context, phase, expression, action, description string) (string, error) {
	if err := c.putEntrypoint(ctx, phase, []rule{{Expression: expression, Action: action, Description: description}}); err != nil {
		return "", err
	}
	return c.findRuleID(ctx, phase, description)
}

// findRuleID re-fetches the entrypoint to learn the ID Cloudflare assigned to the rule we
// just wrote - the PUT response doesn't echo per-rule IDs in a way worth depending on, so
// a fresh GET matched by description is the reliable way to learn it.
func (c *Client) findRuleID(ctx context.Context, phase, description string) (string, error) {
	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", apiBase, c.ZoneID, phase)
	var rs ruleset
	if err := c.do(ctx, http.MethodGet, url, nil, &rs); err != nil {
		return "", fmt.Errorf("re-fetching entrypoint to learn new rule ID: %w", err)
	}
	for _, r := range rs.Rules {
		if r.Description == description {
			return r.ID, nil
		}
	}
	return "", fmt.Errorf("rule with description %q not found after write", description)
}

func (c *Client) putEntrypoint(ctx context.Context, phase string, rules []rule) error {
	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", apiBase, c.ZoneID, phase)
	body := struct {
		Rules []rule `json:"rules"`
	}{Rules: rules}
	return c.do(ctx, http.MethodPut, url, body, nil)
}
