// Package cloudflare is a deliberately small client for exactly the two things this
// plugin needs: maintaining one IP List, and making sure exactly one custom rule
// references it. It is not a general Cloudflare SDK.
//
// Design note: we block via a single IP List + a single custom rule
// ("ip.src in $<list>") rather than one custom rule per IP. Custom rules are capped
// (5 on Cloudflare's Free plan - see the README) - a list can hold thousands of entries
// behind that one rule.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

type Client struct {
	AccountID string
	ZoneID    string
	Token     string
	HTTP      *http.Client

	// Base overrides the Cloudflare API base URL (tests point it at an httptest server).
	Base string
}

func (c *Client) base() string {
	if c.Base != "" {
		return c.Base
	}
	return apiBase
}

// APIError is a failed Cloudflare API call, carrying the HTTP status so callers can tell "404, this
// resource doesn't exist" apart from "403 / 5xx / timeout, we don't know" - that distinction decides
// whether it is safe to create something or we must stop.
type APIError struct {
	Status  int
	Message string
	Codes   []int // Cloudflare's own error codes from the response body, e.g. 10019
}

func (e *APIError) Error() string { return e.Message }

// codeListQuota is Cloudflare's "This account is at the maximum number of lists" error.
const codeListQuota = 10019

func hasAPICode(err error, code int) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	for _, c := range ae.Codes {
		if c == code {
			return true
		}
	}
	return false
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
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
	Success    bool             `json:"success"`
	Errors     []apiResponseErr `json:"errors"`
	Result     json.RawMessage  `json:"result"`
	ResultInfo struct {
		Cursors struct {
			After string `json:"after"`
		} `json:"cursors"`
	} `json:"result_info"`
}

type apiResponseErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) do(ctx context.Context, method, url string, body any, out any) error {
	_, err := c.doPage(ctx, method, url, body, out)
	return err
}

// doPage is do that also returns the pagination cursor ("after") of a list response, "" when there is no more.
func (c *Client) doPage(ctx context.Context, method, url string, body any, out any) (string, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var parsed apiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", &APIError{Status: resp.StatusCode, Message: fmt.Sprintf("cloudflare api: non-JSON response (status %d): %s", resp.StatusCode, string(raw))}
	}
	if !parsed.Success {
		codes := make([]int, 0, len(parsed.Errors))
		for _, e := range parsed.Errors {
			codes = append(codes, e.Code)
		}
		return "", &APIError{Status: resp.StatusCode, Codes: codes, Message: fmt.Sprintf("cloudflare api error (status %d): %+v", resp.StatusCode, parsed.Errors)}
	}
	if out != nil && len(parsed.Result) > 0 {
		if err := json.Unmarshal(parsed.Result, out); err != nil {
			return "", err
		}
	}
	return parsed.ResultInfo.Cursors.After, nil
}

// VerifyToken confirms the token is valid at all (it may still lack the specific scopes
// this client needs - TestCapabilities below tests those individually). Corresponds to
// the "API token" test in Cloudflare's dashboard.
func (c *Client) VerifyToken(ctx context.Context) error {
	url := c.base() + "/user/tokens/verify"
	return c.do(ctx, http.MethodGet, url, nil, nil)
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

	// The account's custom lists (Cloudflare limits how many an account may have - a Free account has very
	// few), and what is known about the list the plugin is configured to use.
	ListCount            int           `json:"list_count"`
	Lists                []ListSummary `json:"lists,omitempty"`
	ListKind             string        `json:"list_kind,omitempty"`
	ListReferencedBy     int           `json:"list_referenced_by"`
	ListUsedByOtherRules bool          `json:"list_used_by_other_rules"`

	// RuleCount is how many custom rules the zone already has (Free plans allow 5 in total).
	RuleCount int `json:"rule_count"`

	// RuleNameConflict is true when a rule with exactly the configured WAF rule name already exists and is
	// not this plugin's rule. The plugin will refuse to touch it (see RuleConflictError), so the operator
	// has to pick another name before going live.
	RuleNameConflict bool `json:"rule_name_conflict"`
}

// ListSummary is one custom list in the account, for display in Test Connection.
type ListSummary struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Items        int    `json:"items"`
	ReferencedBy int    `json:"referenced_by"`
}

func summarise(lists []ipList) []ListSummary {
	out := make([]ListSummary, 0, len(lists))
	for _, l := range lists {
		out = append(out, ListSummary{Name: l.Name, Kind: l.Kind, Items: l.NumItems, ReferencedBy: l.NumReferencingFilters})
	}
	return out
}

// TestCapabilities checks token validity and both required scopes without mutating
// anything - the lists check is a plain GET (list access, not creation), and the WAF
// check is a plain GET of the custom-rules phase entrypoint. If listName is non-empty and
// already exists, also reports its current item count (see Config.MaxIPListItems). If
// ruleDescription is non-empty it also reports whether an existing rule would clash with it.
func (c *Client) TestCapabilities(ctx context.Context, listName, ruleDescription, managedRuleID string) CapabilityReport {
	var report CapabilityReport

	if err := c.VerifyToken(ctx); err != nil {
		report.TokenError = err.Error()
		return report // every other call will also fail with an invalid token, don't bother
	}
	report.TokenValid = true

	listsURL := fmt.Sprintf("%s/accounts/%s/rules/lists", c.base(), c.AccountID)
	var lists []ipList
	if err := c.do(ctx, http.MethodGet, listsURL, nil, &lists); err != nil {
		report.ListsError = err.Error()
	} else {
		report.ListsAccess = true
		report.ListCount = len(lists)
		report.Lists = summarise(lists)
		if listName != "" {
			for _, l := range lists {
				if l.Name == listName {
					report.ListExists = true
					report.ListItemCount = l.NumItems
					report.ListKind = l.Kind
					report.ListReferencedBy = l.NumReferencingFilters
					break
				}
			}
		}
	}

	wafURL := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", c.base(), c.ZoneID, firewallCustomPhase)
	var rs ruleset
	err := c.do(ctx, http.MethodGet, wafURL, nil, &rs)
	var apiErr *APIError
	switch {
	case err == nil:
		report.WAFAccess = true
		report.RuleCount = len(rs.Rules)
		ours := false // does this zone already have the plugin's own rule for this list?
		for _, r := range rs.Rules {
			isOurs := (managedRuleID != "" && r.ID == managedRuleID) || (ruleDescription != "" && r.Description == ruleDescription)
			if isOurs && referencesList(r.Expression, listName) {
				ours = true
			}
			if ruleDescription != "" && r.Description == ruleDescription && r.ID != managedRuleID && !referencesList(r.Expression, listName) {
				report.RuleNameConflict = true
			}
		}
		if report.ListExists {
			expected := 0
			if ours {
				expected = 1
			}
			report.ListUsedByOtherRules = report.ListReferencedBy > expected
		}
	case isNotFound(err):
		// 404 here means "this zone has no custom rules yet", not "no access" - a
		// correctly-scoped token gets 404 on a fresh zone just as often as 200.
		report.WAFAccess = true
		report.ListUsedByOtherRules = report.ListExists && report.ListReferencedBy > 0
	case errors.As(err, &apiErr):
		report.WAFError = fmt.Sprintf("HTTP %d - check the token has Zone > WAF > Edit for this zone", apiErr.Status)
	default:
		report.WAFError = err.Error()
	}

	return report
}

type ipList struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
	// NumReferencingFilters is how many rules/filters, in any zone of the account, reference this list.
	NumReferencingFilters int `json:"num_referencing_filters"`
}

// ListQuotaError means Cloudflare refused to create the plugin's list because the account is already at
// its maximum number of custom lists (Cloudflare error 10019).
type ListQuotaError struct {
	ListName string
	Existing []ListSummary
}

func (e *ListQuotaError) Error() string {
	var have []string
	for _, l := range e.Existing {
		have = append(have, fmt.Sprintf("%s (%s, %d item(s), used by %d rule(s))", l.Name, l.Kind, l.Items, l.ReferencedBy))
	}
	existing := "none listed"
	if len(have) > 0 {
		existing = strings.Join(have, "; ")
	}
	return fmt.Sprintf("cannot create the IP list %q: this Cloudflare account is already at its maximum number of custom lists "+
		"(Cloudflare error %d). Existing lists: %s. Free one up - delete an unused list (Cloudflare refuses while any rule in ANY zone of the "+
		"account still uses it) - or set IP list name to an existing IP list that is safe to add blocked IPs to (never an allow list)",
		e.ListName, codeListQuota, existing)
}

// ListIPListItemCount returns the current number of items in the given list, so callers
// can pre-flight check against Cloudflare's list-size cap before attempting an add (see
// Config.MaxIPListItems).
func (c *Client) ListIPListItemCount(ctx context.Context, listID string) (int, error) {
	var l ipList
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s", c.base(), c.AccountID, listID)
	if err := c.do(ctx, http.MethodGet, url, nil, &l); err != nil {
		return 0, fmt.Errorf("getting list %s: %w", listID, err)
	}
	return l.NumItems, nil
}

// EnsureIPList returns the ID of the IP list named listName, creating it if it doesn't
// exist yet.
func (c *Client) EnsureIPList(ctx context.Context, listName string) (string, error) {
	var lists []ipList
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", c.base(), c.AccountID)
	if err := c.do(ctx, http.MethodGet, url, nil, &lists); err != nil {
		return "", fmt.Errorf("listing ip lists: %w", err)
	}
	for _, l := range lists {
		if l.Name == listName {
			if l.Kind != "" && l.Kind != "ip" {
				return "", fmt.Errorf("the list %q exists but is a %q list, not an IP list - choose another IP list name", listName, l.Kind)
			}
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
		if hasAPICode(err, codeListQuota) {
			return "", &ListQuotaError{ListName: listName, Existing: summarise(lists)}
		}
		return "", fmt.Errorf("creating ip list %q: %w", listName, err)
	}
	return result.ID, nil
}

type listItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

type bulkOperation struct {
	OperationID string `json:"operation_id"`
}

// AddIP appends ip to the list, with comment as the audit trail visible in the
// Cloudflare dashboard. It uses the documented "create list items" call (POST .../items, JSON array
// body), which appends and, for an IP already present, just replaces that entry - so re-adding is
// harmless. Cloudflare processes it asynchronously (the response only carries an operation_id); we
// don't wait for it - this plugin's own recent-actions log says "we tried", the Cloudflare
// dashboard says whether it landed.
func (c *Client) AddIP(ctx context.Context, listID, ip, comment string) error {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", c.base(), c.AccountID, listID)
	var op bulkOperation
	if err := c.do(ctx, http.MethodPost, url, []listItem{{IP: ip, Comment: comment}}, &op); err != nil {
		return fmt.Errorf("adding %s to list: %w", ip, err)
	}
	return nil
}

const firewallCustomPhase = "http_request_firewall_custom"

// ListItemInfo is one entry of an IP list as Cloudflare reports it.
type ListItemInfo struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Comment    string `json:"comment"`
	CreatedOn  string `json:"created_on"`
	ModifiedOn string `json:"modified_on"`
}

// FindIPList returns the ID of the named IP list without creating it (used by the expiry pruner, which must
// never create anything).
func (c *Client) FindIPList(ctx context.Context, name string) (string, bool, error) {
	var lists []ipList
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", c.base(), c.AccountID)
	if err := c.do(ctx, http.MethodGet, url, nil, &lists); err != nil {
		return "", false, fmt.Errorf("listing ip lists: %w", err)
	}
	for _, l := range lists {
		if l.Name == name {
			if l.Kind != "" && l.Kind != "ip" {
				return "", false, fmt.Errorf("the list %q is a %q list, not an IP list", name, l.Kind)
			}
			return l.ID, true, nil
		}
	}
	return "", false, nil
}

// ListItems returns the items of a list, following Cloudflare's cursor pagination (500 per page). It stops
// after maxPages pages as a runaway guard and reports an error rather than a silently partial result if the
// list is longer than that, so callers never act on incomplete data.
func (c *Client) ListItems(ctx context.Context, listID string) ([]ListItemInfo, error) {
	const perPage, maxPages = 500, 50
	var all []ListItemInfo
	cursor := ""
	for page := 0; page < maxPages; page++ {
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items?per_page=%d", c.base(), c.AccountID, listID, perPage)
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		var items []ListItemInfo
		after, err := c.doPage(ctx, http.MethodGet, url, nil, &items)
		if err != nil {
			return nil, fmt.Errorf("listing items of %s: %w", listID, err)
		}
		all = append(all, items...)
		if after == "" || after == cursor || len(items) == 0 {
			return all, nil
		}
		cursor = after
	}
	return nil, fmt.Errorf("list %s has more than %d items - refusing to act on a partial view", listID, perPage*maxPages)
}

// DeleteItems removes the given items (by Cloudflare item ID) from the list. It refuses an empty request:
// Cloudflare's replace/delete calls treat "no items" specially in places, and removing nothing must never be
// able to turn into removing everything.
func (c *Client) DeleteItems(ctx context.Context, listID string, ids []string) error {
	if len(ids) == 0 {
		return errors.New("refusing to send a delete with no item IDs")
	}
	type itemRef struct {
		ID string `json:"id"`
	}
	body := struct {
		Items []itemRef `json:"items"`
	}{}
	for _, id := range ids {
		if id == "" {
			return errors.New("refusing to send a delete containing an empty item ID")
		}
		body.Items = append(body.Items, itemRef{ID: id})
	}
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", c.base(), c.AccountID, listID)
	var op bulkOperation
	if err := c.do(ctx, http.MethodDelete, url, body, &op); err != nil {
		return fmt.Errorf("deleting %d item(s) from %s: %w", len(ids), listID, err)
	}
	return nil
}

type ruleset struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Rules []rule `json:"rules"`
}

// rule is the read view of a custom rule plus the small body we write for our own rule. Other rules are
// only ever READ (never re-sent), so fields we don't model - action_parameters, logging, etc. - on the
// operator's own rules are never touched.
type rule struct {
	ID          string `json:"id,omitempty"`
	Expression  string `json:"expression"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

// RuleConflictError means a rule with the configured WAF rule name already exists in the zone but is
// not this plugin's (its expression doesn't reference our list). We refuse to modify it.
type RuleConflictError struct {
	Description string
	RuleID      string
	ListName    string
}

func (e *RuleConflictError) Error() string {
	return fmt.Sprintf("a rule named %q already exists in this zone (id %s) and does not reference $%s, so it is not this plugin's rule - "+
		"not modifying it; choose a different WAF rule name", e.Description, e.RuleID, e.ListName)
}

// referencesList reports whether a rule expression uses the list `$name` (word-boundary match, so
// $foo doesn't count as a reference to $foobar).
func referencesList(expression, listName string) bool {
	if listName == "" {
		return false
	}
	return regexp.MustCompile(`\$` + regexp.QuoteMeta(listName) + `\b`).MatchString(expression)
}

// EnsureBlockRule makes sure exactly one custom rule exists on the zone's
// http_request_firewall_custom phase referencing listName, with the given action
// (block, managed_challenge, js_challenge, challenge or log - validated by the caller) and
// description (shown as the rule's "Name" in Cloudflare's dashboard - the Ruleset Engine API has no
// separate name field). Returns the rule's ID so the caller can persist it.
//
// Safety, in order of importance:
//   - Other rules are never re-sent. Adding uses POST .../rulesets/{id}/rules and editing uses
//     PATCH .../rules/{id}; the whole-list PUT is used only to create the phase's very first rule on a
//     zone that verifiably has none, because a PUT replaces the entire list.
//   - Any failure reading the current rules aborts. Only an explicit 404 (no entrypoint yet) counts as
//     "no rules", and even then we confirm no ruleset exists for the phase before creating one.
//   - Our own rule is recognised by the stored ID first. Without an ID we adopt a rule with the same
//     description only if its expression already references our list; otherwise it is someone else's
//     rule and we return a RuleConflictError instead of overwriting it.
func (c *Client) EnsureBlockRule(ctx context.Context, listName, action, description, existingRuleID string) (string, error) {
	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", c.base(), c.ZoneID, firewallCustomPhase)
	expression := fmt.Sprintf("(ip.src in $%s)", listName)

	var rs ruleset
	if err := c.do(ctx, http.MethodGet, url, nil, &rs); err != nil {
		if !isNotFound(err) {
			return "", fmt.Errorf("reading the zone's custom rules (not writing anything): %w", err)
		}
		return c.createFirstRule(ctx, url, expression, action, description)
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
			if rs.Rules[i].Description != description {
				continue
			}
			if !referencesList(rs.Rules[i].Expression, listName) {
				return "", &RuleConflictError{Description: description, RuleID: rs.Rules[i].ID, ListName: listName}
			}
			match = &rs.Rules[i]
			break
		}
	}

	if match == nil {
		return c.addRule(ctx, rs, expression, action, description)
	}
	if match.Expression == expression && match.Action == action && match.Description == description {
		return match.ID, nil // already correct, nothing to do
	}
	return c.patchRule(ctx, rs.ID, *match, expression, action, description)
}

// createFirstRule handles a 404 on the phase entrypoint. Before writing anything it lists the zone's
// rulesets to confirm none exists for this phase: the create is a whole-list PUT, so if the 404 were
// wrong we would wipe someone's rules.
func (c *Client) createFirstRule(ctx context.Context, entrypointURL, expression, action, description string) (string, error) {
	var all []ruleset
	listURL := fmt.Sprintf("%s/zones/%s/rulesets", c.base(), c.ZoneID)
	if err := c.do(ctx, http.MethodGet, listURL, nil, &all); err != nil {
		return "", fmt.Errorf("entrypoint not found but could not confirm the zone has no custom ruleset (not writing anything): %w", err)
	}
	for _, r := range all {
		if r.Phase == firewallCustomPhase {
			return "", fmt.Errorf("entrypoint reported not found but ruleset %s exists for %s - refusing to overwrite it", r.ID, firewallCustomPhase)
		}
	}

	body := struct {
		Rules []rule `json:"rules"`
	}{Rules: []rule{{Expression: expression, Action: action, Description: description}}}
	var created ruleset
	if err := c.do(ctx, http.MethodPut, entrypointURL, body, &created); err != nil {
		return "", fmt.Errorf("creating the first custom rule: %w", err)
	}
	return findOurRule(created, nil, expression, description)
}

// addRule appends our rule with the single-rule POST; the response is the full ruleset, so the new
// rule's ID is whichever rule wasn't there before.
func (c *Client) addRule(ctx context.Context, before ruleset, expression, action, description string) (string, error) {
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules", c.base(), c.ZoneID, before.ID)
	body := rule{Expression: expression, Action: action, Description: description}
	enabled := true
	body.Enabled = &enabled
	var after ruleset
	if err := c.do(ctx, http.MethodPost, url, body, &after); err != nil {
		return "", fmt.Errorf("adding rule: %w", err)
	}
	known := map[string]bool{}
	for _, r := range before.Rules {
		known[r.ID] = true
	}
	return findOurRule(after, known, expression, description)
}

// patchRule edits only our own rule. Cloudflare wants the complete new definition of that rule, so we
// send action/expression/description and carry over its enabled flag (a rule the operator paused
// stays paused). action_parameters belong to the old action, so they are not carried over.
func (c *Client) patchRule(ctx context.Context, rulesetID string, existing rule, expression, action, description string) (string, error) {
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules/%s", c.base(), c.ZoneID, rulesetID, existing.ID)
	body := rule{Expression: expression, Action: action, Description: description, Enabled: existing.Enabled}
	if err := c.do(ctx, http.MethodPatch, url, body, nil); err != nil {
		return "", fmt.Errorf("updating rule %s: %w", existing.ID, err)
	}
	return existing.ID, nil
}

func findOurRule(rs ruleset, known map[string]bool, expression, description string) (string, error) {
	for _, r := range rs.Rules {
		if !known[r.ID] && r.Expression == expression && r.Description == description {
			return r.ID, nil
		}
	}
	return "", fmt.Errorf("rule with description %q not found in Cloudflare's response after writing it", description)
}
