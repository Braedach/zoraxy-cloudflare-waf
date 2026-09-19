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

type ipList struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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
// ("block" or "managed_challenge"). It never touches any other rule in that phase - your
// existing manually-authored rules (Google Cloud Services, Block Crawlers, etc.) are left
// exactly as-is; this only adds or updates its own rule, matched by description.
func (c *Client) EnsureBlockRule(ctx context.Context, listName, action string) error {
	const phase = "http_request_firewall_custom"
	const managedDescription = "zoraxy-cloudflare-waf: managed IP list block (do not hand-edit, see plugin UI)"

	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", apiBase, c.ZoneID, phase)

	var rs ruleset
	err := c.do(ctx, http.MethodGet, url, nil, &rs)
	notFound := err != nil // a zone with zero custom rules yet returns a 404 for the phase entrypoint

	expression := fmt.Sprintf("(ip.src in $%s)", listName)

	if !notFound {
		for _, r := range rs.Rules {
			if r.Description == managedDescription {
				if r.Expression == expression && r.Action == action {
					return nil // already correct, nothing to do
				}
				return c.updateRule(ctx, phase, rs.Rules, r.ID, expression, action, managedDescription)
			}
		}
		return c.appendRule(ctx, phase, rs.Rules, expression, action, managedDescription)
	}

	// No entrypoint ruleset exists yet on this zone for this phase - create one with
	// just our rule.
	return c.createEntrypoint(ctx, phase, expression, action, managedDescription)
}

func (c *Client) updateRule(ctx context.Context, phase string, existing []rule, ruleID, expression, action, description string) error {
	updated := make([]rule, 0, len(existing))
	for _, r := range existing {
		if r.ID == ruleID {
			r.Expression = expression
			r.Action = action
			r.Description = description
		}
		updated = append(updated, r)
	}
	return c.putEntrypoint(ctx, phase, updated)
}

func (c *Client) appendRule(ctx context.Context, phase string, existing []rule, expression, action, description string) error {
	updated := append(existing, rule{Expression: expression, Action: action, Description: description})
	return c.putEntrypoint(ctx, phase, updated)
}

func (c *Client) createEntrypoint(ctx context.Context, phase, expression, action, description string) error {
	return c.putEntrypoint(ctx, phase, []rule{{Expression: expression, Action: action, Description: description}})
}

func (c *Client) putEntrypoint(ctx context.Context, phase string, rules []rule) error {
	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/%s/entrypoint", apiBase, c.ZoneID, phase)
	body := struct {
		Rules []rule `json:"rules"`
	}{Rules: rules}
	return c.do(ctx, http.MethodPut, url, body, nil)
}
