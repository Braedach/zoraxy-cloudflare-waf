// Package zoraxy is a deliberately small client for the few Zoraxy REST endpoints this plugin is permitted to
// call (they are declared in the plugin's permitted_api_endpoints, which Zoraxy shows to the operator):
// list access rules, and list / add / remove entries of an access rule's IP blacklist.
//
// Zoraxy quirks handled here (verified against Zoraxy's source, src/accesslist.go and src/mod/utils):
//   - success is the JSON string "OK"; failures are HTTP 200 with {"error":"..."} - the status code alone
//     says nothing;
//   - the add call reads ip/id from the form body but "comment" from the URL query;
//   - the list call returns bare IP strings - no comments and no timestamps, so anything that needs to know
//     when an IP was banned (expiry) has to be tracked by the caller.
package zoraxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Endpoint paths (the plugin API is Zoraxy's /api/... mounted under /plugin).
const (
	PathAccessList      = "/plugin/api/access/list"
	PathBlacklistList   = "/plugin/api/blacklist/list"
	PathBlacklistAdd    = "/plugin/api/blacklist/ip/add"
	PathBlacklistRemove = "/plugin/api/blacklist/ip/remove"
)

type Client struct {
	BaseURL string // e.g. http://127.0.0.1:81
	APIKey  string
	HTTP    *http.Client
}

func New(port int, apiKey string) *Client {
	return &Client{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// AccessRule is the subset of Zoraxy's access rule the plugin cares about.
type AccessRule struct {
	ID                             string `json:"ID"`
	Name                           string `json:"Name"`
	Desc                           string `json:"Desc"`
	BlacklistEnabled               bool   `json:"BlacklistEnabled"`
	WhitelistEnabled               bool   `json:"WhitelistEnabled"`
	WhitelistAllowLocalAndLoopback bool   `json:"WhitelistAllowLocalAndLoopback"`
	TrustProxyHeadersOnly          bool   `json:"TrustProxyHeadersOnly"`
}

// APIError is a failed Zoraxy call.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

var ruleIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func (c *Client) do(ctx context.Context, method, path string, query, form url.Values) ([]byte, error) {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Zoraxy %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &APIError{Status: resp.StatusCode, Message: fmt.Sprintf("Zoraxy refused the plugin API call %s (HTTP %d) - the plugin's API "+
			"permissions have not been granted or its API key is missing; restart Zoraxy so it issues the plugin a key", path, resp.StatusCode)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Message: fmt.Sprintf("Zoraxy %s returned HTTP %d", path, resp.StatusCode)}
	}
	// Zoraxy reports failures as HTTP 200 + {"error":"..."}
	var probe struct {
		Error string `json:"error"`
	}
	if trimmed := strings.TrimSpace(string(raw)); strings.HasPrefix(trimmed, "{") && json.Unmarshal(raw, &probe) == nil && probe.Error != "" {
		return nil, &APIError{Status: resp.StatusCode, Message: fmt.Sprintf("Zoraxy %s: %s", path, probe.Error)}
	}
	return raw, nil
}

// ListAccessRules returns every access rule (id, name and the flags that decide whether a ban can work).
func (c *Client) ListAccessRules(ctx context.Context) ([]AccessRule, error) {
	raw, err := c.do(ctx, http.MethodGet, PathAccessList, nil, nil)
	if err != nil {
		return nil, err
	}
	var rules []AccessRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("unexpected Zoraxy access-rule list: %w", err)
	}
	return rules, nil
}

// SanitizeComment makes attacker-influenced text safe to store as a Zoraxy blacklist comment: control characters
// and angle brackets removed, whitespace collapsed, capped in length.
func SanitizeComment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f || r == '<' || r == '>':
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if r := []rune(out); len(r) > 150 {
		out = string(r[:150])
	}
	return out
}

func checkArgs(ruleID, ip string) error {
	if !ruleIDRe.MatchString(ruleID) {
		return fmt.Errorf("invalid access rule id %q", ruleID)
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return fmt.Errorf("refusing to ban %q: not a single IP address", ip)
	}
	return nil
}

func expectOK(raw []byte, path string) error {
	if strings.TrimSpace(string(raw)) != `"OK"` {
		return fmt.Errorf("unexpected response from Zoraxy %s: %.80s", path, string(raw))
	}
	return nil
}

// BanIP adds one IP to the blacklist of the given access rule (adding one that is already there is harmless).
func (c *Client) BanIP(ctx context.Context, ruleID, ip, comment string) error {
	if err := checkArgs(ruleID, ip); err != nil {
		return err
	}
	comment = SanitizeComment(comment)
	raw, err := c.do(ctx, http.MethodPost, PathBlacklistAdd,
		url.Values{"comment": {comment}}, // Zoraxy reads the comment from the query string
		url.Values{"ip": {ip}, "id": {ruleID}, "comment": {comment}})
	if err != nil {
		return err
	}
	return expectOK(raw, PathBlacklistAdd)
}

// UnbanIP removes one IP from the blacklist of the given access rule.
func (c *Client) UnbanIP(ctx context.Context, ruleID, ip string) error {
	if err := checkArgs(ruleID, ip); err != nil {
		return err
	}
	raw, err := c.do(ctx, http.MethodPost, PathBlacklistRemove, nil, url.Values{"ip": {ip}, "id": {ruleID}})
	if err != nil {
		return err
	}
	return expectOK(raw, PathBlacklistRemove)
}

// ListBannedIPs returns the IPs in an access rule's blacklist (no comments or dates - Zoraxy doesn't expose them).
func (c *Client) ListBannedIPs(ctx context.Context, ruleID string) ([]string, error) {
	if !ruleIDRe.MatchString(ruleID) {
		return nil, fmt.Errorf("invalid access rule id %q", ruleID)
	}
	raw, err := c.do(ctx, http.MethodGet, PathBlacklistList, url.Values{"type": {"ip"}, "id": {ruleID}}, nil)
	if err != nil {
		return nil, err
	}
	var ips []string
	if err := json.Unmarshal(raw, &ips); err != nil {
		return nil, fmt.Errorf("unexpected Zoraxy blacklist response: %w", err)
	}
	return ips, nil
}
