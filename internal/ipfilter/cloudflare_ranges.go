// Package ipfilter answers two questions this plugin needs to get right before it ever
// touches Cloudflare's API:
//
//  1. Is a candidate "client IP" actually a routable public address, and not a private/
//     loopback/link-local one that leaked in because a header was missing or spoofed?
//  2. Is a candidate "client IP" actually one of Cloudflare's own edge IPs? If so, it is
//     never a real visitor - it means whatever extracted the "client" field fell back to
//     the wrong header (X-Forwarded-For instead of CF-Connecting-IP) and blocking it would
//     firewall off Cloudflare's own edge, not an attacker.
//
// See Proxmox/LXC/Scripts/setup-lxc-proxy.sh in the homelab repo: "the real client IP is
// the CF-Connecting-IP HTTP header" - X-Forwarded-For is attacker-controlled on tunnel
// traffic and must never be trusted for blocking decisions.
package ipfilter

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// fallbackCloudflareRanges is used if the live fetch from cloudflare.com fails (e.g. no
// egress yet, or Cloudflare's own endpoint is briefly unreachable). Sourced from
// https://www.cloudflare.com/ips-v4 / ips-v6. Refreshed automatically once the fetch
// succeeds - this is only ever the starting point, never assumed to stay accurate forever.
var fallbackCloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

type Checker struct {
	mu     sync.RWMutex
	ranges []*net.IPNet
	client *http.Client
}

func NewChecker() *Checker {
	c := &Checker{client: &http.Client{Timeout: 10 * time.Second}}
	c.setRanges(fallbackCloudflareRanges)
	return c
}

// Refresh re-fetches Cloudflare's published ranges. Call periodically (e.g. daily) - not
// on every request, this is not latency-sensitive since it only gates outbound API calls,
// never the live proxy path.
func (c *Checker) Refresh(ctx context.Context) error {
	v4, err4 := c.fetchList(ctx, "https://www.cloudflare.com/ips-v4")
	v6, err6 := c.fetchList(ctx, "https://www.cloudflare.com/ips-v6")
	if err4 != nil && err6 != nil {
		return err4
	}
	combined := append(v4, v6...)
	if len(combined) == 0 {
		return err4
	}
	c.setRanges(combined)
	return nil
}

func (c *Checker) fetchList(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}

func (c *Checker) setRanges(cidrs []string) {
	var parsed []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			parsed = append(parsed, network)
		}
	}
	if len(parsed) == 0 {
		return
	}
	c.mu.Lock()
	c.ranges = parsed
	c.mu.Unlock()
}

// IsCloudflareIP reports whether ip belongs to Cloudflare's own edge network.
func (c *Checker) IsCloudflareIP(ip net.IP) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, network := range c.ranges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsValidBlockCandidate reports whether ip is safe to hand to Cloudflare as a block
// target: a syntactically valid public address that is neither private/loopback/
// link-local nor part of Cloudflare's own edge network.
func (c *Checker) IsValidBlockCandidate(ipStr string) (net.IP, bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return nil, false
	}
	if c.IsCloudflareIP(ip) {
		return nil, false
	}
	return ip, true
}
