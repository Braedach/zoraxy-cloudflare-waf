package blocker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare"
)

// Target is one Cloudflare destination: an account's IP list, plus the custom rule that references that list in each of the
// target's zones. A plain install has exactly one target with one zone, which is the only shape older versions knew; a release
// that supports several accounts and zones just has more of them. Everything is read through functions so a change made in the
// UI takes effect on the next block without a restart.
type Target struct {
	Label        string // shown in actions and logs when there is more than one target; "" for the single legacy target
	AccountKey   string // identifies the Cloudflare account, so two targets sharing a list are only pruned once
	IPListName   string
	BlockAction  string
	RuleName     string
	MaxListItems int
	Zones        []string // at least one; the first is also used for the list calls
	NewClient    func(zone string) (*cloudflare.Client, bool)
	GetRuleID    func(zone string) string
	SetRuleID    func(zone, id string)
}

// targets returns the Cloudflare targets to act on. With no GetTargets dependency it wraps the original single-target
// dependencies, so the single-account behaviour (and its tests) is exactly the code path below with one target.
func (b *Blocker) targets() []Target {
	if b.deps.GetTargets != nil {
		return b.deps.GetTargets()
	}
	return []Target{{
		IPListName:   b.deps.GetIPListName(),
		BlockAction:  b.deps.GetBlockAction(),
		RuleName:     b.deps.GetRuleDescription(),
		MaxListItems: b.deps.GetMaxListItems(),
		Zones:        []string{""},
		NewClient:    func(string) (*cloudflare.Client, bool) { return b.deps.NewCFClient() },
		GetRuleID:    func(string) string { return b.deps.GetManagedRuleID() },
		SetRuleID:    func(_, id string) { b.deps.SetManagedRuleID(id) },
	}}
}

func targetName(t Target) string {
	if t.Label == "" {
		return t.IPListName
	}
	return t.Label + ":" + t.IPListName
}

func shortZone(z string) string {
	if len(z) > 8 {
		return z[:8]
	}
	return z
}

// blockAtCloudflare blocks the IP at every configured target and combines the outcomes. With one target the result is that
// target's own result unchanged. With several, one failing target never stops the others: the layer is "partial" when some
// worked and some did not, and the detail says which. Caller holds cfMu.
func (b *Blocker) blockAtCloudflare(ctx context.Context, ip string, c Candidate) layerResult {
	ts := b.targets()
	if len(ts) == 0 {
		return layerResult{state: layerOff, detail: "cloudflare credentials not configured"}
	}
	if len(ts) == 1 {
		return b.blockAtTarget(ctx, ip, c, ts[0])
	}

	var parts []string
	good, bad, absent, full := 0, 0, 0, 0
	for _, t := range ts {
		r := b.blockAtTarget(ctx, ip, c, t)
		switch r.state {
		case layerOK:
			good++
		case layerOff:
			absent++
		case layerListFull:
			bad++
			full++
		default: // failed or partial
			bad++
			if r.state == layerPartial {
				good++ // some of this target's zones are protected
			}
		}
		parts = append(parts, t.Label+": "+orOK(r.detail))
	}
	detail := strings.Join(parts, "; ")
	switch {
	case bad == 0 && good > 0:
		return layerResult{state: layerOK, detail: detail}
	case bad == 0 && good == 0:
		return layerResult{state: layerOff, detail: "cloudflare credentials not configured"}
	case good > 0:
		return layerResult{state: layerPartial, detail: detail}
	case full == bad:
		return layerResult{state: layerListFull, detail: detail}
	default:
		return layerResult{state: layerFailed, detail: detail}
	}
}

// blockAtTarget: ensure list -> size guard -> ensure the rule in each zone -> add IP.
func (b *Blocker) blockAtTarget(ctx context.Context, ip string, c Candidate, t Target) layerResult {
	client, ok := t.NewClient(t.Zones[0])
	if !ok {
		return layerResult{state: layerOff, detail: "cloudflare credentials not configured"}
	}

	listID, err := client.EnsureIPList(ctx, t.IPListName)
	if err != nil {
		return layerResult{state: layerFailed, detail: err.Error()}
	}

	// Pre-flight against Cloudflare's list-size cap (Free/Pro/Business: 10,000 items total across all custom lists - see
	// Config.MaxIPListItems). Checked live, right before the add, rather than cached: blocks are rare enough (thanks to the
	// dedup TTL) that one extra read here per real block is cheap, and it's always accurate rather than staleness-prone.
	if count, err := client.ListIPListItemCount(ctx, listID); err != nil {
		log.Printf("block %s: list size check failed (continuing anyway): %v", ip, err)
	} else if max := t.MaxListItems; max > 0 && count >= max {
		return layerResult{state: layerListFull, detail: fmt.Sprintf("list %s has %d/%d items", t.IPListName, count, max)}
	}

	var conflicts []string
	ensured := 0
	for _, zone := range t.Zones {
		zc := client
		if zone != t.Zones[0] {
			var ok bool
			if zc, ok = t.NewClient(zone); !ok {
				conflicts = append(conflicts, "zone "+shortZone(zone)+": cloudflare credentials not configured")
				continue
			}
		}
		newRuleID, err := zc.EnsureBlockRule(ctx, t.IPListName, t.BlockAction, t.RuleName, t.GetRuleID(zone))
		if err != nil {
			var conflict *cloudflare.RuleConflictError
			if errors.As(err, &conflict) {
				// Someone else's rule has our name. We won't touch it, and adding IPs to a list nothing references would only
				// look like protection - report it loudly instead.
				msg := err.Error()
				if len(t.Zones) > 1 {
					msg = "zone " + shortZone(zone) + ": " + msg
				}
				conflicts = append(conflicts, msg)
				continue
			}
			// Non-fatal: the list membership below still protects, just via whatever rule (if any) already references this
			// list. Surface it, don't abort the add.
			log.Printf("block %s: ensure rule (continuing anyway): %v", ip, err)
			ensured++
			continue
		}
		ensured++
		if newRuleID != t.GetRuleID(zone) {
			t.SetRuleID(zone, newRuleID)
		}
	}
	if ensured == 0 && len(conflicts) > 0 {
		return layerResult{state: layerFailed, detail: strings.Join(conflicts, "; ")}
	}

	comment := fmt.Sprintf("zoraxy/%s: %s", c.Source, c.Reason)
	if len(comment) > 100 { // Cloudflare list item comments are capped
		comment = comment[:100]
	}
	if err := client.AddIP(ctx, listID, ip, comment); err != nil {
		return layerResult{state: layerFailed, detail: err.Error()}
	}
	if len(conflicts) > 0 {
		// The address is on the list and protects the zones whose rule is ours; say which zones are not covered.
		return layerResult{state: layerPartial, detail: strings.Join(conflicts, "; ")}
	}
	return layerResult{state: layerOK}
}

// pruneCloudflare removes expired blocks from every distinct list across the targets (two targets that share an account and
// list name are handled once).
func (b *Blocker) pruneCloudflare(ctx context.Context, cutoff time.Time, days int) []string {
	var removed []string
	seen := map[string]bool{}
	for _, t := range b.targets() {
		key := t.AccountKey + "/" + t.IPListName
		if seen[key] {
			continue
		}
		seen[key] = true
		removed = append(removed, b.pruneTarget(ctx, t, cutoff, days)...)
	}
	return removed
}
