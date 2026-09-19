// Package blocker is the single funnel every detection source (log tailer, Zoraxy
// blacklist event subscription, future fail2ban integration) feeds into. It owns the
// only logic allowed to decide "does this IP actually get sent to Cloudflare" - so that
// logic exists in exactly one place, not duplicated per detection source.
package blocker

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/ipfilter"
)

// Candidate is a proposed block, from whichever detector noticed it.
type Candidate struct {
	IP     string
	Reason string
	Source string // e.g. "logtail", "blacklist-event"
}

// Action is a completed (or deliberately skipped) decision, kept for the UI's
// recent-actions view.
type Action struct {
	Time   time.Time `json:"time"`
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
	Source string    `json:"source"`
	Result string    `json:"result"` // "blocked" | "dry-run" | "skipped-disabled" | "skipped-duplicate" | "skipped-invalid-ip" | "skipped-list-full" | "error"
	Detail string    `json:"detail,omitempty"`
}

// Deps is read fresh on every candidate so config changes made in the UI take effect
// immediately, without restarting the plugin.
type Deps struct {
	GetEnabled         func() bool
	GetDryRun          func() bool
	GetTTL             func() time.Duration
	GetIPListName      func() string
	GetBlockAction     func() string
	GetRuleDescription func() string
	GetManagedRuleID   func() string
	SetManagedRuleID   func(id string) // persists the rule ID EnsureBlockRule returns, so future syncs match by ID
	GetMaxListItems    func() int
	NewCFClient        func() (*cloudflare.Client, bool) // ok=false if credentials aren't configured yet
}

type Blocker struct {
	deps    Deps
	checker *ipfilter.Checker

	mu      sync.Mutex
	seen    map[string]time.Time // ip -> last actioned time, for dedup
	history []Action             // ring buffer, newest last
}

const historyLimit = 200

func New(deps Deps, checker *ipfilter.Checker) *Blocker {
	return &Blocker{
		deps:    deps,
		checker: checker,
		seen:    make(map[string]time.Time),
	}
}

func (b *Blocker) History() []Action {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Action, len(b.history))
	copy(out, b.history)
	return out
}

func (b *Blocker) record(a Action) {
	b.mu.Lock()
	b.history = append(b.history, a)
	if len(b.history) > historyLimit {
		b.history = b.history[len(b.history)-historyLimit:]
	}
	b.mu.Unlock()

	// Every outcome goes to the journal too (Zoraxy captures plugin stdout), so `journalctl -u zoraxy`
	// shows what the plugin is doing and it survives a restart - the UI table is in-memory only.
	// skipped-duplicate is left out: a scanner hammering one IP would flood the journal, and the first
	// hit for that IP already has its line (the UI table still lists every one).
	if a.Result != "skipped-duplicate" {
		detail := ""
		if a.Detail != "" {
			detail = fmt.Sprintf(" detail=%q", a.Detail)
		}
		log.Printf("action: %s ip=%s source=%s reason=%q%s", a.Result, a.IP, a.Source, a.Reason, detail)
	}
}

// Submit evaluates one candidate and, if warranted, calls Cloudflare. Safe to call
// concurrently from multiple detectors.
func (b *Blocker) Submit(ctx context.Context, c Candidate) {
	now := time.Now()
	action := Action{Time: now, IP: c.IP, Reason: c.Reason, Source: c.Source}

	ip, ok := b.checker.IsValidBlockCandidate(c.IP)
	if !ok {
		action.Result = "skipped-invalid-ip"
		action.Detail = "not a public, non-Cloudflare address"
		b.record(action)
		return
	}
	normalizedIP := ip.String()
	action.IP = normalizedIP

	if !b.deps.GetEnabled() {
		action.Result = "skipped-disabled"
		b.record(action)
		return
	}

	b.mu.Lock()
	if last, dup := b.seen[normalizedIP]; dup && now.Sub(last) < b.deps.GetTTL() {
		b.mu.Unlock()
		action.Result = "skipped-duplicate"
		action.Detail = fmt.Sprintf("already actioned %s ago", now.Sub(last).Round(time.Second))
		b.record(action)
		return
	}
	b.seen[normalizedIP] = now
	b.mu.Unlock()

	if b.deps.GetDryRun() {
		action.Result = "dry-run"
		action.Detail = "would have added to " + b.deps.GetIPListName()
		b.record(action)
		return
	}

	client, ok := b.deps.NewCFClient()
	if !ok {
		action.Result = "error"
		action.Detail = "cloudflare credentials not configured"
		b.record(action)
		return
	}

	listID, err := client.EnsureIPList(ctx, b.deps.GetIPListName())
	if err != nil {
		action.Result = "error"
		action.Detail = err.Error()
		b.record(action)
		return
	}

	// Pre-flight against Cloudflare's list-size cap (Free/Pro/Business: 10,000 items
	// total across all custom lists - see Config.MaxIPListItems). Checked live, right
	// before the add, rather than cached: blocks are rare enough (thanks to the dedup
	// TTL above) that one extra read here per real block is cheap, and it's always
	// accurate rather than staleness-prone.
	if count, err := client.ListIPListItemCount(ctx, listID); err != nil {
		log.Printf("block %s: list size check failed (continuing anyway): %v", normalizedIP, err)
	} else if max := b.deps.GetMaxListItems(); max > 0 && count >= max {
		action.Result = "skipped-list-full"
		action.Detail = fmt.Sprintf("list %s has %d/%d items", b.deps.GetIPListName(), count, max)
		b.record(action)
		return
	}

	if newRuleID, err := client.EnsureBlockRule(ctx, b.deps.GetIPListName(), b.deps.GetBlockAction(), b.deps.GetRuleDescription(), b.deps.GetManagedRuleID()); err != nil {
		// Non-fatal: the list membership below still protects, just via whatever rule
		// (if any) already references this list. Surface it, don't abort the add.
		log.Printf("block %s: ensure rule (continuing anyway): %v", normalizedIP, err)
	} else if newRuleID != b.deps.GetManagedRuleID() {
		b.deps.SetManagedRuleID(newRuleID)
	}

	comment := fmt.Sprintf("zoraxy/%s: %s", c.Source, c.Reason)
	if len(comment) > 100 { // Cloudflare list item comments are capped
		comment = comment[:100]
	}
	if err := client.AddIP(ctx, listID, normalizedIP, comment); err != nil {
		action.Result = "error"
		action.Detail = err.Error()
		b.record(action)
		return
	}

	action.Result = "blocked"
	b.record(action)
}
