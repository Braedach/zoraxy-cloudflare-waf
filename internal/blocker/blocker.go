// Package blocker is the single funnel every detection source (log tailer, Zoraxy
// blacklist event subscription, future fail2ban integration) feeds into. It owns the
// only logic allowed to decide "does this IP actually get sent to Cloudflare" - so that
// logic exists in exactly one place, not duplicated per detection source.
package blocker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/ipfilter"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/zoraxy"
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
	Result string    `json:"result"` // "blocked" | "partial" | "dry-run" | "expired" | "skipped-disabled" | "skipped-duplicate" | "skipped-invalid-ip" | "skipped-list-full" | "error"
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

	// Optional layers (nil = behave as if off): block expiry, and bans in Zoraxy's own blacklist.
	GetExpiryDays       func() int
	GetZoraxyBanEnabled func() bool
	GetZoraxyRules      func() []string
	NewZoraxyClient     func() (*zoraxy.Client, bool) // ok=false if the plugin has no Zoraxy API key
	Bans                *BanStore                     // what the plugin banned in Zoraxy, and when (for expiry)
}

type Blocker struct {
	deps    Deps
	checker *ipfilter.Checker

	mu      sync.Mutex
	seen    map[string]time.Time // ip -> last actioned time, for dedup
	history []Action             // ring buffer, newest last

	// cfMu serialises the live Cloudflare section (ensure list -> ensure rule -> add IP). Detectors call
	// Submit concurrently; without this two first-ever blocks could both create the WAF rule.
	cfMu sync.Mutex
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

// layerState is the outcome of one blocking layer (Cloudflare, or Zoraxy's own blacklist).
type layerState int

const (
	layerOff      layerState = iota // not configured / not enabled - the layer is simply absent
	layerOK                         // done
	layerFailed                     // tried and failed
	layerListFull                   // Cloudflare list at the plugin's own cap (Cloudflare layer only)
)

type layerResult struct {
	state  layerState
	detail string
}

func (b *Blocker) zoraxyEnabled() bool {
	return b.deps.GetZoraxyBanEnabled != nil && b.deps.GetZoraxyBanEnabled()
}

func (b *Blocker) zoraxyRules() []string {
	if b.deps.GetZoraxyRules == nil {
		return nil
	}
	return b.deps.GetZoraxyRules()
}

func (b *Blocker) expiryDays() int {
	if b.deps.GetExpiryDays == nil {
		return 0
	}
	return b.deps.GetExpiryDays()
}

// Submit evaluates one candidate and, if warranted, blocks it in every enabled layer. Safe to call
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
		if b.zoraxyEnabled() {
			action.Detail += "; would ban in Zoraxy access rule(s): " + strings.Join(b.zoraxyRules(), ", ")
		}
		b.record(action)
		return
	}

	b.cfMu.Lock()
	defer b.cfMu.Unlock()

	cf := b.blockAtCloudflare(ctx, normalizedIP, c)
	zx := layerResult{state: layerOff}
	if b.zoraxyEnabled() {
		zx = b.banInZoraxy(ctx, normalizedIP, c, now)
	}
	action.Result, action.Detail = combine(cf, zx)
	b.record(action)
}

// combine turns the two layers' outcomes into one action result. With Zoraxy banning off it reproduces the
// Cloudflare-only results exactly (blocked / skipped-list-full / error).
func combine(cf, zx layerResult) (result, detail string) {
	if zx.state == layerOff {
		switch cf.state {
		case layerOK:
			return "blocked", cf.detail
		case layerListFull:
			return "skipped-list-full", cf.detail
		default:
			return "error", cf.detail
		}
	}

	var parts []string
	if cf.state != layerOff {
		parts = append(parts, "cloudflare: "+orOK(cf.detail))
	}
	parts = append(parts, "zoraxy: "+orOK(zx.detail))
	detail = strings.Join(parts, "; ")

	cfGood := cf.state == layerOK
	cfAbsent := cf.state == layerOff
	zxGood := zx.state == layerOK
	switch {
	case zxGood && (cfGood || cfAbsent):
		return "blocked", detail
	case zxGood || cfGood:
		return "partial", detail
	default:
		return "error", detail
	}
}

func orOK(s string) string {
	if s == "" {
		return "ok"
	}
	return s
}

// blockAtCloudflare: ensure list -> size guard -> ensure rule -> add IP. Caller holds cfMu.
func (b *Blocker) blockAtCloudflare(ctx context.Context, ip string, c Candidate) layerResult {
	client, ok := b.deps.NewCFClient()
	if !ok {
		return layerResult{state: layerOff, detail: "cloudflare credentials not configured"}
	}

	listID, err := client.EnsureIPList(ctx, b.deps.GetIPListName())
	if err != nil {
		return layerResult{state: layerFailed, detail: err.Error()}
	}

	// Pre-flight against Cloudflare's list-size cap (Free/Pro/Business: 10,000 items
	// total across all custom lists - see Config.MaxIPListItems). Checked live, right
	// before the add, rather than cached: blocks are rare enough (thanks to the dedup
	// TTL) that one extra read here per real block is cheap, and it's always
	// accurate rather than staleness-prone.
	if count, err := client.ListIPListItemCount(ctx, listID); err != nil {
		log.Printf("block %s: list size check failed (continuing anyway): %v", ip, err)
	} else if max := b.deps.GetMaxListItems(); max > 0 && count >= max {
		return layerResult{state: layerListFull, detail: fmt.Sprintf("list %s has %d/%d items", b.deps.GetIPListName(), count, max)}
	}

	if newRuleID, err := client.EnsureBlockRule(ctx, b.deps.GetIPListName(), b.deps.GetBlockAction(), b.deps.GetRuleDescription(), b.deps.GetManagedRuleID()); err != nil {
		var conflict *cloudflare.RuleConflictError
		if errors.As(err, &conflict) {
			// Someone else's rule has our name. We won't touch it, and adding IPs to a list nothing
			// references would only look like protection - report it loudly instead.
			return layerResult{state: layerFailed, detail: err.Error()}
		}
		// Non-fatal: the list membership below still protects, just via whatever rule
		// (if any) already references this list. Surface it, don't abort the add.
		log.Printf("block %s: ensure rule (continuing anyway): %v", ip, err)
	} else if newRuleID != b.deps.GetManagedRuleID() {
		b.deps.SetManagedRuleID(newRuleID)
	}

	comment := fmt.Sprintf("zoraxy/%s: %s", c.Source, c.Reason)
	if len(comment) > 100 { // Cloudflare list item comments are capped
		comment = comment[:100]
	}
	if err := client.AddIP(ctx, listID, ip, comment); err != nil {
		return layerResult{state: layerFailed, detail: err.Error()}
	}
	return layerResult{state: layerOK}
}

// banInZoraxy adds the IP to the blacklist of every selected Zoraxy access rule and remembers it for expiry.
// Caller holds cfMu (which also serialises Zoraxy calls).
func (b *Blocker) banInZoraxy(ctx context.Context, ip string, c Candidate, now time.Time) layerResult {
	if b.deps.NewZoraxyClient == nil {
		return layerResult{state: layerFailed, detail: "Zoraxy API not available"}
	}
	zc, ok := b.deps.NewZoraxyClient()
	if !ok {
		return layerResult{state: layerFailed, detail: "Zoraxy API not available (the plugin has no API key - restart Zoraxy so it issues one after the permissions are granted)"}
	}
	rules := b.zoraxyRules()
	if len(rules) == 0 {
		return layerResult{state: layerFailed, detail: "no Zoraxy access rule selected"}
	}

	names := map[string]zoraxy.AccessRule{}
	if all, err := zc.ListAccessRules(ctx); err != nil {
		log.Printf("block %s: could not list Zoraxy access rules (banning anyway): %v", ip, err)
	} else {
		for _, r := range all {
			names[r.ID] = r
		}
	}

	comment := "zoraxy-cloudflare-waf: " + c.Reason
	var okRules, failures, notes []string
	for _, id := range rules {
		label := id
		if r, known := names[id]; known && r.Name != "" {
			label = r.Name
		}
		if err := zc.BanIP(ctx, id, ip, comment); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		okRules = append(okRules, id)
		if r, known := names[id]; known && !r.BlacklistEnabled {
			notes = append(notes, fmt.Sprintf("rule %q has its blacklist switched OFF - the ban has no effect until you enable it", label))
		}
	}

	if len(okRules) > 0 && b.deps.Bans != nil {
		if err := b.deps.Bans.Record(ip, okRules, now); err != nil {
			log.Printf("block %s: could not record the Zoraxy ban for expiry: %v", ip, err)
		}
	}

	var detail []string
	if len(okRules) > 0 {
		detail = append(detail, fmt.Sprintf("banned in %d access rule(s)", len(okRules)))
	}
	detail = append(detail, notes...)
	detail = append(detail, failures...)
	if len(failures) > 0 {
		return layerResult{state: layerFailed, detail: strings.Join(detail, "; ")}
	}
	return layerResult{state: layerOK, detail: strings.Join(detail, "; ")}
}

// Pruning removes what this plugin blocked long enough ago. Bounded per run so a surprise (say, a mis-set expiry)
// can never empty a list in one go: the rest follows on later runs.
const (
	maxPrunePerRun = 200
	pruneBatch     = 100
	ownedPrefix    = "zoraxy/" // comment prefix of Cloudflare list items this plugin added
)

// PruneExpired removes blocks older than the configured expiry, in every layer that holds them. It only runs live
// (enabled, not dry-run), only touches entries the plugin created, and does nothing on any read failure.
func (b *Blocker) PruneExpired(ctx context.Context, now time.Time) {
	days := b.expiryDays()
	if days <= 0 || !b.deps.GetEnabled() || b.deps.GetDryRun() {
		return
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)

	b.cfMu.Lock()
	defer b.cfMu.Unlock()

	var removed []string
	removed = append(removed, b.pruneCloudflare(ctx, cutoff, days)...)
	removed = append(removed, b.pruneZoraxy(ctx, cutoff, days)...)

	if len(removed) > 0 {
		shown := removed
		if len(shown) > 10 {
			shown = append(append([]string(nil), shown[:10]...), fmt.Sprintf("+%d more", len(removed)-10))
		}
		b.record(Action{Time: now, IP: fmt.Sprintf("%d IP(s)", len(removed)), Source: "expiry", Result: "expired",
			Reason: fmt.Sprintf("blocked more than %d days ago", days), Detail: strings.Join(shown, ", ")})
	}
}

func (b *Blocker) pruneCloudflare(ctx context.Context, cutoff time.Time, days int) []string {
	client, ok := b.deps.NewCFClient()
	if !ok {
		return nil
	}
	listID, found, err := client.FindIPList(ctx, b.deps.GetIPListName())
	if err != nil {
		log.Printf("expiry: cloudflare: %v (nothing removed)", err)
		return nil
	}
	if !found {
		return nil
	}
	items, err := client.ListItems(ctx, listID)
	if err != nil {
		log.Printf("expiry: cloudflare: %v (nothing removed)", err)
		return nil
	}

	type due struct{ id, ip string }
	var dueItems []due
	owned := 0
	for _, it := range items {
		if !strings.HasPrefix(it.Comment, ownedPrefix) {
			continue // not ours - never touch entries an operator added
		}
		owned++
		ts, err := time.Parse(time.RFC3339, firstNonEmpty(it.ModifiedOn, it.CreatedOn))
		if err != nil {
			continue // can't tell how old it is - leave it
		}
		if ts.Before(cutoff) {
			dueItems = append(dueItems, due{id: it.ID, ip: it.IP})
		}
	}
	if len(dueItems) == 0 {
		// Say so: a silent pruner can't be told apart from one that never ran.
		log.Printf("expiry: checked %d Cloudflare list item(s), %d added by this plugin, none older than %d days", len(items), owned, days)
		return nil
	}
	if len(dueItems) > maxPrunePerRun {
		log.Printf("expiry: cloudflare: %d item(s) are due, removing %d now and the rest on later runs", len(dueItems), maxPrunePerRun)
		dueItems = dueItems[:maxPrunePerRun]
	}

	var removed []string
	for start := 0; start < len(dueItems); start += pruneBatch {
		end := start + pruneBatch
		if end > len(dueItems) {
			end = len(dueItems)
		}
		ids := make([]string, 0, end-start)
		for _, d := range dueItems[start:end] {
			ids = append(ids, d.id)
		}
		if err := client.DeleteItems(ctx, listID, ids); err != nil {
			log.Printf("expiry: cloudflare: %v (stopping)", err)
			break
		}
		for _, d := range dueItems[start:end] {
			removed = append(removed, d.ip)
		}
	}
	if len(removed) > 0 {
		log.Printf("expiry: removed %d Cloudflare list item(s) not renewed for %d days from %s", len(removed), days, b.deps.GetIPListName())
	}
	return removed
}

func (b *Blocker) pruneZoraxy(ctx context.Context, cutoff time.Time, days int) []string {
	if b.deps.Bans == nil || b.deps.NewZoraxyClient == nil {
		return nil
	}
	ips, recs := b.deps.Bans.Older(cutoff)
	if len(ips) == 0 {
		if n := b.deps.Bans.Len(); n > 0 {
			log.Printf("expiry: tracking %d Zoraxy ban(s), none older than %d days", n, days)
		}
		return nil
	}
	zc, ok := b.deps.NewZoraxyClient()
	if !ok {
		log.Printf("expiry: zoraxy: %d ban(s) are due for removal but the Zoraxy API is not available (kept)", len(ips))
		return nil
	}
	if len(ips) > maxPrunePerRun {
		ips = ips[:maxPrunePerRun]
	}
	var removed []string
	for _, ip := range ips {
		var done []string
		for _, rule := range recs[ip].Rules {
			if err := zc.UnbanIP(ctx, rule, ip); err != nil {
				log.Printf("expiry: zoraxy: unban %s in %q: %v (kept, will retry)", ip, rule, err)
				continue
			}
			done = append(done, rule)
		}
		if len(done) > 0 {
			if err := b.deps.Bans.Resolve(ip, done); err != nil {
				log.Printf("expiry: zoraxy: recording removal of %s: %v", ip, err)
			}
		}
		if len(done) == len(recs[ip].Rules) {
			removed = append(removed, ip)
		}
	}
	if len(removed) > 0 {
		log.Printf("expiry: removed %d Zoraxy ban(s) older than %d days", len(removed), days)
	}
	return removed
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
