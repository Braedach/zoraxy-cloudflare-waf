package blocker

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

// BanRecord is one IP the plugin banned in Zoraxy's own blacklist: which access rules, and when. Zoraxy's list call
// returns bare IPs with no dates, so this is the only record of when to expire a ban - and of which entries the
// plugin owns, so it never removes one an operator added by hand.
type BanRecord struct {
	Rules    []string  `json:"rules"`
	BannedAt time.Time `json:"banned_at"`
}

// BanStore persists the plugin's Zoraxy bans (a small JSON file next to the plugin binary).
type BanStore struct {
	mu   sync.Mutex
	path string
	m    map[string]BanRecord
}

// LoadBanStore reads path (a missing file is an empty store). An unreadable/corrupt file is moved aside rather than
// overwritten, so nothing is lost silently, and the store starts empty.
func LoadBanStore(path string) *BanStore {
	s := &BanStore{path: path, m: map[string]BanRecord{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("bans: cannot read %s: %v (starting empty)", path, err)
		}
		return s
	}
	if err := json.Unmarshal(raw, &s.m); err != nil {
		aside := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, aside); rerr != nil {
			log.Printf("bans: %s is corrupt (%v) and could not be moved aside: %v", path, err, rerr)
		} else {
			log.Printf("bans: %s is corrupt (%v) - moved to %s, starting empty", path, err, aside)
		}
		s.m = map[string]BanRecord{}
	}
	return s
}

func (s *BanStore) saveLocked() error {
	raw, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Record notes that ip was banned in the given rules at time at (a re-ban refreshes the clock and merges the rules).
func (s *BanStore) Record(ip string, rules []string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.m[ip]
	have := map[string]bool{}
	for _, r := range rec.Rules {
		have[r] = true
	}
	for _, r := range rules {
		if !have[r] {
			rec.Rules = append(rec.Rules, r)
		}
	}
	sort.Strings(rec.Rules)
	rec.BannedAt = at
	s.m[ip] = rec
	return s.saveLocked()
}

// Older returns the records banned before cutoff (a copy, oldest first via the returned key order).
func (s *BanStore) Older(cutoff time.Time) (ips []string, recs map[string]BanRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs = map[string]BanRecord{}
	for ip, r := range s.m {
		if r.BannedAt.Before(cutoff) {
			recs[ip] = BanRecord{Rules: append([]string(nil), r.Rules...), BannedAt: r.BannedAt}
			ips = append(ips, ip)
		}
	}
	sort.Slice(ips, func(i, j int) bool { return recs[ips[i]].BannedAt.Before(recs[ips[j]].BannedAt) })
	return ips, recs
}

// Resolve marks rules as no longer banned for ip; the record is dropped when none remain.
func (s *BanStore) Resolve(ip string, removed []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[ip]
	if !ok {
		return nil
	}
	gone := map[string]bool{}
	for _, r := range removed {
		gone[r] = true
	}
	var left []string
	for _, r := range rec.Rules {
		if !gone[r] {
			left = append(left, r)
		}
	}
	if len(left) == 0 {
		delete(s.m, ip)
	} else {
		rec.Rules = left
		s.m[ip] = rec
	}
	return s.saveLocked()
}

// Len reports how many IPs are currently tracked.
func (s *BanStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
