package blocker

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"sync"
)

// HistoryStore keeps the plugin's action history on disk as one JSON object per line (JSONL), so the "Recent actions" view and the
// operator's records survive a restart (Zoraxy restarts weekly when it self-updates, which used to empty the in-memory table).
//
// It is deliberately simple and cannot get in the way of a ban:
//   - append-only; a write error is logged once and ignored (the in-memory history and the journal still have the action);
//   - size-capped: when the file would pass maxBytes it is renamed to <path>.1 (replacing any older one) and a new file starts,
//     so at most about 2*maxBytes is ever used;
//   - mode 0600, and it holds only what the journal already shows (time, address, reason, source, result, detail): no credentials.
type HistoryStore struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	size     int64
	failed   bool // a write error has been logged and not yet recovered from
	needNL   bool // the file does not end in a newline (a crash tore the last line): start the next entry on a fresh line
}

// OpenHistoryStore prepares the store. It never fails: a missing file is an empty history, and any problem later is logged.
func OpenHistoryStore(path string, maxBytes int64) *HistoryStore {
	s := &HistoryStore{path: path, maxBytes: maxBytes}
	if fi, err := os.Stat(path); err == nil {
		s.size = fi.Size()
		if s.size > 0 {
			if f, err := os.Open(path); err == nil {
				last := make([]byte, 1)
				if _, err := f.ReadAt(last, s.size-1); err == nil && last[0] != '\n' {
					s.needNL = true
				}
				f.Close()
			}
		}
	}
	return s
}

// Load returns up to limit of the most recent actions, oldest first, reading the rotated file and then the current one. Lines that
// do not parse are skipped (a torn last line after a crash must not lose the rest).
func (s *HistoryStore) Load(limit int) []Action {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []Action
	skipped := 0
	for _, p := range []string{s.path + ".1", s.path} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var a Action
			if err := json.Unmarshal(sc.Bytes(), &a); err != nil || a.IP == "" {
				skipped++
				continue
			}
			all = append(all, a)
		}
		f.Close()
	}
	if skipped > 0 {
		log.Printf("history: skipped %d unreadable line(s) in %s", skipped, s.path)
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all
}

// Append writes one action. Errors are returned (so tests can see them) but callers treat them as non-fatal.
func (s *HistoryStore) Append(a Action) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxBytes > 0 && s.size > 0 && s.size+int64(len(raw)) > s.maxBytes {
		_ = os.Remove(s.path + ".1")
		if err := os.Rename(s.path, s.path+".1"); err != nil {
			return err
		}
		s.size = 0
		s.needNL = false
	}
	if s.needNL {
		raw = append([]byte{'\n'}, raw...) // without this the new entry would be glued to the torn line and lost
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, werr := f.Write(raw)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	s.size += int64(n)
	s.needNL = false
	return cerr
}

// noteResult logs the first failure and the recovery, so a full disk cannot flood the journal.
func (s *HistoryStore) noteResult(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err != nil && !s.failed:
		s.failed = true
		log.Printf("history: cannot write %s: %v (actions are still in memory and the journal; further errors are not repeated)", s.path, err)
	case err == nil && s.failed:
		s.failed = false
		log.Printf("history: writing %s works again", s.path)
	}
}
