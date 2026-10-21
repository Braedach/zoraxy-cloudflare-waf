package blocker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func act(i int, result string) Action {
	return Action{Time: time.Date(2026, 10, 21, 12, 0, i, 0, time.UTC), IP: fmt.Sprintf("203.0.113.%d", i%250+1), Reason: "r", Source: "logtail", Result: result}
}

func TestHistory_RoundTripKeepsOrderAndLimit(t *testing.T) {
	s := OpenHistoryStore(filepath.Join(t.TempDir(), "a.jsonl"), 1<<20)
	for i := 0; i < 10; i++ {
		if err := s.Append(act(i, "blocked")); err != nil {
			t.Fatal(err)
		}
	}
	got := s.Load(4)
	if len(got) != 4 || got[0].IP != "203.0.113.7" || got[3].IP != "203.0.113.10" {
		t.Fatalf("want the last 4 oldest-first (.7 to .10), got %+v", got)
	}
	if all := s.Load(0); len(all) != 10 {
		t.Fatalf("limit 0 means everything, got %d", len(all))
	}
}

func TestHistory_FileIsPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	s := OpenHistoryStore(p, 1<<20)
	if err := s.Append(act(1, "blocked")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0600 {
		t.Errorf("history must be mode 0600, got %v", fi.Mode().Perm())
	}
}

func TestHistory_RotatesAndLoadsAcrossBothFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	s := OpenHistoryStore(p, 400) // tiny cap so a few lines force rotation
	for i := 0; i < 30; i++ {
		if err := s.Append(act(i, "blocked")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatal("expected a rotated file")
	}
	if _, err := os.Stat(p + ".2"); err == nil {
		t.Error("only one rotated copy may exist")
	}
	got := s.Load(0)
	if len(got) == 0 || len(got) >= 30 {
		t.Fatalf("older entries beyond the two files must be dropped, kept %d of 30", len(got))
	}
	last := got[len(got)-1]
	if last.IP != act(29, "").IP {
		t.Errorf("newest entry must be last, got %s", last.IP)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Time.Before(got[i-1].Time) {
			t.Fatal("entries must stay in time order across the rotation boundary")
		}
	}
	fi, _ := os.Stat(p)
	fi1, _ := os.Stat(p + ".1")
	if fi.Size() > 400+200 || fi1.Size() > 400+200 {
		t.Errorf("files must stay near the cap: %d and %d", fi.Size(), fi1.Size())
	}
}

func TestHistory_SkipsUnreadableLinesWithoutLosingTheRest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	s := OpenHistoryStore(p, 1<<20)
	_ = s.Append(act(1, "blocked"))
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("this is not json\n{\"time\":\"2026-10-21T12:00:09Z\",\"ip\":\"\"}\n{\"torn\":") // garbage, an entry with no IP, and a torn last line
	f.Close()
	s = OpenHistoryStore(p, 1<<20) // "restart": the file now ends in a torn, newline-less line
	_ = s.Append(act(2, "blocked"))
	got := s.Load(0)
	if len(got) != 2 || got[0].IP != "203.0.113.2" || got[1].IP != "203.0.113.3" {
		t.Fatalf("expected exactly the two good entries (the one after the torn line must not be glued to it), got %+v", got)
	}
}

func TestHistory_AFailingDiskNeverStopsRecording(t *testing.T) {
	bad := OpenHistoryStore(filepath.Join(t.TempDir(), "no-such-dir", "a.jsonl"), 1<<20)
	if err := bad.Append(act(1, "blocked")); err == nil {
		t.Fatal("expected an error writing into a missing directory")
	}
	b := New(Deps{History: bad}, nil)
	b.record(act(1, "blocked")) // must not panic or block
	b.record(act(2, "blocked"))
	if got := b.History(); len(got) != 2 {
		t.Fatalf("the in-memory history must still hold both actions, got %d", len(got))
	}
}

func TestBlocker_RestoresHistoryAfterARestart_AndSkipsDuplicates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	b1 := New(Deps{History: OpenHistoryStore(p, 1<<20)}, nil)
	b1.record(act(1, "blocked"))
	b1.record(act(2, "skipped-duplicate"))
	b1.record(act(3, "expired"))

	b2 := New(Deps{History: OpenHistoryStore(p, 1<<20)}, nil) // "restart": a new Blocker over the same file
	got := b2.History()
	if len(got) != 2 || got[0].Result != "blocked" || got[1].Result != "expired" {
		t.Fatalf("restart must restore the persisted actions (not the duplicate), got %+v", got)
	}
	if len(b2.seen) != 0 {
		t.Error("dedup state must start empty after a restart so a restart never suppresses a block")
	}
}

func TestBlocker_RestoreIsBoundedByTheDisplayLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	s := OpenHistoryStore(p, 10<<20)
	for i := 0; i < historyLimit+50; i++ {
		_ = s.Append(act(i, "blocked"))
	}
	if got := New(Deps{History: OpenHistoryStore(p, 10<<20)}, nil).History(); len(got) != historyLimit {
		t.Fatalf("the UI buffer holds %d, restored %d", historyLimit, len(got))
	}
}

func TestHistory_ConcurrentAppendsAreSafe(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	s := OpenHistoryStore(p, 4096)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = s.Append(act(g*50+i, "blocked"))
			}
		}(g)
	}
	wg.Wait()
	for _, a := range s.Load(0) {
		if !strings.HasPrefix(a.IP, "203.0.113.") {
			t.Fatalf("a torn or interleaved line produced a bad entry: %+v", a)
		}
	}
}
