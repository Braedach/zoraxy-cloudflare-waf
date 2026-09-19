// Package logtail follows Zoraxy's own monthly access log and turns suspicious activity
// into blocker.Candidate values. It never touches the live proxy path - this is a
// read-only file follower, so a bug here can slow down its own detection, never break
// serving traffic.
//
// Log format and field names (zr_YYYY-M.log, [client: ip], [origin: ...], [useragent:
// ...], [router:ratelimit], [router:whitelist], trailing "METHOD /path STATUS") are taken
// from Proxmox/LXC/Scripts/forensic-report-zoraxy-v2.sh in the homelab repo, which
// reverse-engineered them from real Zoraxy output before this plugin existed.
package logtail

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var (
	clientRe = regexp.MustCompile(`\[client: ([^\]]+)\]`)
	statusRe = regexp.MustCompile(`\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) (\d{3})\b`)

	// Same probe/exploit pattern set as the forensic report script's "Exploit / Probe
	// Attempts" section - kept in sync deliberately so a human reading both tools sees
	// the same definition of "suspicious".
	exploitRe = regexp.MustCompile(`(?i)(\.\./|%2e%2e|cmd=|exec=|eval\(|<script|union.*select|/etc/passwd|/bin/sh|169\.254\.169\.254|file%3a%2f%2f|file://|\.azure/credentials|\.azure/accessTokens|/actuator/env|/actuator/|\.env\.backup|\.env\.prod|dump\.sql|terraform\.tfstate)`)
)

// Candidate mirrors blocker.Candidate's shape without importing it, so this package has
// no dependency on the blocker package - main.go wires the two together.
type Candidate struct {
	IP     string
	Reason string
}

type Config struct {
	LogDir        string
	WindowSeconds int
	Threshold     int
	PollInterval  time.Duration
}

type Tailer struct {
	cfg     Config
	onEvent func(Candidate)

	mu      sync.Mutex
	windows map[string][]time.Time // ip -> timestamps of recent noisy statuses, for the sliding window
}

func New(cfg Config, onEvent func(Candidate)) *Tailer {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Tailer{
		cfg:     cfg,
		onEvent: onEvent,
		windows: make(map[string][]time.Time),
	}
}

// Run blocks, following the current month's log file and rolling over automatically at
// month boundaries. Intended to be run in its own goroutine.
func (t *Tailer) Run(stop <-chan struct{}) {
	var (
		file    *os.File
		reader  *bufio.Reader
		curPath string
	)
	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	ticker := time.NewTicker(t.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		expectedPath := t.currentLogPath()
		if expectedPath != curPath {
			// Month rolled over (or first run, or config changed underneath us).
			newFile, err := os.Open(expectedPath)
			if err != nil {
				// Not necessarily an error - the new month's file may not exist yet in
				// the first seconds of the month, or LogDir may be misconfigured.
				continue
			}
			if file != nil {
				file.Close()
			}
			file = newFile
			// Start from EOF: we only want new activity from the moment this plugin
			// started watching, not a re-detection sweep of the entire month's history
			// every time it restarts.
			if _, err := file.Seek(0, io.SeekEnd); err != nil {
				log.Printf("logtail: seek to end of %s: %v", expectedPath, err)
			}
			reader = bufio.NewReader(file)
			curPath = expectedPath
		}

		if reader == nil {
			continue
		}

		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				t.handleLine(line)
			}
			if err != nil {
				break // caught up to EOF, wait for next tick
			}
		}
	}
}

func (t *Tailer) currentLogPath() string {
	now := time.Now()
	// Matches the bash forensic report script's `date '+%Y-%-m'` - no zero-padded month.
	return filepath.Join(t.cfg.LogDir, fmt.Sprintf("zr_%d-%d.log", now.Year(), int(now.Month())))
}

func (t *Tailer) handleLine(line string) {
	clientMatch := clientRe.FindStringSubmatch(line)
	if clientMatch == nil {
		return
	}
	ip := clientMatch[1]

	if exploitRe.MatchString(line) {
		t.onEvent(Candidate{IP: ip, Reason: "exploit-pattern-match in request line"})
		return
	}

	statusMatch := statusRe.FindStringSubmatch(line)
	if statusMatch == nil {
		return
	}
	status, err := strconv.Atoi(statusMatch[3])
	if err != nil || status < 400 {
		return // only 4xx/5xx count toward the noisy-client threshold
	}

	if t.recordNoisyAndCheckThreshold(ip) {
		t.onEvent(Candidate{
			IP:     ip,
			Reason: fmt.Sprintf("more than %d 4xx/5xx responses within %ds", t.cfg.Threshold, t.cfg.WindowSeconds),
		})
	}
}

// recordNoisyAndCheckThreshold returns true the first time ip crosses the threshold
// within the current window; it won't fire again for the same ip until the window's
// entries age out and it re-crosses, since the blocker package's own dedup TTL is what
// actually prevents repeat Cloudflare calls - this just prevents pointless bookkeeping
// growth here.
func (t *Tailer) recordNoisyAndCheckThreshold(ip string) bool {
	now := time.Now()
	window := time.Duration(t.cfg.WindowSeconds) * time.Second

	t.mu.Lock()
	defer t.mu.Unlock()

	events := t.windows[ip]
	cutoff := now.Add(-window)
	kept := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	t.windows[ip] = kept

	crossed := len(kept) == t.cfg.Threshold // fire exactly once per crossing, not on every subsequent hit
	if len(kept) > t.cfg.Threshold*2 {
		// Safety valve: forget ancient history for an IP that's been noisy for a very
		// long time so this map entry can't grow unbounded.
		t.windows[ip] = kept[len(kept)-t.cfg.Threshold:]
	}
	return crossed
}
