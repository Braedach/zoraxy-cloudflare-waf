// Command zoraxy-cloudflare-waf is a Zoraxy plugin (PluginType_Utilities - it never sits
// in the live proxy path) that watches Zoraxy's own access log and blacklist events for
// abusive clients, and mirrors them into a Cloudflare IP List so Cloudflare's edge blocks
// them before they ever reach this reverse proxy again.
//
// See README.md for setup. See internal/blocker, internal/logtail and internal/cloudflare
// for the three pieces this wires together.
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Braedach/zoraxy-cloudflare-waf/internal/blocker"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/cloudflare"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/ipfilter"
	"github.com/Braedach/zoraxy-cloudflare-waf/internal/logtail"
	plugin "github.com/Braedach/zoraxy-cloudflare-waf/mod/zoraxy_plugin"
	"github.com/Braedach/zoraxy-cloudflare-waf/mod/zoraxy_plugin/events"
)

const (
	PLUGIN_ID   = "com.braedach.zoraxy.cloudflarewaf"
	UI_PATH     = "/ui"
	EVENT_PATH  = "/events"
	CONFIG_FILE = "cloudflarewaf.json"
)

//go:embed www/*
var wwwFS embed.FS

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            PLUGIN_ID,
		Name:          "Zoraxy Cloudflare WAF plugin",
		Author:        "Braedach",
		AuthorContact: "https://github.com/Braedach",
		Description:   "Watches Zoraxy's access log and blacklist events, and mirrors abusive client IPs into a Cloudflare IP List referenced by a custom WAF rule.",
		URL:           "https://github.com/Braedach/zoraxy-cloudflare-waf",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  0,
		VersionMinor:  1,
		VersionPatch:  0,

		UIPath: UI_PATH,

		SubscriptionPath: EVENT_PATH,
		SubscriptionsEvents: map[string]string{
			string(events.EventBlacklistedIPBlocked): "Mirror an IP Zoraxy's own access-rule blacklist just blocked into the Cloudflare IP list immediately.",
		},
	})
	if err != nil {
		fmt.Println("This is a plugin for Zoraxy and should not be run standalone. Visit https://zoraxy.aroz.org to download Zoraxy.")
		panic(err)
	}

	cfgStore, err := loadConfigStore(CONFIG_FILE)
	if err != nil {
		panic(fmt.Errorf("loading %s: %w", CONFIG_FILE, err))
	}
	log.Printf("zoraxy-cloudflare-waf starting against Zoraxy %s (uuid %s)", runtimeCfg.RuntimeConst.ZoraxyVersion, runtimeCfg.RuntimeConst.ZoraxyUUID)
	logConfigSummary("loaded config", cfgStore.get())

	checker := ipfilter.NewChecker()
	go refreshCloudflareRangesForever(checker)

	deps := blocker.Deps{
		GetEnabled:         func() bool { return cfgStore.get().Enabled },
		GetDryRun:          func() bool { return cfgStore.get().DryRun },
		GetTTL:             func() time.Duration { return time.Duration(cfgStore.get().BlockTTLHours) * time.Hour },
		GetIPListName:      func() string { return cfgStore.get().IPListName },
		GetBlockAction:     func() string { return cfgStore.get().BlockAction },
		GetRuleDescription: func() string { return cfgStore.get().RuleDescription },
		GetManagedRuleID:   func() string { return cfgStore.get().ManagedRuleID },
		SetManagedRuleID: func(id string) {
			c := cfgStore.get()
			c.ManagedRuleID = id
			if err := cfgStore.set(c); err != nil {
				log.Printf("persisting managed_rule_id: %v", err)
			}
		},
		GetMaxListItems: func() int { return cfgStore.get().MaxIPListItems },
		NewCFClient: func() (*cloudflare.Client, bool) {
			c := cfgStore.get()
			if !c.Configured() {
				return nil, false
			}
			return cloudflare.New(c.CloudflareAccountID, c.CloudflareZoneID, c.CloudflareAPIToken), true
		},
	}
	blk := blocker.New(deps, checker)

	startLogTailer(cfgStore, blk)
	registerEventSubscriber(cfgStore, blk)
	registerUI(cfgStore, blk)

	serverAddr := "127.0.0.1:" + strconv.Itoa(runtimeCfg.Port)
	log.Printf("zoraxy-cloudflare-waf listening on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		panic(err)
	}
}

func refreshCloudflareRangesForever(checker *ipfilter.Checker) {
	// First refresh shortly after startup (give networking a moment to settle), then
	// daily - Cloudflare's published ranges change rarely, this is just hygiene against
	// staleness, not something latency-sensitive.
	time.Sleep(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := checker.Refresh(ctx); err != nil {
			log.Printf("ipfilter: refresh cloudflare ranges failed, keeping previous set: %v", err)
		}
		cancel()
		time.Sleep(24 * time.Hour)
	}
}

func startLogTailer(cfgStore *configStore, blk *blocker.Blocker) {
	cfg := cfgStore.get()
	t := logtail.New(logtail.Config{
		LogDir:        cfg.ZoraxyLogDir,
		WindowSeconds: cfg.RateLimitWindowSeconds,
		Threshold:     cfg.RateLimitThreshold,
	}, func(c logtail.Candidate) {
		blk.Submit(context.Background(), blocker.Candidate{IP: c.IP, Reason: c.Reason, Source: "logtail"})
	})
	// Changing log directory / window / threshold in the UI takes effect on next plugin
	// restart (Zoraxy's plugin manager can restart a plugin without a full reboot) - v1
	// keeps the tailer's own config static after start rather than hot-reloading mid-file.
	go t.Run(nil)
}

func registerEventSubscriber(cfgStore *configStore, blk *blocker.Blocker) {
	http.HandleFunc(EVENT_PATH+"/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !cfgStore.get().ReactToBlacklistEvent {
			w.WriteHeader(http.StatusOK)
			return
		}

		defer r.Body.Close()
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(r.Body); err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		var ev events.Event
		if err := events.ParseEvent(buf.Bytes(), &ev); err != nil {
			http.Error(w, "failed to parse event: "+err.Error(), http.StatusBadRequest)
			return
		}

		if data, ok := ev.Data.(*events.BlacklistedIPBlockedEvent); ok {
			reason := fmt.Sprintf("zoraxy blacklist blocked (%s %s)", data.Method, data.RequestedURL)
			blk.Submit(r.Context(), blocker.Candidate{IP: data.IP, Reason: reason, Source: "blacklist-event"})
		}

		w.WriteHeader(http.StatusOK)
	})
}

func registerUI(cfgStore *configStore, blk *blocker.Blocker) {
	uiRouter := plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &wwwFS, "/www", UI_PATH)
	uiRouter.RegisterTerminateHandler(func() {
		log.Println("zoraxy-cloudflare-waf terminating on Zoraxy's request")
	}, nil)

	uiRouter.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, struct {
			Config  Config           `json:"config"`
			History []blocker.Action `json:"history"`
		}{Config: redactedConfig(cfgStore.get()), History: blk.History()})
	}, nil)

	uiRouter.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var incoming Config
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		current := cfgStore.get()
		// A blank token in the incoming payload means "leave the stored one alone" -
		// the redacted GET response never round-trips the real token back to the form.
		if incoming.CloudflareAPIToken == "" {
			incoming.CloudflareAPIToken = current.CloudflareAPIToken
		}
		// managed_rule_id is bookkeeping the blocker owns (see SetManagedRuleID) - the
		// form never sends it, so always carry the stored value forward rather than
		// letting a save silently wipe it and orphan the rule Cloudflare already has.
		incoming.ManagedRuleID = current.ManagedRuleID

		if incoming.BlockAction == "" {
			incoming.BlockAction = defaultConfig().BlockAction
		}
		if !validBlockAction(incoming.BlockAction) {
			http.Error(w, fmt.Sprintf("invalid block_action %q: must be one of %s", incoming.BlockAction, strings.Join(validBlockActions, ", ")), http.StatusBadRequest)
			return
		}

		// Server-side enforcement of "must be tested before it can run for real" -
		// mirrors the UI's own gating but doesn't rely on it, since the UI can be
		// bypassed by anyone hitting this endpoint directly.
		if incoming.Enabled && !incoming.Configured() {
			http.Error(w, "cannot enable: cloudflare_api_token, cloudflare_account_id and cloudflare_zone_id must all be set first", http.StatusBadRequest)
			return
		}

		if err := cfgStore.set(incoming); err != nil {
			http.Error(w, "failed to save: "+err.Error(), http.StatusInternalServerError)
			return
		}
		logConfigSummary("config saved", incoming)
		writeJSON(w, redactedConfig(cfgStore.get()))
	}, nil)

	uiRouter.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Accepts the same shape as /api/config so the UI can test credentials the user
		// just typed, before saving them - a blank token in the request means "test the
		// currently saved one" instead.
		var incoming struct {
			CloudflareAPIToken  string `json:"cloudflare_api_token"`
			CloudflareAccountID string `json:"cloudflare_account_id"`
			CloudflareZoneID    string `json:"cloudflare_zone_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		current := cfgStore.get()
		token := incoming.CloudflareAPIToken
		if token == "" {
			token = current.CloudflareAPIToken
		}
		if token == "" || incoming.CloudflareAccountID == "" || incoming.CloudflareZoneID == "" {
			http.Error(w, "api token, account id and zone id are all required to test", http.StatusBadRequest)
			return
		}
		client := cloudflare.New(incoming.CloudflareAccountID, incoming.CloudflareZoneID, token)
		report := client.TestCapabilities(r.Context(), current.IPListName)
		log.Printf("test connection: token_valid=%v lists_access=%v waf_access=%v list_exists=%v",
			report.TokenValid, report.ListsAccess, report.WAFAccess, report.ListExists)
		writeJSON(w, report)
	}, nil)

	uiRouter.AttachHandlerToMux(nil)
}

// logConfigSummary writes the settings that decide whether the plugin acts, never the credentials
// themselves (only whether they are present).
func logConfigSummary(prefix string, c Config) {
	log.Printf("%s: enabled=%v dry_run=%v block_action=%s ip_list=%s react_to_blacklist=%v log_dir=%s credentials_set=%v",
		prefix, c.Enabled, c.DryRun, c.BlockAction, c.IPListName, c.ReactToBlacklistEvent, c.ZoraxyLogDir, c.Configured())
}

func redactedConfig(c Config) Config {
	if c.CloudflareAPIToken != "" {
		c.CloudflareAPIToken = "•••• (set)"
	}
	return c
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}
