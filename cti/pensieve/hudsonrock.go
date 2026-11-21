package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runHudsonRock(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=%s",
		url.QueryEscape(target))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("api-key", cfg.HudsonRockApiKey)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hudson Rock error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		Stealers []struct {
			DateCompromised string `json:"date_compromised"`
			ComputerName    string `json:"computer_name"`
			OperatingSystem string `json:"operating_system"`
			MalwareFamily   string `json:"malware_path"`
			IP              string `json:"ip"`
			TopLogins       []struct {
				URL      string `json:"url"`
				Username string `json:"username"`
			} `json:"top_logins"`
		} `json:"stealers"`
	}

	if json.Unmarshal(data, &result) != nil {
		return
	}

	for _, s := range result.Stealers {
		desc := fmt.Sprintf("Stealer log found for '%s'.", target)
		if s.DateCompromised != "" {
			desc += fmt.Sprintf(" Compromised: %s.", s.DateCompromised)
		}
		if s.ComputerName != "" {
			desc += fmt.Sprintf(" Machine: %s (%s).", s.ComputerName, s.OperatingSystem)
		}
		if len(s.TopLogins) > 0 {
			desc += fmt.Sprintf(" Affected logins: %d.", len(s.TopLogins))
		}

		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Stealer Log: %s", truncate(target, 40)),
			Severity:    "critical",
			Description: desc,
			MatchedAt:   target,
			Tags:        []string{"data-leak", "pensieve", "stealer", "hudsonrock", "fraud"},
			References:  []string{"https://cavalier.hudsonrock.com"},
			Fingerprint: fingerprint("pensieve", "hudsonrock", target, s.DateCompromised),
		}) {
			return
		}
	}
}
