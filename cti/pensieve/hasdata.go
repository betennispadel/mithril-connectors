package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runHasData(ctx context.Context, cfg *PensieveConfig, target string, targetType string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Get multilingual queries from query_builder
	queries := getSearchQueries(ctx, target, targetType)
	if len(queries) == 0 {
		// Fallback: just use raw target
		queries = []string{target}
	}

	seen := make(map[string]bool)

	for _, q := range queries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoint := fmt.Sprintf("https://api.hasdata.com/scrape/google?q=%s&domain=google.com&lang=en",
			url.QueryEscape(q))

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("x-api-key", cfg.HasDataApiKey)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HasData error: %v\n", err)
			continue
		}

		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}

		var result struct {
			OrganicResults []struct {
				Title   string `json:"title"`
				Link    string `json:"link"`
				Snippet string `json:"snippet"`
			} `json:"organicResults"`
		}

		if json.Unmarshal(data, &result) != nil {
			continue
		}

		for _, r := range result.OrganicResults {
			if seen[r.Link] {
				continue
			}
			seen[r.Link] = true

			// Score severity by content signals
			severity := "info"
			lower := strings.ToLower(r.Title + " " + r.Snippet)
			if strings.Contains(lower, "breach") || strings.Contains(lower, "ransomware") || strings.Contains(lower, "leaked") {
				severity = "high"
			} else if strings.Contains(lower, "phishing") || strings.Contains(lower, "hack") || strings.Contains(lower, "vulnerability") {
				severity = "medium"
			} else if strings.Contains(lower, "attack") || strings.Contains(lower, "exploit") || strings.Contains(lower, "scam") {
				severity = "low"
			}

			// Categorize
			category := "social-monitor"
			if strings.Contains(lower, "phishing") || strings.Contains(lower, "impersonat") || strings.Contains(lower, "fake") {
				category = "brand-protection"
			} else if strings.Contains(lower, "breach") || strings.Contains(lower, "leak") || strings.Contains(lower, "credential") {
				category = "data-leak"
			}

			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("SERP: %s", truncate(r.Title, 60)),
				Severity:    severity,
				Description: fmt.Sprintf("Google result for '%s': %s — %s", target, r.Title, truncate(r.Snippet, 300)),
				MatchedAt:   r.Link,
				Tags:        []string{category, "pensieve", "serp", "hasdata"},
				References:  []string{r.Link},
				Fingerprint: fingerprint("pensieve", "hasdata", r.Link),
			}) {
				return
			}
		}
	}
}

// getSearchQueries calls query_builder.py to get multilingual queries
func getSearchQueries(ctx context.Context, target string, targetType string) []string {
	cmd := exec.CommandContext(ctx, "python3", "/usr/local/bin/query_builder.py",
		"--target", target, "--type", targetType, "--flat")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var queries []string
	json.Unmarshal(out, &queries)
	return queries
}
