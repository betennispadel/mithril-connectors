package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runNewsData(ctx context.Context, cfg *PensieveConfig, target string, targetType string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Get multilingual queries
	queries := getSearchQueries(ctx, target, targetType)
	if len(queries) == 0 {
		queries = []string{target}
	}

	// NewsData supports language param — use all languages
	languages := "en,ru,zh,ar,es,de,fr,pt,tr"
	seen := make(map[string]bool)

	for _, q := range queries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoint := fmt.Sprintf("https://newsdata.io/api/1/news?apikey=%s&q=%s&language=%s&category=technology",
			url.QueryEscape(cfg.NewsDataApiKey), url.QueryEscape(q), languages)

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NewsData error: %v\n", err)
			continue
		}

		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}

		var result struct {
			Results []struct {
				Title       string `json:"title"`
				Link        string `json:"link"`
				Description string `json:"description"`
				PubDate     string `json:"pubDate"`
				Source      string `json:"source_id"`
				Language    string `json:"language"`
			} `json:"results"`
		}

		if json.Unmarshal(data, &result) != nil {
			continue
		}

		for _, r := range result.Results {
			if seen[r.Link] {
				continue
			}
			seen[r.Link] = true

			// Score severity by content
			severity := "info"
			lower := strings.ToLower(r.Title + " " + r.Description)
			if strings.Contains(lower, "breach") || strings.Contains(lower, "ransomware") || strings.Contains(lower, "leaked") {
				severity = "high"
			} else if strings.Contains(lower, "phishing") || strings.Contains(lower, "hack") || strings.Contains(lower, "attack") {
				severity = "medium"
			} else if strings.Contains(lower, "vulnerability") || strings.Contains(lower, "exploit") {
				severity = "low"
			}

			category := "social-monitor"
			if strings.Contains(lower, "phishing") || strings.Contains(lower, "impersonat") {
				category = "brand-protection"
			} else if strings.Contains(lower, "breach") || strings.Contains(lower, "leak") {
				category = "data-leak"
			}

			lang := r.Language
			if lang == "" {
				lang = "en"
			}

			tags := []string{category, "pensieve", "news", r.Source, "lang:" + lang}

			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("News: %s", truncate(r.Title, 60)),
				Severity:    severity,
				Description: fmt.Sprintf("News from %s (%s): %s — %s", r.Source, lang, r.Title, truncate(r.Description, 300)),
				MatchedAt:   r.Link,
				Tags:        tags,
				References:  []string{r.Link},
				Fingerprint: fingerprint("pensieve", "newsdata", r.Link),
			}) {
				return
			}
		}
	}
}
