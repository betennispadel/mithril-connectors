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

func runHasData(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://api.hasdata.com/scrape/google?q=%s&domain=google.com&lang=en",
		url.QueryEscape(target))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("x-api-key", cfg.HasDataApiKey)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HasData error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		OrganicResults []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
		} `json:"organicResults"`
	}

	if json.Unmarshal(data, &result) != nil {
		return
	}

	for _, r := range result.OrganicResults {
		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("SERP Mention: %s", truncate(r.Title, 50)),
			Severity:    "info",
			Description: fmt.Sprintf("Search result for '%s': %s — %s", target, r.Title, truncate(r.Snippet, 200)),
			MatchedAt:   r.Link,
			Tags:        []string{"social-monitor", "pensieve", "serp", "hasdata"},
			References:  []string{r.Link},
			Fingerprint: fingerprint("pensieve", "hasdata", r.Link),
		}) {
			return
		}
	}
}
