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

func runNewsData(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://newsdata.io/api/1/news?apikey=%s&q=%s&language=en,tr&category=technology",
		url.QueryEscape(cfg.NewsDataApiKey), url.QueryEscape(target))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewsData error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		Results []struct {
			Title       string `json:"title"`
			Link        string `json:"link"`
			Description string `json:"description"`
			PubDate     string `json:"pubDate"`
			Source      string `json:"source_id"`
		} `json:"results"`
	}

	if json.Unmarshal(data, &result) != nil {
		return
	}

	for _, r := range result.Results {
		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("News: %s", truncate(r.Title, 50)),
			Severity:    "info",
			Description: fmt.Sprintf("News article about '%s' from %s: %s", target, r.Source, truncate(r.Description, 300)),
			MatchedAt:   r.Link,
			Tags:        []string{"social-monitor", "pensieve", "news", r.Source},
			References:  []string{r.Link},
			Fingerprint: fingerprint("pensieve", "newsdata", r.Link),
		}) {
			return
		}
	}
}
