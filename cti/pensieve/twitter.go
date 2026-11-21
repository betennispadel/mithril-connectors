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

func runTwitter(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://api.twitter.com/2/tweets/search/recent?query=%s&max_results=50&tweet.fields=created_at,author_id,public_metrics",
		url.QueryEscape(target))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.TwitterBearerToken)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Twitter API error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Twitter API %d: %s\n", resp.StatusCode, truncate(string(data), 200))
		return
	}

	var result struct {
		Data []struct {
			ID        string `json:"id"`
			Text      string `json:"text"`
			AuthorID  string `json:"author_id"`
			CreatedAt string `json:"created_at"`
			Metrics   struct {
				Retweets int `json:"retweet_count"`
				Likes    int `json:"like_count"`
			} `json:"public_metrics"`
		} `json:"data"`
	}

	if json.Unmarshal(data, &result) != nil {
		return
	}

	for _, tweet := range result.Data {
		severity := "info"
		if tweet.Metrics.Retweets > 100 || tweet.Metrics.Likes > 500 {
			severity = "medium"
		}
		if tweet.Metrics.Retweets > 1000 {
			severity = "high"
		}

		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Twitter Mention: %s", truncate(tweet.Text, 50)),
			Severity:    severity,
			Description: fmt.Sprintf("Tweet mentioning '%s': %s (RT: %d, Likes: %d)", target, truncate(tweet.Text, 200), tweet.Metrics.Retweets, tweet.Metrics.Likes),
			MatchedAt:   fmt.Sprintf("https://twitter.com/i/status/%s", tweet.ID),
			Tags:        []string{"social-monitor", "pensieve", "twitter"},
			References:  []string{fmt.Sprintf("https://twitter.com/i/status/%s", tweet.ID)},
			Fingerprint: fingerprint("pensieve", "twitter", tweet.ID),
		}) {
			return
		}
	}
}
