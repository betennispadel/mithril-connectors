package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type twitterResult struct {
	ID              string   `json:"id"`
	Text            string   `json:"text"`
	AuthorUsername  string   `json:"author_username"`
	AuthorDisplay   string   `json:"author_display"`
	AuthorFollowers int      `json:"author_followers"`
	AuthorVerified  bool     `json:"author_verified"`
	CreatedAt       string   `json:"created_at"`
	Retweets        int      `json:"retweets"`
	Likes           int      `json:"likes"`
	Replies         int      `json:"replies"`
	Engagement      int      `json:"engagement"`
	Severity        string   `json:"severity"`
	Lang            string   `json:"lang"`
	URL             string   `json:"url"`
	QueryLang       string   `json:"query_lang"`
	QueryVariant    int      `json:"query_variant"`
	QueryTerms      []string `json:"query_terms"`
	FoundInLangs    []string `json:"found_in_languages"`
}

func runTwitter(ctx context.Context, cfg *PensieveConfig, target string, targetType string, em *emitter) {
	// Requires at least one Twitter account credential
	if cfg.TwitterUsername == "" {
		return
	}

	// Build env for the Python scraper
	env := append(os.Environ(),
		"TWITTER_USERNAME="+cfg.TwitterUsername,
		"TWITTER_PASSWORD="+cfg.TwitterPassword,
		"TWITTER_EMAIL="+cfg.TwitterEmail,
		"TWITTER_EMAIL_PASSWORD="+cfg.TwitterEmailPassword,
		"TWSCRAPE_DB=/tmp/twscrape.db",
	)

	args := []string{
		"/usr/local/bin/twitter_scraper.py",
		"--target", target,
		"--type", targetType,
		"--max-results", "200",
		"--max-per-query", "30",
	}

	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.Env = env
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Twitter scraper error: %v\n", err)
		return
	}

	var results []twitterResult
	if json.Unmarshal(out, &results) != nil {
		return
	}

	fmt.Fprintf(os.Stderr, "twitter: found %d tweets for %q (%s) across %d languages\n",
		len(results), target, targetType, 8)

	for _, tweet := range results {
		// Determine category based on query terms
		category := "social-monitor"
		terms := strings.Join(tweet.QueryTerms, " ")
		if strings.Contains(terms, "phishing") || strings.Contains(terms, "impersonation") || strings.Contains(terms, "scam") {
			category = "brand-protection"
		} else if strings.Contains(terms, "breach") || strings.Contains(terms, "leak") || strings.Contains(terms, "credentials") {
			category = "data-leak"
		} else if strings.Contains(terms, "ransomware") || strings.Contains(terms, "malware") {
			category = "darkweb"
		} else if strings.Contains(terms, "exploit") || strings.Contains(terms, "vulnerability") {
			category = "ioc"
		}

		tags := []string{category, "pensieve", "twitter", "lang:" + tweet.Lang}
		if len(tweet.FoundInLangs) > 1 {
			tags = append(tags, "multilingual")
		}
		if tweet.AuthorVerified {
			tags = append(tags, "verified-author")
		}
		if tweet.AuthorFollowers > 10000 {
			tags = append(tags, "high-reach")
		}

		desc := fmt.Sprintf("@%s: %s\n\nEngagement: %d (RT: %d, Likes: %d, Replies: %d)",
			tweet.AuthorUsername,
			truncate(tweet.Text, 500),
			tweet.Engagement, tweet.Retweets, tweet.Likes, tweet.Replies)

		if len(tweet.FoundInLangs) > 1 {
			desc += fmt.Sprintf("\nFound via languages: %s", strings.Join(tweet.FoundInLangs, ", "))
		}

		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Tweet: @%s — %s", tweet.AuthorUsername, truncate(tweet.Text, 60)),
			Severity:    tweet.Severity,
			Description: desc,
			MatchedAt:   tweet.URL,
			Tags:        tags,
			References:  []string{tweet.URL},
			Fingerprint: fingerprint("pensieve", "twitter", tweet.ID),
		}) {
			return
		}
	}
}
