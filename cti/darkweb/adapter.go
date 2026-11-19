package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

type DarkWebConfig struct {
	RansomwareLiveApiKey string `json:"ransomwareLiveApiKey"`
	MaxFindings          int    `json:"maxFindings"`
}

type DarkWebAdapter struct{}

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (DarkWebAdapter) Validate(_ context.Context, inputs map[string]any) error {
	if strInput(inputs, "host") == "" && strInput(inputs, "keyword") == "" {
		return fmt.Errorf("host (domain) or keyword is required")
	}
	return nil
}

func (DarkWebAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[DarkWebConfig](ctx)
	if err != nil {
		cfg = &DarkWebConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 500
	}
	if cfg.RansomwareLiveApiKey == "" {
		cfg.RansomwareLiveApiKey = os.Getenv("RANSOMWARE_LIVE_API_KEY")
	}

	host := strInput(inputs, "host")

	// Primary keyword: explicit override > auto-extract from domain
	keyword := strInput(inputs, "keyword")
	if keyword == "" {
		keyword = host
		kparts := strings.Split(host, ".")
		if len(kparts) >= 2 && !strings.Contains(host, " ") {
			keyword = kparts[len(kparts)-2]
		}
	}

	// Extra keywords (comma-separated)
	var allKeywords []string
	if keyword != "" {
		allKeywords = append(allKeywords, keyword)
	}
	for _, extra := range strings.Split(strInput(inputs, "extraKeywords"), ",") {
		extra = strings.TrimSpace(extra)
		if extra != "" && extra != keyword {
			allKeywords = append(allKeywords, extra)
		}
	}

	// Days back filter
	daysBack := 90
	if v, ok := inputs["daysBack"].(float64); ok && v > 0 {
		daysBack = int(v)
	}
	cutoff := time.Now().AddDate(0, 0, -daysBack)

	language := strInput(inputs, "language")

	client := &http.Client{Timeout: 30 * time.Second}
	sent := 0

	emit := func(f connector.Finding) {
		if cfg.MaxFindings > 0 && sent >= cfg.MaxFindings {
			return
		}
		select {
		case out <- f:
			sent++
		case <-ctx.Done():
		}
	}

	for _, kw := range allKeywords {
		checkRansomwareLive(ctx, client, kw, cfg.RansomwareLiveApiKey, emit)
		checkCISARSS(ctx, client, kw, cutoff, emit)
		checkNewsRSS(ctx, client, kw, language, cutoff, emit)
	}

	return ctx.Err()
}

// ── Ransomware.live ───────────────────────────────────────────────────────────

func checkRansomwareLive(ctx context.Context, c *http.Client, keyword, apiKey string, emit func(connector.Finding)) {
	var reqURL string
	var req *http.Request
	if apiKey != "" {
		reqURL = "https://api-pro.ransomware.live/victims/recent"
		req, _ = http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		req.Header.Set("X-API-KEY", apiKey)
	} else {
		reqURL = "https://api.ransomware.live/victims"
		req, _ = http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var victims []struct {
		VictimName  string `json:"victim_name"`
		GroupName   string `json:"group_name"`
		Published   string `json:"published"`
		Description string `json:"description"`
		PostURL     string `json:"post_url"`
		Country     string `json:"country"`
	}
	if json.NewDecoder(resp.Body).Decode(&victims) != nil {
		return
	}

	kw := strings.ToLower(keyword)
	for _, v := range victims {
		name := strings.ToLower(v.VictimName)
		desc := strings.ToLower(v.Description)
		if !strings.Contains(name, kw) && !strings.Contains(desc, kw) {
			continue
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("Ransomware Victim — %s by %s", v.VictimName, v.GroupName),
			Severity:    "critical",
			Description: fmt.Sprintf("Organization matching '%s' listed as ransomware victim by group %s. Published: %s | Country: %s | %s", keyword, v.GroupName, v.Published, v.Country, truncate(v.Description, 300)),
			MatchedAt:   v.PostURL,
			Tags:        []string{"darkweb", "ransomware", v.GroupName},
			References:  []string{v.PostURL, "https://www.ransomware.live/"},
			Fingerprint: fingerprint("ransomware", v.VictimName, v.GroupName, v.Published),
		})
	}
}

// ── CISA RSS ──────────────────────────────────────────────────────────────────

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
}

type rssFeed struct {
	Items []rssItem `xml:"channel>item"`
}

func checkCISARSS(ctx context.Context, c *http.Client, keyword string, cutoff time.Time, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cisa.gov/cybersecurity-advisories/all.xml", nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var feed rssFeed
	xml.NewDecoder(resp.Body).Decode(&feed)

	kw := strings.ToLower(keyword)
	for _, item := range feed.Items {
		// Date filter
		if pubTime, err := time.Parse(time.RFC1123Z, item.PubDate); err == nil {
			if pubTime.Before(cutoff) {
				continue
			}
		}
		title := strings.ToLower(item.Title)
		desc := strings.ToLower(item.Description)
		if kw != "" && !strings.Contains(title, kw) && !strings.Contains(desc, kw) {
			continue
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("CISA Advisory: %s", item.Title),
			Severity:    "high",
			Description: fmt.Sprintf("CISA cybersecurity advisory. Published: %s | %s", item.PubDate, truncate(item.Description, 300)),
			MatchedAt:   item.Link,
			Tags:        []string{"darkweb", "cisa", "advisory", "threat-intel"},
			References:  []string{item.Link},
			Fingerprint: fingerprint("cisa", item.Link),
		})
	}
}

// ── News RSS ──────────────────────────────────────────────────────────────────

func checkNewsRSS(ctx context.Context, c *http.Client, keyword, language string, cutoff time.Time, emit func(connector.Finding)) {
	feeds := []struct {
		URL    string
		Source string
	}{
		{"https://feeds.reuters.com/reuters/technologyNews", "Reuters"},
		{"https://feeds.bbci.co.uk/news/technology/rss.xml", "BBC"},
	}

	// Add Turkish feed if language=tr
	if language == "tr" {
		feeds = append(feeds,
			struct {
				URL    string
				Source string
			}{"https://www.haberler.com/rss/teknoloji.asp", "Haberler.com"},
		)
	}

	kw := strings.ToLower(keyword)
	for _, feed := range feeds {
		req, _ := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		var rss rssFeed
		xml.NewDecoder(resp.Body).Decode(&rss)
		resp.Body.Close()

		count := 0
		for _, item := range rss.Items {
			if pubTime, err := time.Parse(time.RFC1123Z, item.PubDate); err == nil {
				if pubTime.Before(cutoff) {
					continue
				}
			}
			if kw == "" {
				break
			}
			title := strings.ToLower(item.Title)
			desc := strings.ToLower(item.Description)
			if strings.Contains(title, kw) || strings.Contains(desc, kw) {
				emit(connector.Finding{
					Name:        fmt.Sprintf("[%s] %s", feed.Source, item.Title),
					Severity:    "medium",
					Description: fmt.Sprintf("News mention matching '%s' from %s. Published: %s | %s", keyword, feed.Source, item.PubDate, truncate(item.Description, 300)),
					MatchedAt:   item.Link,
					Tags:        []string{"darkweb", "news", "media", feed.Source},
					References:  []string{item.Link},
					Fingerprint: fingerprint("news", feed.Source, item.Link),
				})
				count++
				if count >= 5 {
					break
				}
			}
		}
	}
}
