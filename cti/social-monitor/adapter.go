package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

type SocialMonitorConfig struct {
	TwitterBearerToken string `json:"twitterBearerToken"`
	HasDataApiKey      string `json:"hasDataApiKey"`
	NewsDataApiKey     string `json:"newsDataApiKey"`
	TelegramBotToken   string `json:"telegramBotToken"`
	MaxFindings        int    `json:"maxFindings"`
	DaysBack           int    `json:"daysBack"`
}

type SocialMonitorAdapter struct{}

var reHandle = regexp.MustCompile(`^@?[a-zA-Z0-9_]{1,50}$`)
var reTgChan = regexp.MustCompile(`^@?[a-zA-Z0-9_]{5,32}$`)
var reKeyword = regexp.MustCompile(`^[\p{L}\p{N}\s\-_'.,:()]{2,200}$`)
var reLang = regexp.MustCompile(`^[a-z]{2}$`)

// Hardcoded threat intel / dark web Telegram channels to monitor
var defaultTelegramChannels = []string{
	"vxunderground",
	"breachdetector",
	"kelvinsecteam",
	"leakbase",
	"uawarnews",
	"ransomwarenews",
	"darkwebinformer",
}

// Negative sentiment keywords (EN + TR)
var negativeWords = []string{
	"hack", "breach", "leak", "scam", "fraud", "attack", "lawsuit",
	"scandal", "arrested", "criminal", "malware", "ransomware", "phishing",
	"doxx", "exploit", "vulnerability", "data exposed", "compromised",
	"dolandırıcı", "sahte", "şikayet", "mağdur", "rezalet", "ihlal",
	"saldırı", "ele geçirildi", "veri sızıntısı", "ihbar", "suistimal",
}

var threatWords = []string{
	"kill", "threat", "bomb", "ddos", "ddos attack",
	"öldür", "suikast", "bomba", "patlat", "tehdit",
}

func strIn(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fp(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func trunc(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "..."
}

func extractBrandFromDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	host = strings.TrimPrefix(host, "www.")
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return host
}

func detectSentiment(text string) string {
	lower := strings.ToLower(text)
	for _, w := range threatWords {
		if strings.Contains(lower, w) {
			return "threat"
		}
	}
	for _, w := range negativeWords {
		if strings.Contains(lower, w) {
			return "negative"
		}
	}
	return "neutral"
}

func (SocialMonitorAdapter) Validate(_ context.Context, inputs map[string]any) error {
	keyword := strIn(inputs, "keyword")
	host := strIn(inputs, "host")

	if keyword == "" && host == "" {
		return fmt.Errorf("keyword or host is required")
	}
	if keyword != "" && !reKeyword.MatchString(keyword) {
		return fmt.Errorf("keyword contains invalid characters (max 200 chars, letters/numbers/spaces/-_'.,:() only)")
	}

	lang := strIn(inputs, "language")
	if lang != "" && !reLang.MatchString(lang) {
		return fmt.Errorf("language must be a 2-letter ISO code (e.g., tr, en)")
	}

	handle := strIn(inputs, "twitterHandle")
	if handle != "" && !reHandle.MatchString(handle) {
		return fmt.Errorf("twitterHandle format invalid (letters, numbers, underscore, 1-50 chars)")
	}

	tgChan := strIn(inputs, "telegramChannel")
	if tgChan != "" && !reTgChan.MatchString(tgChan) {
		return fmt.Errorf("telegramChannel format invalid (5-32 chars, letters/numbers/underscore)")
	}

	aliases := strIn(inputs, "aliases")
	if aliases != "" {
		parts := strings.Split(aliases, ",")
		if len(parts) > 5 {
			return fmt.Errorf("aliases: maximum 5 aliases allowed")
		}
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) > 100 {
				return fmt.Errorf("each alias must be under 100 characters")
			}
		}
	}
	return nil
}

func (SocialMonitorAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[SocialMonitorConfig](ctx)
	if err != nil {
		cfg = &SocialMonitorConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 200
	}
	if cfg.DaysBack == 0 {
		cfg.DaysBack = 7
	}
	if cfg.TwitterBearerToken == "" {
		cfg.TwitterBearerToken = os.Getenv("TWITTER_BEARER_TOKEN")
	}
	if cfg.HasDataApiKey == "" {
		cfg.HasDataApiKey = os.Getenv("HASDATA_API_KEY")
	}
	if cfg.NewsDataApiKey == "" {
		cfg.NewsDataApiKey = os.Getenv("NEWSDATA_API_KEY")
	}

	// Build keyword list
	keyword := strIn(inputs, "keyword")
	if keyword == "" {
		keyword = extractBrandFromDomain(strIn(inputs, "host"))
	}

	lang := strIn(inputs, "language")
	twitterHandle := strings.TrimPrefix(strIn(inputs, "twitterHandle"), "@")
	telegramChannel := strings.TrimPrefix(strIn(inputs, "telegramChannel"), "@")

	queries := []string{keyword}
	aliasRaw := strIn(inputs, "aliases")
	if aliasRaw != "" {
		for _, a := range strings.Split(aliasRaw, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				queries = append(queries, a)
			}
		}
	}

	client := &http.Client{Timeout: 20 * time.Second}
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

	// 1. Twitter/X API v2
	if cfg.TwitterBearerToken != "" {
		for _, q := range queries {
			searchTwitter(ctx, client, q, twitterHandle, cfg.TwitterBearerToken, cfg.DaysBack, emit)
		}
	}

	// 2. Telegram public channels
	tgChannels := append([]string{}, defaultTelegramChannels...)
	if telegramChannel != "" {
		tgChannels = append(tgChannels, telegramChannel)
	}
	for _, ch := range tgChannels {
		for _, q := range queries {
			searchTelegram(ctx, client, ch, q, emit)
		}
	}

	// 3. HasData Google SERP + Ekşi Sözlük
	if cfg.HasDataApiKey != "" {
		for _, q := range queries {
			searchHasData(ctx, client, q, cfg.HasDataApiKey, cfg.DaysBack, emit)
			if lang == "tr" || isLikelyTurkish(q) {
				searchEksiSozluk(ctx, client, q, cfg.HasDataApiKey, emit)
			}
		}
	}

	// 4. NewsData.io
	if cfg.NewsDataApiKey != "" {
		for _, q := range queries {
			searchNewsData(ctx, client, q, lang, cfg.NewsDataApiKey, cfg.DaysBack, emit)
		}
	} else {
		// 5. gnews RSS fallback
		for _, q := range queries {
			searchGNewsRSS(ctx, client, q, lang, cfg.DaysBack, emit)
		}
	}

	return ctx.Err()
}

// ─── TWITTER / X ─────────────────────────────────────────────────────────────

func searchTwitter(ctx context.Context, c *http.Client, keyword, handle, bearerToken string, daysBack int, emit func(connector.Finding)) {
	since := time.Now().AddDate(0, 0, -daysBack).UTC().Format("2006-01-02T15:04:05Z")

	q := fmt.Sprintf(`"%s" -is:retweet lang:tr OR lang:en`, keyword)
	if handle != "" {
		q = fmt.Sprintf(`(from:%s OR "%s") -is:retweet`, handle, keyword)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.twitter.com/2/tweets/search/recent", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	params := req.URL.Query()
	params.Set("query", q)
	params.Set("max_results", "50")
	params.Set("start_time", since)
	params.Set("tweet.fields", "created_at,author_id,public_metrics,text")
	req.URL.RawQuery = params.Encode()

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var result struct {
		Data []struct {
			ID        string `json:"id"`
			Text      string `json:"text"`
			CreatedAt string `json:"created_at"`
			Metrics   struct {
				Retweets int `json:"retweet_count"`
				Likes    int `json:"like_count"`
			} `json:"public_metrics"`
		} `json:"data"`
		Meta struct {
			ResultCount int `json:"result_count"`
		} `json:"meta"`
	}
	if json.Unmarshal(body, &result) != nil || len(result.Data) == 0 {
		return
	}

	for _, tweet := range result.Data {
		sentiment := detectSentiment(tweet.Text)
		if sentiment == "neutral" {
			continue // only emit negative/threat mentions
		}
		sev := "medium"
		if sentiment == "threat" {
			sev = "critical"
		} else if tweet.Metrics.Retweets >= 100 {
			sev = "high"
		}
		tweetURL := fmt.Sprintf("https://twitter.com/i/web/status/%s", tweet.ID)
		emit(connector.Finding{
			Name:        fmt.Sprintf("Twitter Mention [%s] — %s", strings.ToUpper(sentiment), keyword),
			Severity:    sev,
			Description: fmt.Sprintf("Tweet about '%s' with %s sentiment. Date: %s | Retweets: %d | Likes: %d\n\n%s", keyword, sentiment, tweet.CreatedAt, tweet.Metrics.Retweets, tweet.Metrics.Likes, trunc(tweet.Text, 500)),
			MatchedAt:   tweetURL,
			Tags:        []string{"social-monitor", "twitter", "mention", sentiment},
			References:  []string{tweetURL},
			Fingerprint: fp("twitter", tweet.ID),
		})
	}
}

// ─── TELEGRAM ─────────────────────────────────────────────────────────────────

func searchTelegram(ctx context.Context, c *http.Client, channel, keyword string, emit func(connector.Finding)) {
	tgURL := fmt.Sprintf("https://t.me/s/%s", url.PathEscape(channel))
	req, err := http.NewRequestWithContext(ctx, "GET", tgURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CTI-scanner/1.0)")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	html := string(body)

	// Extract message divs (simple HTML scan — no external deps)
	kwLower := strings.ToLower(keyword)
	messages := extractTelegramMessages(html)

	for _, msg := range messages {
		if !strings.Contains(strings.ToLower(msg.text), kwLower) {
			continue
		}
		sentiment := detectSentiment(msg.text)
		sev := "medium"
		if sentiment == "threat" {
			sev = "critical"
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("Telegram Mention [%s] — @%s", channel, keyword),
			Severity:    sev,
			Description: fmt.Sprintf("Keyword '%s' found in Telegram channel @%s. Date: %s\n\n%s", keyword, channel, msg.date, trunc(msg.text, 500)),
			MatchedAt:   fmt.Sprintf("https://t.me/%s/%s", channel, msg.id),
			Tags:        []string{"social-monitor", "telegram", "mention", channel},
			References:  []string{fmt.Sprintf("https://t.me/%s", channel)},
			Fingerprint: fp("telegram", channel, msg.id, keyword),
		})
	}
}

type tgMessage struct {
	id   string
	date string
	text string
}

func extractTelegramMessages(html string) []tgMessage {
	var msgs []tgMessage
	// Find all tgme_widget_message_text divs
	parts := strings.Split(html, `tgme_widget_message_text`)
	for i, part := range parts {
		if i == 0 {
			continue
		}
		start := strings.Index(part, ">")
		if start < 0 {
			continue
		}
		end := strings.Index(part[start:], "</div>")
		if end < 0 {
			continue
		}
		raw := part[start+1 : start+end]
		// strip HTML tags
		text := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(raw, " ")
		text = strings.Join(strings.Fields(text), " ")

		// Extract message id from data-post attribute
		msgID := ""
		dateStr := ""
		if idx := strings.Index(html[:strings.Index(html, raw)+len(raw)], `data-post="`); idx > 0 {
			s := html[idx+len(`data-post="`):]
			if end2 := strings.Index(s, `"`); end2 > 0 {
				parts2 := strings.Split(s[:end2], "/")
				if len(parts2) > 1 {
					msgID = parts2[len(parts2)-1]
				}
			}
		}

		if len(text) > 20 {
			msgs = append(msgs, tgMessage{id: msgID, date: dateStr, text: text})
		}
		if len(msgs) >= 50 {
			break
		}
	}
	return msgs
}

// ─── HASDATA SERP ─────────────────────────────────────────────────────────────

func searchHasData(ctx context.Context, c *http.Client, keyword, apiKey string, daysBack int, emit func(connector.Finding)) {
	// HasData Google SERP — recent news about keyword
	body := map[string]any{
		"q":          fmt.Sprintf(`"%s" (breach OR hack OR leak OR scam OR fraud OR threat OR attack OR sızıntı OR saldırı OR dolandırıcı)`, keyword),
		"tbm":        "nws",
		"num":        20,
		"apikey":     apiKey,
	}

	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.hasdata.com/scrape/google/serp", strings.NewReader(string(b)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		NewsResults []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
			Date    string `json:"date"`
			Source  string `json:"source"`
		} `json:"newsResults"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if json.Unmarshal(raw, &result) != nil || len(result.NewsResults) == 0 {
		return
	}

	for _, item := range result.NewsResults {
		combined := item.Title + " " + item.Snippet
		sentiment := detectSentiment(combined)
		if sentiment == "neutral" {
			continue
		}
		sev := "medium"
		if sentiment == "threat" {
			sev = "high"
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("News Mention [%s] — %s", item.Source, keyword),
			Severity:    sev,
			Description: fmt.Sprintf("News article about '%s'. Source: %s | Date: %s\nTitle: %s\n%s", keyword, item.Source, item.Date, item.Title, trunc(item.Snippet, 400)),
			MatchedAt:   item.Link,
			Tags:        []string{"social-monitor", "news", "serp", "hasdata", sentiment},
			References:  []string{item.Link},
			Fingerprint: fp("hasdata-news", keyword, item.Link),
		})
	}
}

// ─── EKŞİ SÖZLÜK ─────────────────────────────────────────────────────────────

func searchEksiSozluk(ctx context.Context, c *http.Client, keyword, apiKey string, emit func(connector.Finding)) {
	body := map[string]any{
		"q":      fmt.Sprintf(`site:eksisozluk.com "%s"`, keyword),
		"num":    10,
		"apikey": apiKey,
	}

	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.hasdata.com/scrape/google/serp", strings.NewReader(string(b)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		OrganicResults []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
		} `json:"organicResults"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if json.Unmarshal(raw, &result) != nil || len(result.OrganicResults) == 0 {
		return
	}

	for _, item := range result.OrganicResults {
		combined := item.Title + " " + item.Snippet
		sentiment := detectSentiment(combined)
		sev := "low"
		if sentiment == "threat" {
			sev = "high"
		} else if sentiment == "negative" {
			sev = "medium"
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("Ekşi Sözlük Entry — %s", keyword),
			Severity:    sev,
			Description: fmt.Sprintf("Ekşi Sözlük entry mentioning '%s'.\nTitle: %s\nContext: %s", keyword, item.Title, trunc(item.Snippet, 400)),
			MatchedAt:   item.Link,
			Tags:        []string{"social-monitor", "eksi-sozluk", "turkish", "forum"},
			References:  []string{item.Link},
			Fingerprint: fp("eksi", keyword, item.Link),
		})
	}
}

// ─── NEWSDATA.IO ──────────────────────────────────────────────────────────────

func searchNewsData(ctx context.Context, c *http.Client, keyword, lang, apiKey string, daysBack int, emit func(connector.Finding)) {
	params := url.Values{}
	params.Set("q", keyword)
	params.Set("apikey", apiKey)
	if lang != "" {
		params.Set("language", lang)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://newsdata.io/api/1/news?"+params.Encode(), nil)
	if err != nil {
		return
	}
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Title       string   `json:"title"`
			Link        string   `json:"link"`
			Description string   `json:"description"`
			PubDate     string   `json:"pubDate"`
			SourceID    string   `json:"source_id"`
			Keywords    []string `json:"keywords"`
		} `json:"results"`
		TotalResults int `json:"totalResults"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if json.Unmarshal(raw, &result) != nil || len(result.Results) == 0 {
		return
	}

	for _, item := range result.Results {
		combined := item.Title + " " + item.Description
		sentiment := detectSentiment(combined)
		if sentiment == "neutral" {
			continue
		}
		sev := "medium"
		if sentiment == "threat" {
			sev = "high"
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("News Alert [%s] — %s", item.SourceID, keyword),
			Severity:    sev,
			Description: fmt.Sprintf("News about '%s'. Source: %s | Date: %s\nTitle: %s\n%s", keyword, item.SourceID, item.PubDate, item.Title, trunc(item.Description, 400)),
			MatchedAt:   item.Link,
			Tags:        []string{"social-monitor", "news", "newsdata", sentiment},
			References:  []string{item.Link},
			Fingerprint: fp("newsdata", keyword, item.Link),
		})
	}
}

// ─── GNEWS RSS (FALLBACK) ─────────────────────────────────────────────────────

type rssItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	PubDate string `xml:"pubDate"`
	Desc    string `xml:"description"`
}
type rssFeed struct {
	Items []rssItem `xml:"channel>item"`
}

func searchGNewsRSS(ctx context.Context, c *http.Client, keyword, lang string, daysBack int, emit func(connector.Finding)) {
	hl := "en"
	if lang != "" {
		hl = lang
	}
	feedURL := fmt.Sprintf("https://news.google.com/rss/search?q=%s&hl=%s&gl=%s&ceid=%s:en",
		url.QueryEscape(keyword), hl, strings.ToUpper(hl), strings.ToUpper(hl))

	req, err := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CTI-scanner/1.0)")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var feed rssFeed
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if xml.Unmarshal(raw, &feed) != nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -daysBack)
	for _, item := range feed.Items {
		combined := item.Title + " " + item.Desc
		sentiment := detectSentiment(combined)
		if sentiment == "neutral" {
			continue
		}

		// Parse date
		pubTime, _ := time.Parse(time.RFC1123Z, item.PubDate)
		if !pubTime.IsZero() && pubTime.Before(cutoff) {
			continue
		}

		sev := "medium"
		if sentiment == "threat" {
			sev = "high"
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("Google News — %s", keyword),
			Severity:    sev,
			Description: fmt.Sprintf("News about '%s' (Google News RSS). Date: %s\nTitle: %s\n%s", keyword, item.PubDate, item.Title, trunc(item.Desc, 400)),
			MatchedAt:   item.Link,
			Tags:        []string{"social-monitor", "news", "google-news", sentiment},
			References:  []string{item.Link},
			Fingerprint: fp("gnews", keyword, item.Link),
		})
	}
}

// isLikelyTurkish checks for Turkish-specific characters
func isLikelyTurkish(s string) bool {
	turkishChars := "çğıöşüÇĞİÖŞÜ"
	for _, r := range s {
		if strings.ContainsRune(turkishChars, r) {
			return true
		}
	}
	return false
}
