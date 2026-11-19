package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

type DataLeaksConfig struct {
	LeakRadarApiKey  string `json:"leakRadarApiKey"`
	HudsonRockApiKey string `json:"hudsonRockApiKey"`
	MaxFindings      int    `json:"maxFindings"`
}

type DataLeaksAdapter struct{}

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

var rePackage = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)
var reUsername = regexp.MustCompile(`^[a-zA-Z0-9._\-]{3,40}$`)
var reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func autoDetectType(host string) string {
	if reEmail.MatchString(host) {
		return "email"
	}
	if net.ParseIP(host) != nil {
		return "ip"
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return "url"
	}
	if strings.Contains(host, ".") {
		return "domain"
	}
	return "keyword"
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	if idx := strings.Index(d, ":"); idx > 0 {
		d = d[:idx]
	}
	d = strings.TrimPrefix(d, "www.")
	return d
}

func extractBrand(host string) string {
	host = cleanDomain(host)
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return host
}

func dedupeStrings(ss ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (DataLeaksAdapter) Validate(_ context.Context, inputs map[string]any) error {
	entityType := strInput(inputs, "entityType")
	if entityType == "" {
		entityType = "auto"
	}

	host := strInput(inputs, "host")
	name := strInput(inputs, "name")
	keyword := strInput(inputs, "keyword")
	appPackage := strInput(inputs, "appPackage")
	urlVal := strInput(inputs, "url")

	switch entityType {
	case "auto":
		if host == "" {
			return fmt.Errorf("host is required")
		}
	case "domain":
		if host == "" {
			return fmt.Errorf("host (domain) is required")
		}
	case "email":
		if host == "" {
			return fmt.Errorf("host (email address) is required")
		}
		if !reEmail.MatchString(host) {
			return fmt.Errorf("host must be a valid email address")
		}
	case "username":
		if host == "" {
			return fmt.Errorf("host (username) is required")
		}
	case "person":
		if name == "" && host == "" {
			return fmt.Errorf("name or host is required for person searches")
		}
	case "organization", "brand":
		if name == "" && host == "" {
			return fmt.Errorf("name or host is required for %s searches", entityType)
		}
	case "keyword":
		if keyword == "" && host == "" {
			return fmt.Errorf("keyword or host is required")
		}
	case "ip":
		if host == "" {
			return fmt.Errorf("host (IP address) is required")
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("host must be a valid IP address")
		}
	case "url":
		if urlVal == "" && host == "" {
			return fmt.Errorf("url or host is required")
		}
	case "application":
		if appPackage == "" {
			return fmt.Errorf("appPackage is required (e.g., com.example.app)")
		}
		if !rePackage.MatchString(appPackage) {
			return fmt.Errorf("appPackage must be a valid package name (e.g., com.example.app)")
		}
	default:
		return fmt.Errorf("unsupported entityType: %s — valid values: auto, domain, email, username, person, organization, brand, keyword, ip, url, application", entityType)
	}
	return nil
}

func (DataLeaksAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[DataLeaksConfig](ctx)
	if err != nil {
		cfg = &DataLeaksConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 500
	}
	if cfg.LeakRadarApiKey == "" {
		cfg.LeakRadarApiKey = os.Getenv("LEAKRADAR_API_KEY")
	}
	if cfg.HudsonRockApiKey == "" {
		cfg.HudsonRockApiKey = os.Getenv("HUDSON_ROCK_API_KEY")
	}

	entityType := strInput(inputs, "entityType")
	host := strInput(inputs, "host")

	if entityType == "" || entityType == "auto" {
		entityType = autoDetectType(host)
	}

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

	switch entityType {
	case "domain":
		domain := cleanDomain(host)
		checkLeakRadarDomain(ctx, client, domain, cfg.LeakRadarApiKey, emit)
		checkLeakRadarDarkWeb(ctx, client, domain, cfg.LeakRadarApiKey, emit)
		checkHudsonRock(ctx, client, domain, cfg.HudsonRockApiKey, emit)

	case "email":
		checkLeakRadarEmail(ctx, client, host, cfg.LeakRadarApiKey, emit)
		checkLeakRadarDarkWeb(ctx, client, host, cfg.LeakRadarApiKey, emit)

	case "username":
		checkLeakRadarUsername(ctx, client, host, cfg.LeakRadarApiKey, emit)
		checkLeakRadarDarkWeb(ctx, client, host, cfg.LeakRadarApiKey, emit)

	case "person":
		name := strInput(inputs, "name")
		if name == "" {
			name = host
		}
		personEmail := strInput(inputs, "email")
		twitter := strings.TrimPrefix(strInput(inputs, "twitterHandle"), "@")
		instagram := strings.TrimPrefix(strInput(inputs, "instagramHandle"), "@")
		username := strInput(inputs, "username")
		extraRaw := strInput(inputs, "extraUsernames")

		// Dark web by full name
		checkLeakRadarDarkWeb(ctx, client, name, cfg.LeakRadarApiKey, emit)

		// Known email → combolist + dark web
		if personEmail != "" && reEmail.MatchString(personEmail) {
			checkLeakRadarEmail(ctx, client, personEmail, cfg.LeakRadarApiKey, emit)
			checkLeakRadarDarkWeb(ctx, client, personEmail, cfg.LeakRadarApiKey, emit)
		}

		// Social handles + explicit username
		handles := dedupeStrings(twitter, instagram, username)
		for _, u := range handles {
			if reUsername.MatchString(u) {
				checkLeakRadarUsername(ctx, client, u, cfg.LeakRadarApiKey, emit)
				checkLeakRadarDarkWeb(ctx, client, u, cfg.LeakRadarApiKey, emit)
			}
		}

		// Extra comma-separated usernames
		for _, u := range strings.Split(extraRaw, ",") {
			u = strings.TrimSpace(u)
			if u != "" && reUsername.MatchString(u) {
				checkLeakRadarUsername(ctx, client, u, cfg.LeakRadarApiKey, emit)
			}
		}

		// No metadata? derive slug from name
		if personEmail == "" && len(handles) == 0 && extraRaw == "" {
			slug := regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(strings.ToLower(name), "")
			if reUsername.MatchString(slug) {
				checkLeakRadarUsername(ctx, client, slug, cfg.LeakRadarApiKey, emit)
			}
		}

	case "organization", "brand":
		orgName := strInput(inputs, "name")
		if orgName == "" && host != "" {
			orgName = extractBrand(host)
		}
		checkLeakRadarDarkWeb(ctx, client, orgName, cfg.LeakRadarApiKey, emit)
		checkLeakRadarRawSearch(ctx, client, orgName, cfg.LeakRadarApiKey, emit)
		checkLeakRadarCombolistAdvanced(ctx, client, orgName, cfg.LeakRadarApiKey, emit)
		// If domain also provided, run full domain scan
		if host != "" && strings.Contains(host, ".") {
			domain := cleanDomain(host)
			checkLeakRadarDomain(ctx, client, domain, cfg.LeakRadarApiKey, emit)
			checkHudsonRock(ctx, client, domain, cfg.HudsonRockApiKey, emit)
		}

	case "keyword":
		kw := strInput(inputs, "keyword")
		if kw == "" {
			kw = host
		}
		checkLeakRadarDarkWeb(ctx, client, kw, cfg.LeakRadarApiKey, emit)
		checkLeakRadarRawSearch(ctx, client, kw, cfg.LeakRadarApiKey, emit)

	case "ip":
		checkLeakRadarStealerAdvanced(ctx, client, "ip", host, cfg.LeakRadarApiKey, emit)
		checkLeakRadarDarkWeb(ctx, client, host, cfg.LeakRadarApiKey, emit)

	case "url":
		urlVal := strInput(inputs, "url")
		if urlVal == "" {
			urlVal = host
		}
		checkLeakRadarStealerAdvanced(ctx, client, "url", urlVal, cfg.LeakRadarApiKey, emit)

	case "application":
		appPackage := strInput(inputs, "appPackage")
		checkLeakRadarAppLeaks(ctx, client, appPackage, cfg.LeakRadarApiKey, emit)
	}

	return ctx.Err()
}

// ─── LeakRadar Helpers ───────────────────────────────────────────────────────

func lrAuthHeader(apiKey string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+apiKey)
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json")
	return h
}

func lrGet(ctx context.Context, c *http.Client, apiKey, url string, params map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range lrAuthHeader(apiKey) {
		req.Header[k] = v
	}
	q := req.URL.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()
	return c.Do(req)
}

func lrPost(ctx context.Context, c *http.Client, apiKey, url string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	for k, v := range lrAuthHeader(apiKey) {
		req.Header[k] = v
	}
	return c.Do(req)
}

// ─── DOMAIN ──────────────────────────────────────────────────────────────────

func checkLeakRadarDomain(ctx context.Context, c *http.Client, domain, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrGet(ctx, c, apiKey,
		fmt.Sprintf("https://api.leakradar.io/search/domain/%s/all", domain),
		map[string]string{"page": "1", "page_size": "100", "auto_unlock": "false"},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total     int `json:"total"`
		Employees []struct {
			Username string `json:"username"`
			URL      string `json:"url"`
			Source   string `json:"source"`
			Date     string `json:"date"`
		} `json:"employees"`
		Clients []struct {
			Username string `json:"username"`
			URL      string `json:"url"`
			Source   string `json:"source"`
		} `json:"clients"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	sev := "high"
	if result.Total >= 100 {
		sev = "critical"
	} else if result.Total < 10 {
		sev = "medium"
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Leaked Credentials — %d records (LeakRadar)", result.Total),
		Severity:    sev,
		Description: fmt.Sprintf("Domain %s has %d leaked credential records (stealer logs + breach DBs + combolists). Employees: %d | Clients: %d", domain, result.Total, len(result.Employees), len(result.Clients)),
		MatchedAt:   domain,
		Tags:        []string{"data-leak", "credential", "leakradar", "stealer-log"},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-domain", domain),
	})

	for i, emp := range result.Employees {
		if i >= 10 {
			break
		}
		emit(connector.Finding{
			Name:        "Employee Credential Exposed (LeakRadar)",
			Severity:    "high",
			Description: fmt.Sprintf("Employee credential for %s. User: %s | URL: %s | Source: %s | Date: %s", domain, emp.Username, emp.URL, emp.Source, emp.Date),
			MatchedAt:   emp.URL,
			Tags:        []string{"data-leak", "credential", "employee", "leakradar"},
			Fingerprint: fingerprint("leakradar-emp", domain, emp.Username, emp.URL),
		})
	}
}

// ─── DARK WEB ─────────────────────────────────────────────────────────────────

func checkLeakRadarDarkWeb(ctx context.Context, c *http.Client, query, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrGet(ctx, c, apiKey,
		"https://api.leakradar.io/search/dark-web",
		map[string]string{"query": query, "limit": "20"},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			Title   string `json:"title"`
			URL     string `json:"url"`
			Source  string `json:"source"`
			Date    string `json:"date"`
			Snippet string `json:"snippet"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	for _, item := range result.Items {
		emit(connector.Finding{
			Name:        fmt.Sprintf("Dark Web Mention — %s", item.Source),
			Severity:    "high",
			Description: fmt.Sprintf("Query '%s' mentioned on dark web. Title: %s | Source: %s | Date: %s | Context: %s", query, item.Title, item.Source, item.Date, truncate(item.Snippet, 300)),
			MatchedAt:   item.URL,
			Tags:        []string{"data-leak", "dark-web", "leakradar", item.Source},
			References:  []string{item.URL},
			Fingerprint: fingerprint("leakradar-darkweb", query, item.URL),
		})
	}
}

// ─── EMAIL ────────────────────────────────────────────────────────────────────

func checkLeakRadarEmail(ctx context.Context, c *http.Client, email, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrPost(ctx, c, apiKey,
		"https://api.leakradar.io/search/email",
		map[string]any{"email": email, "is_email": true, "auto_unlock": false},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			Source   string `json:"source"`
			Date     string `json:"date"`
			Password string `json:"password"`
			URL      string `json:"url"`
			Locked   bool   `json:"locked"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	sev := "high"
	if result.Total >= 10 {
		sev = "critical"
	}

	sources := map[string]bool{}
	for _, i := range result.Items {
		if i.Source != "" {
			sources[i.Source] = true
		}
	}
	srcList := make([]string, 0, len(sources))
	for s := range sources {
		srcList = append(srcList, s)
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Email Credential Leak — %d records", result.Total),
		Severity:    sev,
		Description: fmt.Sprintf("Email '%s' found in %d breach/combolist records. Sources: %s", email, result.Total, strings.Join(srcList, ", ")),
		MatchedAt:   email,
		Tags:        []string{"data-leak", "credential", "email", "leakradar"},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-email", email),
	})
}

// ─── USERNAME / COMBOLIST ─────────────────────────────────────────────────────

func checkLeakRadarUsername(ctx context.Context, c *http.Client, username, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrPost(ctx, c, apiKey,
		"https://api.leakradar.io/search/combolist/username",
		map[string]any{"username": username},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			Source   string `json:"source"`
			Password string `json:"password"`
			Locked   bool   `json:"locked"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	unlocked := 0
	for _, i := range result.Items {
		if !i.Locked && i.Password != "" {
			unlocked++
		}
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Username in Combolist — %d records ('%s')", result.Total, username),
		Severity:    "high",
		Description: fmt.Sprintf("Username '%s' found in combolist databases with %d records. Plaintext passwords exposed: %d", username, result.Total, unlocked),
		MatchedAt:   username,
		Tags:        []string{"data-leak", "credential", "username", "combolist", "leakradar"},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-username", username),
	})
}

// ─── RAW SEARCH ───────────────────────────────────────────────────────────────

func checkLeakRadarRawSearch(ctx context.Context, c *http.Client, keyword, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrPost(ctx, c, apiKey,
		"https://api.leakradar.io/search/raw",
		map[string]any{"query": keyword, "page": 1, "page_size": 20},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			FileName string `json:"file_name"`
			FileType string `json:"file_type"`
			Date     string `json:"date"`
			Snippet  string `json:"snippet"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	ftypes := map[string]bool{}
	for _, i := range result.Items {
		if i.FileType != "" {
			ftypes[i.FileType] = true
		}
	}
	ftList := make([]string, 0, len(ftypes))
	for f := range ftypes {
		ftList = append(ftList, f)
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Raw Leak File Match — '%s' in %d files", keyword, result.Total),
		Severity:    "medium",
		Description: fmt.Sprintf("Keyword '%s' appears in %d raw leak files (SQL dumps, pastes, forum archives). File types: %s", keyword, result.Total, strings.Join(ftList, ", ")),
		MatchedAt:   keyword,
		Tags:        []string{"data-leak", "raw-leak", "paste", "leakradar"},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-raw", keyword),
	})
}

// ─── COMBOLIST ADVANCED ───────────────────────────────────────────────────────

func checkLeakRadarCombolistAdvanced(ctx context.Context, c *http.Client, emailDomain, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrPost(ctx, c, apiKey,
		"https://api.leakradar.io/search/combolist/advanced",
		map[string]any{"email_domain": emailDomain, "page": 1, "page_size": 100},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Source   string `json:"source"`
			Locked   bool   `json:"locked"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	unlocked := 0
	sources := map[string]bool{}
	for _, i := range result.Items {
		if !i.Locked && i.Password != "" {
			unlocked++
		}
		if i.Source != "" {
			sources[i.Source] = true
		}
	}
	srcList := make([]string, 0, len(sources))
	for s := range sources {
		srcList = append(srcList, s)
	}

	sev := "high"
	if result.Total >= 50 {
		sev = "critical"
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Combolist Advanced — %d credential pairs for '%s'", result.Total, emailDomain),
		Severity:    sev,
		Description: fmt.Sprintf("Advanced combolist search found %d email:password pairs for domain '%s'. Plaintext: %d | Sources: %s", result.Total, emailDomain, unlocked, strings.Join(srcList, ", ")),
		MatchedAt:   emailDomain,
		Tags:        []string{"data-leak", "credential", "combolist", "advanced", "leakradar"},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-combo-adv", emailDomain),
	})
}

// ─── STEALER ADVANCED (IP / URL) ──────────────────────────────────────────────

func checkLeakRadarStealerAdvanced(ctx context.Context, c *http.Client, field, value, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrPost(ctx, c, apiKey,
		"https://api.leakradar.io/search/advanced",
		map[string]any{field: value, "page": 1, "page_size": 100, "auto_unlock": false},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			Username string `json:"username"`
			URL      string `json:"url"`
			IP       string `json:"ip"`
			Date     string `json:"date"`
			Locked   bool   `json:"locked"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	sev := "high"
	if result.Total >= 20 {
		sev = "critical"
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Stealer Log — %d records for %s '%s'", result.Total, field, value),
		Severity:    sev,
		Description: fmt.Sprintf("Stealer malware log search by %s='%s' returned %d credential records.", field, value, result.Total),
		MatchedAt:   value,
		Tags:        []string{"data-leak", "stealer-log", "infostealer", "leakradar", field},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-stealer-adv", field, value),
	})
}

// ─── MOBILE APP LEAKS ─────────────────────────────────────────────────────────

func checkLeakRadarAppLeaks(ctx context.Context, c *http.Client, appPackage, apiKey string, emit func(connector.Finding)) {
	if apiKey == "" {
		return
	}
	resp, err := lrGet(ctx, c, apiKey,
		fmt.Sprintf("https://api.leakradar.io/search/applications/%s/leaks", appPackage),
		map[string]string{"page": "1", "page_size": "100", "auto_unlock": "false"},
	)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total int `json:"total"`
		Items []struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Date     string `json:"date"`
			Source   string `json:"source"`
			Locked   bool   `json:"locked"`
		} `json:"items"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	sev := "high"
	if result.Total >= 50 {
		sev = "critical"
	} else if result.Total < 5 {
		sev = "medium"
	}

	unlocked := 0
	for _, i := range result.Items {
		if !i.Locked && i.Password != "" {
			unlocked++
		}
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Mobile App Credential Leak — %d records (%s)", result.Total, appPackage),
		Severity:    sev,
		Description: fmt.Sprintf("Application package '%s' has %d stolen credentials from infostealer malware. Users of this app had their credentials exfiltrated. Plaintext passwords: %d", appPackage, result.Total, unlocked),
		MatchedAt:   appPackage,
		Tags:        []string{"data-leak", "credential", "mobile-app", "stealer-log", "infostealer", "leakradar"},
		References:  []string{"https://leakradar.io/"},
		Fingerprint: fingerprint("leakradar-app", appPackage),
	})

	for i, item := range result.Items {
		if i >= 5 {
			break
		}
		if item.Locked {
			continue
		}
		who := item.Email
		if who == "" {
			who = item.Username
		}
		if who == "" {
			continue
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("App User Credential Exposed — %s", appPackage),
			Severity:    "high",
			Description: fmt.Sprintf("App user credential stolen from %s. User: %s | Date: %s | Source: %s", appPackage, who, item.Date, item.Source),
			MatchedAt:   who,
			Tags:        []string{"data-leak", "credential", "mobile-app", "user", "leakradar"},
			Fingerprint: fingerprint("leakradar-app-user", appPackage, who, item.Date),
		})
	}
}

// ─── HUDSON ROCK ─────────────────────────────────────────────────────────────

func checkHudsonRock(ctx context.Context, c *http.Client, domain, apiKey string, emit func(connector.Finding)) {
	url := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if apiKey != "" {
		req.Header.Set("api-key", apiKey)
	}
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total     int `json:"total"`
		Employees []struct {
			Username string `json:"username"`
			App      string `json:"application_name"`
			Stealer  string `json:"stealer_family"`
			Date     string `json:"date_compromised"`
		} `json:"employees"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	sev := "high"
	if result.Total >= 50 {
		sev = "critical"
	}

	emit(connector.Finding{
		Name:        fmt.Sprintf("Stealer Log Exposure — %d records (Hudson Rock)", result.Total),
		Severity:    sev,
		Description: fmt.Sprintf("Domain %s found in stealer log databases. Compromised machines: %d", domain, result.Total),
		MatchedAt:   domain,
		Tags:        []string{"data-leak", "stealer-log", "hudson-rock", "infostealer"},
		References:  []string{"https://www.hudsonrock.com/"},
		Fingerprint: fingerprint("hudsonrock-domain", domain),
	})

	for i, emp := range result.Employees {
		if i >= 5 {
			break
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("Employee Infostealer Compromise — %s", emp.Stealer),
			Severity:    "critical",
			Description: fmt.Sprintf("Employee credential stolen by %s. User: %s | App: %s | Date: %s", emp.Stealer, emp.Username, emp.App, emp.Date),
			MatchedAt:   domain,
			Tags:        []string{"data-leak", "stealer-log", "employee", "infostealer", emp.Stealer},
			Fingerprint: fingerprint("hudsonrock-emp", domain, emp.Username, emp.Stealer),
		})
	}
}
