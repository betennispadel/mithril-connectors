package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type BrandProtectionConfig struct {
	MaxFindings int `json:"maxFindings"`
}

type BrandProtectionAdapter struct{}

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func (BrandProtectionAdapter) Validate(_ context.Context, inputs map[string]any) error {
	if strInput(inputs, "host") == "" {
		return fmt.Errorf("domain is required")
	}
	return nil
}

func (BrandProtectionAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[BrandProtectionConfig](ctx)
	if err != nil {
		cfg = &BrandProtectionConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 500
	}

	domain := strInput(inputs, "host")

	// Brand name: explicit override > auto-extract from domain
	brandName := strInput(inputs, "brandName")
	if brandName == "" {
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			brandName = parts[len(parts)-2]
		} else {
			brandName = domain
		}
	}

	// Build keyword set: brandName + domain + extras
	keywordSet := map[string]bool{brandName: true, domain: true}
	for _, kw := range strings.Split(strInput(inputs, "keywords"), ",") {
		kw = strings.TrimSpace(kw)
		if kw != "" {
			keywordSet[kw] = true
		}
	}
	var keywords []string
	for kw := range keywordSet {
		keywords = append(keywords, kw)
	}

	country := strings.ToUpper(strInput(inputs, "country"))

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

	// OpenPhish — check all keywords
	for _, kw := range keywords {
		checkOpenPhish(ctx, client, domain, kw, emit)
	}

	// URLhaus — full domain check
	checkURLhaus(ctx, client, domain, emit)

	// crt.sh — certificate transparency
	checkCRTSH(ctx, client, domain, emit)

	// Typosquatting on primary domain
	checkTyposquatting(ctx, domain, country, emit)

	return ctx.Err()
}

// ── OpenPhish ─────────────────────────────────────────────────────────────────

func checkOpenPhish(ctx context.Context, c *http.Client, domain, keyword string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://openphish.com/feed.txt", nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	kw := strings.ToLower(keyword)
	scanner := bufio.NewScanner(resp.Body)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(strings.ToLower(line), kw) {
			emit(connector.Finding{
				Name:        fmt.Sprintf("Phishing URL targeting '%s' (OpenPhish)", keyword),
				Severity:    "critical",
				Description: fmt.Sprintf("Active phishing URL targeting brand '%s' found in OpenPhish live feed: %s", keyword, line),
				MatchedAt:   line,
				Tags:        []string{"brand-protection", "phishing", "openphish", keyword},
				References:  []string{"https://openphish.com/"},
				Fingerprint: fingerprint("openphish", line),
			})
			count++
			if count >= 20 {
				break
			}
		}
	}
}

// ── URLhaus ───────────────────────────────────────────────────────────────────

func checkURLhaus(ctx context.Context, c *http.Client, domain string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://urlhaus-api.abuse.ch/v1/host/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(strings.NewReader("host=" + domain))

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		QueryStatus string `json:"query_status"`
		URLCount    int    `json:"urlhaus_reference"`
		URLs        []struct {
			URL      string `json:"url"`
			Threat   string `json:"threat"`
			DateAdded string `json:"date_added"`
		} `json:"urls"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.QueryStatus != "is_host" {
		return
	}

	for i, u := range result.URLs {
		if i >= 10 {
			break
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("URLhaus Malicious URL — %s (%s)", domain, u.Threat),
			Severity:    "critical",
			Description: fmt.Sprintf("Domain %s hosting malicious content. URL: %s | Threat: %s | Added: %s", domain, u.URL, u.Threat, u.DateAdded),
			MatchedAt:   u.URL,
			Tags:        []string{"brand-protection", "malware", "urlhaus", u.Threat},
			References:  []string{"https://urlhaus.abuse.ch/"},
			Fingerprint: fingerprint("urlhaus", u.URL),
		})
	}
}

// ── Certificate Transparency ──────────────────────────────────────────────────

func checkCRTSH(ctx context.Context, c *http.Client, domain string, emit func(connector.Finding)) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var certs []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
		NotBefore  string `json:"not_before"`
		IssuerName string `json:"issuer_name"`
	}
	if json.NewDecoder(resp.Body).Decode(&certs) != nil {
		return
	}

	seen := map[string]bool{}
	subCount := 0
	for _, cert := range certs {
		for _, name := range strings.Split(cert.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || name == domain || seen[name] {
				continue
			}
			seen[name] = true
			subCount++
		}
	}

	if subCount > 0 {
		emit(connector.Finding{
			Name:        fmt.Sprintf("Certificate Transparency — %d subdomains discovered for %s", subCount, domain),
			Severity:    "info",
			Description: fmt.Sprintf("crt.sh found %d unique subdomains/SANs for %s across %d total certificates. Review for unexpected or malicious subdomains.", subCount, domain, len(certs)),
			MatchedAt:   domain,
			Tags:        []string{"brand-protection", "subdomain", "certificate", "crtsh"},
			References:  []string{fmt.Sprintf("https://crt.sh/?q=%%25.%s", domain)},
			Fingerprint: fingerprint("crtsh", domain),
		})
	}
}

// ── Typosquatting ─────────────────────────────────────────────────────────────

func checkTyposquatting(ctx context.Context, domain, country string, emit func(connector.Finding)) {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return
	}
	name := parts[0]
	tld := parts[1]

	// Add country-specific TLDs to check
	countryTLDs := map[string]string{
		"TR": "com.tr", "DE": "de", "FR": "fr", "GB": "co.uk",
		"US": "us", "RU": "ru", "CN": "cn", "JP": "jp",
	}
	extraTLD := ""
	if country != "" {
		extraTLD = countryTLDs[country]
	}

	variants := generateTypos(name, tld, extraTLD)
	resolver := &net.Resolver{}
	found := 0

	for _, variant := range variants {
		if ctx.Err() != nil {
			break
		}
		if variant == domain {
			continue
		}
		resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := resolver.LookupHost(resolveCtx, variant)
		cancel()
		if err == nil && len(addrs) > 0 {
			limit := len(addrs)
			if limit > 2 {
				limit = 2
			}
			emit(connector.Finding{
				Name:        fmt.Sprintf("Typosquat Registered: %s", variant),
				Severity:    "high",
				Description: fmt.Sprintf("Potential typosquatting domain '%s' resolves to %s. Original: %s", variant, strings.Join(addrs[:limit], ", "), domain),
				MatchedAt:   variant,
				Tags:        []string{"brand-protection", "typosquatting", "domain"},
				References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", variant)},
				Fingerprint: fingerprint("typosquat", variant),
			})
			found++
			if found >= 30 {
				break
			}
		}
	}
}

func generateTypos(name, tld, extraTLD string) []string {
	var variants []string
	runes := []rune(name)

	// Delete one character
	for i := range runes {
		variants = append(variants, string(runes[:i])+string(runes[i+1:])+"."+tld)
	}

	// Swap adjacent
	for i := 0; i < len(runes)-1; i++ {
		r := make([]rune, len(runes))
		copy(r, runes)
		r[i], r[i+1] = r[i+1], r[i]
		variants = append(variants, string(r)+"."+tld)
	}

	// Keyboard substitutions
	substitutions := map[rune]string{
		'a': "sq", 'e': "wr", 'i': "uo", 'o': "ip", 'u': "yi",
		's': "ad", 'g': "fh", 'l': "ko", 'n': "bm",
	}
	for i, r := range runes {
		if subs, ok := substitutions[unicode.ToLower(r)]; ok {
			for _, sub := range subs {
				v := make([]rune, len(runes))
				copy(v, runes)
				v[i] = sub
				variants = append(variants, string(v)+"."+tld)
			}
		}
	}

	// Alternative TLDs
	altTLDs := []string{"com", "net", "org", "io", "co", "app", "online", "site"}
	for _, t := range altTLDs {
		if t != tld {
			variants = append(variants, name+"."+t)
		}
	}
	if extraTLD != "" && extraTLD != tld {
		variants = append(variants, name+"."+extraTLD)
	}

	// Common prefixes (phishing kits)
	for _, prefix := range []string{"my", "get", "login", "secure", "account", "portal", "signin"} {
		variants = append(variants, prefix+name+"."+tld)
		variants = append(variants, prefix+"-"+name+"."+tld)
	}

	// Homoglyph (simple ASCII lookalikes)
	homoglyphs := map[rune]rune{'o': '0', 'l': '1', 'i': '1', 'a': '@'}
	for i, r := range runes {
		if sub, ok := homoglyphs[unicode.ToLower(r)]; ok {
			v := make([]rune, len(runes))
			copy(v, runes)
			v[i] = sub
			variants = append(variants, string(v)+"."+tld)
		}
	}

	return variants
}
