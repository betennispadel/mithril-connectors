package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type PolyjuiceConfig struct {
	ConfidenceLevel int    `json:"confidenceLevel"`
	DNSValidation   bool   `json:"dnsValidation"`
	CTLogs          bool   `json:"ctLogs"`
	PortCheck       bool   `json:"portCheck"`
	Subdomains      bool   `json:"subdomains"`
	OpenSquatAPIKey string `json:"opensquatApiKey"`
	VirusTotalKey   string `json:"virusTotalKey"`
	MaxFindings     int    `json:"maxFindings"`
}

type PolyjuiceAdapter struct{}

type openSquatResult struct {
	Keyword string            `json:"keyword"`
	Domains []openSquatDomain `json:"domains"`
}

type openSquatDomain struct {
	Domain  string `json:"domain"`
	TLD     string `json:"tld"`
	Date    string `json:"date"`
	IDN     bool   `json:"idn"`
	Unicode string `json:"unicode"`
}

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func (PolyjuiceAdapter) Validate(_ context.Context, inputs map[string]any) error {
	if strInput(inputs, "host") == "" {
		return fmt.Errorf("domain is required")
	}
	return nil
}

func (PolyjuiceAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[PolyjuiceConfig](ctx)
	if err != nil {
		cfg = &PolyjuiceConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 500
	}
	if cfg.ConfidenceLevel == 0 {
		cfg.ConfidenceLevel = 1
	}

	domain := strInput(inputs, "host")

	parts := strings.Split(domain, ".")
	brandName := domain
	if len(parts) >= 2 {
		brandName = parts[len(parts)-2]
	}

	keywords := []string{brandName}
	for _, kw := range strings.Split(strInput(inputs, "keywords"), ",") {
		kw = strings.TrimSpace(kw)
		if kw != "" && kw != brandName {
			keywords = append(keywords, kw)
		}
	}

	workDir, err := os.MkdirTemp("", "polyjuice-*")
	if err != nil {
		return fmt.Errorf("failed to create workdir: %w", err)
	}
	defer os.RemoveAll(workDir)

	keywordsFile := filepath.Join(workDir, "keywords.txt")
	if err := os.WriteFile(keywordsFile, []byte(strings.Join(keywords, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write keywords file: %w", err)
	}

	if cfg.VirusTotalKey != "" {
		vtFile := filepath.Join(workDir, "vt_key.txt")
		os.WriteFile(vtFile, []byte(cfg.VirusTotalKey), 0600)
	}

	outputFile := filepath.Join(workDir, "results.json")
	useAPIMode := cfg.OpenSquatAPIKey != ""

	args := []string{
		"-k", keywordsFile,
		"-o", outputFile,
		"-t", "json",
		"-c", fmt.Sprintf("%d", cfg.ConfidenceLevel),
	}

	if useAPIMode {
		args = append(args, "--api", "--api-key", cfg.OpenSquatAPIKey)
	}
	if cfg.DNSValidation {
		args = append(args, "--dns")
	}
	if cfg.CTLogs {
		args = append(args, "--ct")
	}
	if cfg.PortCheck {
		args = append(args, "--portcheck")
	}
	if cfg.Subdomains {
		args = append(args, "--subdomains")
	}
	if cfg.VirusTotalKey != "" {
		args = append(args, "--vt")
	}

	cmd := exec.CommandContext(ctx, "opensquat", args...)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("HOME=%s", workDir))

	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "opensquat warning: %v\noutput: %s\n", err, string(cmdOutput))
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("failed to read results: %w (opensquat output: %s)", err, string(cmdOutput))
	}

	sent := 0
	emit := func(f connector.Finding) bool {
		if cfg.MaxFindings > 0 && sent >= cfg.MaxFindings {
			return false
		}
		select {
		case out <- f:
			sent++
			return true
		case <-ctx.Done():
			return false
		}
	}

	var apiResults []openSquatResult
	if json.Unmarshal(data, &apiResults) == nil && len(apiResults) > 0 {
		parseAPIResults(apiResults, domain, emit)
		return ctx.Err()
	}

	var communityResults []string
	if json.Unmarshal(data, &communityResults) == nil {
		parseCommunityResults(communityResults, domain, keywords, emit)
		return ctx.Err()
	}

	parseLineResults(string(data), domain, keywords, emit)
	return ctx.Err()
}

func parseAPIResults(results []openSquatResult, targetDomain string, emit func(connector.Finding) bool) {
	for _, r := range results {
		for _, d := range r.Domains {
			severity := classifySeverity(d, targetDomain)
			name := fmt.Sprintf("Domain Squatting: %s", d.Domain)
			desc := fmt.Sprintf("Suspicious domain '%s' targeting keyword '%s'.", d.Domain, r.Keyword)
			if d.IDN {
				desc += fmt.Sprintf(" IDN homograph attack — renders as '%s'.", d.Unicode)
				name = fmt.Sprintf("IDN Homograph: %s -> %s", d.Domain, d.Unicode)
			}
			if d.Date != "" {
				desc += fmt.Sprintf(" Registered: %s.", d.Date)
			}

			tags := []string{"domain-squatting", "polyjuice", r.Keyword}
			if d.IDN {
				tags = append(tags, "idn-homograph")
			}

			if !emit(connector.Finding{
				Name:        name,
				Severity:    severity,
				Description: desc,
				MatchedAt:   d.Domain,
				Tags:        tags,
				References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", d.Domain)},
				Fingerprint: fingerprint("polyjuice", d.Domain),
			}) {
				return
			}
		}
	}
}

func parseCommunityResults(domains []string, targetDomain string, keywords []string, emit func(connector.Finding) bool) {
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || d == targetDomain {
			continue
		}

		matchedKeyword := ""
		for _, kw := range keywords {
			if strings.Contains(strings.ToLower(d), strings.ToLower(kw)) {
				matchedKeyword = kw
				break
			}
		}
		if matchedKeyword == "" {
			matchedKeyword = keywords[0]
		}

		if !emit(connector.Finding{
			Name:        fmt.Sprintf("Domain Squatting: %s", d),
			Severity:    "high",
			Description: fmt.Sprintf("Newly registered domain '%s' resembles '%s' — potential typosquatting or phishing.", d, targetDomain),
			MatchedAt:   d,
			Tags:        []string{"domain-squatting", "polyjuice", matchedKeyword},
			References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", d)},
			Fingerprint: fingerprint("polyjuice", d),
		}) {
			return
		}
	}
}

func parseLineResults(data string, targetDomain string, keywords []string, emit func(connector.Finding) bool) {
	for _, line := range strings.Split(data, "\n") {
		d := strings.TrimSpace(line)
		if d == "" || d == targetDomain || strings.HasPrefix(d, "#") || strings.HasPrefix(d, "[") {
			continue
		}
		if !emit(connector.Finding{
			Name:        fmt.Sprintf("Domain Squatting: %s", d),
			Severity:    "high",
			Description: fmt.Sprintf("Newly registered domain '%s' resembles '%s'.", d, targetDomain),
			MatchedAt:   d,
			Tags:        []string{"domain-squatting", "polyjuice"},
			References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", d)},
			Fingerprint: fingerprint("polyjuice", d),
		}) {
			return
		}
	}
}

func classifySeverity(d openSquatDomain, targetDomain string) string {
	if d.IDN {
		return "critical"
	}
	target := strings.Split(targetDomain, ".")[0]
	domainName := strings.Split(d.Domain, ".")[0]
	dist := levenshteinDistance(target, domainName)
	if dist <= 1 {
		return "critical"
	}
	if dist <= 2 {
		return "high"
	}
	return "medium"
}

func levenshteinDistance(a, b string) int {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	la, lb := len(a), len(b)
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			m1 := dp[i-1][j] + 1
			m2 := dp[i][j-1] + 1
			m3 := dp[i-1][j-1] + cost
			if m1 < m2 {
				dp[i][j] = m1
			} else {
				dp[i][j] = m2
			}
			if m3 < dp[i][j] {
				dp[i][j] = m3
			}
		}
	}
	return dp[la][lb]
}
