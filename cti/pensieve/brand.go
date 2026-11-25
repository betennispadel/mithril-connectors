package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runBrandProtection(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runOpenPhish(ctx, target, em)
	runTyposquat(ctx, target, em)
	runOpenSquat(ctx, cfg, target, em)
}

// preDownloadFeed downloads a URL using Go's net/http (which handles proxy auth
// correctly for CONNECT tunnels) and saves it to dst. Returns nil on success.
// This works around Python requests failing 407 on HTTPS CONNECT through the
// egress proxy.
func preDownloadFeed(ctx context.Context, feedURL, dst string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", feedURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: HTTP %d", feedURL, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// runOpenSquat calls the opensquat Python tool for advanced domain squatting detection.
// It handles IDN homograph attacks, CT log monitoring, VirusTotal checks,
// and newly registered domain matching that the simple typosquat generator misses.
func runOpenSquat(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	domain := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return
	}
	brandName := parts[0]

	// Build keywords list
	keywords := []string{brandName}

	// Create temp workdir
	workDir, err := os.MkdirTemp("", "opensquat-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "opensquat: failed to create workdir: %v\n", err)
		return
	}
	defer os.RemoveAll(workDir)

	// Pre-download the NRD feed using Go's HTTP client. Go's net/http handles
	// proxy auth (HTTPS_PROXY with userinfo) correctly for CONNECT tunnels,
	// whereas Python requests/urllib3 often sends 407 in this setup.
	feedURL := "https://feeds.opensquat.com/opensquat-nrd-latest.txt"
	feedFile := filepath.Join(workDir, "opensquat-nrd-latest.txt")
	fmt.Fprintf(os.Stderr, "opensquat: pre-downloading NRD feed via Go HTTP client\n")
	if err := preDownloadFeed(ctx, feedURL, feedFile); err != nil {
		fmt.Fprintf(os.Stderr, "opensquat: feed pre-download failed: %v\n", err)
		// Continue anyway — opensquat will try its own download (may also fail)
	} else {
		// Write matching MD5 so opensquat's check_latest_feeds() finds the file fresh
		data, _ := os.ReadFile(feedFile)
		h := md5.Sum(data)
		md5File := feedFile + ".md5"
		os.WriteFile(md5File, []byte(hex.EncodeToString(h[:])), 0644)
		fmt.Fprintf(os.Stderr, "opensquat: NRD feed ready (%d bytes)\n", len(data))
	}

	keywordsFile := filepath.Join(workDir, "keywords.txt")
	if err := os.WriteFile(keywordsFile, []byte(strings.Join(keywords, "\n")), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "opensquat: failed to write keywords: %v\n", err)
		return
	}

	outputFile := filepath.Join(workDir, "results.json")

	args := []string{
		"-k", keywordsFile,
		"-o", outputFile,
		"-t", "json",
		"-c", "1",
		"--dns",
	}

	if cfg.VirusTotalKey != "" {
		args = append(args, "--vt")
		vtFile := filepath.Join(workDir, "vt_key.txt")
		os.WriteFile(vtFile, []byte(cfg.VirusTotalKey), 0600)
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
		fmt.Fprintf(os.Stderr, "opensquat: failed to read results: %v\n", err)
		return
	}

	// Try API-style JSON output
	var apiResults []openSquatResult
	if json.Unmarshal(data, &apiResults) == nil && len(apiResults) > 0 {
		for _, r := range apiResults {
			for _, d := range r.Domains {
				severity := classifyOpenSquatSeverity(d, domain)
				name := fmt.Sprintf("Domain Squatting: %s", d.Domain)
				desc := fmt.Sprintf("Suspicious domain '%s' targeting keyword '%s'.", d.Domain, r.Keyword)
				if d.IDN {
					desc += fmt.Sprintf(" IDN homograph attack - renders as '%s'.", d.Unicode)
					name = fmt.Sprintf("IDN Homograph: %s -> %s", d.Domain, d.Unicode)
				}
				if d.Date != "" {
					desc += fmt.Sprintf(" Registered: %s.", d.Date)
				}

				tags := []string{"brand-protection", "pensieve", "opensquat", r.Keyword}
				if d.IDN {
					tags = append(tags, "idn-homograph")
				}

				if !em.emit(connector.Finding{
					Name:        name,
					Severity:    severity,
					Description: desc,
					MatchedAt:   d.Domain,
					Tags:        tags,
					References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", d.Domain)},
					Fingerprint: fingerprint("pensieve", "opensquat", d.Domain),
				}) {
					return
				}
			}
		}
		return
	}

	// Fallback: community-style JSON (array of strings)
	var communityResults []string
	if json.Unmarshal(data, &communityResults) == nil {
		for _, d := range communityResults {
			d = strings.TrimSpace(d)
			if d == "" || d == domain {
				continue
			}
			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("Domain Squatting: %s", d),
				Severity:    "high",
				Description: fmt.Sprintf("Newly registered domain '%s' resembles '%s' - potential typosquatting or phishing.", d, domain),
				MatchedAt:   d,
				Tags:        []string{"brand-protection", "pensieve", "opensquat"},
				References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", d)},
				Fingerprint: fingerprint("pensieve", "opensquat", d),
			}) {
				return
			}
		}
	}
}

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

func classifyOpenSquatSeverity(d openSquatDomain, targetDomain string) string {
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

func runOpenPhish(ctx context.Context, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://openphish.com/feed.txt", nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenPhish error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	domain := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(target, "www."), "*."))

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), domain) {
			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("Phishing URL: %s", truncate(line, 60)),
				Severity:    "critical",
				Description: fmt.Sprintf("Active phishing URL '%s' targeting '%s' detected in OpenPhish feed.", line, target),
				MatchedAt:   line,
				Tags:        []string{"brand-protection", "pensieve", "phishing", "openphish"},
				References:  []string{"https://openphish.com"},
				Fingerprint: fingerprint("pensieve", "openphish", line),
			}) {
				return
			}
		}
	}
}

func runTyposquat(ctx context.Context, target string, em *emitter) {
	domain := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return
	}
	name := parts[0]

	// Generate typosquat variants
	variants := generateTyposquats(name)
	tlds := []string{parts[1], "com", "net", "org", "io"}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, v := range variants {
		for _, tld := range tlds {
			candidate := v + "." + tld
			if candidate == domain {
				continue
			}

			// DNS check
			req, err := http.NewRequestWithContext(ctx, "GET",
				fmt.Sprintf("https://dns.google/resolve?name=%s&type=A", url.QueryEscape(candidate)), nil)
			if err != nil {
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var dnsResp struct {
				Answer []struct{ Data string } `json:"Answer"`
			}
			if json.Unmarshal(data, &dnsResp) != nil || len(dnsResp.Answer) == 0 {
				continue
			}

			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("Typosquat: %s", candidate),
				Severity:    "high",
				Description: fmt.Sprintf("Typosquatting domain '%s' resolves to %s — potential brand impersonation of '%s'.", candidate, dnsResp.Answer[0].Data, target),
				MatchedAt:   candidate,
				Tags:        []string{"brand-protection", "pensieve", "typosquat"},
				References:  []string{fmt.Sprintf("https://www.whois.com/whois/%s", candidate)},
				Fingerprint: fingerprint("pensieve", "typosquat", candidate),
			}) {
				return
			}
		}
	}
}

func generateTyposquats(name string) []string {
	var results []string
	// Character omission
	for i := range name {
		results = append(results, name[:i]+name[i+1:])
	}
	// Character swap
	for i := 0; i < len(name)-1; i++ {
		swapped := []byte(name)
		swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
		results = append(results, string(swapped))
	}
	// Character duplication
	for i := range name {
		results = append(results, name[:i+1]+string(name[i])+name[i+1:])
	}
	// Common substitutions
	subs := map[byte][]string{
		'o': {"0"}, 'l': {"1", "i"}, 'i': {"1", "l"}, 'e': {"3"},
		'a': {"4", "@"}, 's': {"5", "$"}, 'g': {"9"},
	}
	for i := range name {
		if replacements, ok := subs[name[i]]; ok {
			for _, r := range replacements {
				results = append(results, name[:i]+r+name[i+1:])
			}
		}
	}
	return results
}
