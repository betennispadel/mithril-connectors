package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runBrandProtection(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runOpenPhish(ctx, target, em)
	runTyposquat(ctx, target, em)
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
