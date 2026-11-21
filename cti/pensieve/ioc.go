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

type threatFoxResult struct {
	IOC        string `json:"ioc"`
	IOCType    string `json:"ioc_type"`
	ThreatType string `json:"threat_type"`
	Malware    string `json:"malware_printable"`
	Confidence int    `json:"confidence_level"`
	FirstSeen  string `json:"first_seen_utc"`
	Reference  string `json:"reference"`
	Tags       []string `json:"tags"`
}

type threatFoxResponse struct {
	QueryStatus string            `json:"query_status"`
	Data        []threatFoxResult `json:"data"`
}

func runIOCDomain(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runThreatFox(ctx, target, "domain", em)
	runURLhaus(ctx, target, "domain", em)
}

func runIOCIP(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runThreatFox(ctx, target, "ip", em)
	runURLhaus(ctx, target, "ip", em)
}

func runIOCHash(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runThreatFox(ctx, target, "hash", em)
}

func runThreatFox(ctx context.Context, target, queryType string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}

	body := fmt.Sprintf(`{"query":"search_ioc","search_term":"%s"}`, target)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://threatfox-api.abuse.ch/api/v1/", strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ThreatFox error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result threatFoxResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	if result.QueryStatus != "ok" {
		return
	}

	for _, ioc := range result.Data {
		severity := "high"
		if ioc.Confidence >= 75 {
			severity = "critical"
		} else if ioc.Confidence < 50 {
			severity = "medium"
		}

		name := fmt.Sprintf("IOC: %s — %s", ioc.ThreatType, truncate(ioc.IOC, 50))
		desc := fmt.Sprintf("Indicator of Compromise '%s' (type: %s) linked to %s.", ioc.IOC, ioc.IOCType, ioc.Malware)
		if ioc.FirstSeen != "" {
			desc += fmt.Sprintf(" First seen: %s.", ioc.FirstSeen)
		}

		tags := append([]string{"ioc", "pensieve", "threatfox", queryType}, ioc.Tags...)
		refs := []string{"https://threatfox.abuse.ch"}
		if ioc.Reference != "" {
			refs = append(refs, ioc.Reference)
		}

		if !em.emit(connector.Finding{
			Name:        name,
			Severity:    severity,
			Description: desc,
			MatchedAt:   ioc.IOC,
			Tags:        tags,
			References:  refs,
			Fingerprint: fingerprint("pensieve", "threatfox", ioc.IOC),
		}) {
			return
		}
	}
}

func runURLhaus(ctx context.Context, target, queryType string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}

	var endpoint string
	var formKey string
	if queryType == "domain" {
		endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
		formKey = "host"
	} else {
		endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
		formKey = "host"
	}

	form := url.Values{}
	form.Set(formKey, target)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "URLhaus error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	var result struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			URL        string   `json:"url"`
			URLStatus  string   `json:"url_status"`
			Threat     string   `json:"threat"`
			DateAdded  string   `json:"date_added"`
			Tags       []string `json:"tags"`
		} `json:"urls"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return
	}

	for _, u := range result.URLs {
		severity := "high"
		if u.URLStatus == "online" {
			severity = "critical"
		}

		name := fmt.Sprintf("Malware URL: %s", truncate(u.URL, 60))
		desc := fmt.Sprintf("Malicious URL '%s' (threat: %s, status: %s) associated with target.", u.URL, u.Threat, u.URLStatus)
		if u.DateAdded != "" {
			desc += fmt.Sprintf(" Added: %s.", u.DateAdded)
		}

		tags := append([]string{"ioc", "pensieve", "urlhaus", u.Threat}, u.Tags...)

		if !em.emit(connector.Finding{
			Name:        name,
			Severity:    severity,
			Description: desc,
			MatchedAt:   u.URL,
			Tags:        tags,
			References:  []string{"https://urlhaus.abuse.ch"},
			Fingerprint: fingerprint("pensieve", "urlhaus", u.URL),
		}) {
			return
		}
	}
}
