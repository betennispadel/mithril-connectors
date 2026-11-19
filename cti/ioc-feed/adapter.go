package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type IOCFeedConfig struct {
	OTXApiKey       string `json:"otxApiKey"`
	GreyNoiseApiKey string `json:"greyNoiseApiKey"`
	AbuseIPDBApiKey string `json:"abuseIpDbApiKey"`
	MaxFindings     int    `json:"maxFindings"`
}

type IOCFeedAdapter struct{}

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

func (IOCFeedAdapter) Validate(_ context.Context, inputs map[string]any) error {
	if strInput(inputs, "host") == "" {
		return fmt.Errorf("host (domain or IP) is required")
	}
	return nil
}

func (a IOCFeedAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[IOCFeedConfig](ctx)
	if err != nil {
		cfg = &IOCFeedConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 1000
	}
	if cfg.OTXApiKey == "" {
		cfg.OTXApiKey = os.Getenv("OTX_API_KEY")
	}
	if cfg.GreyNoiseApiKey == "" {
		cfg.GreyNoiseApiKey = os.Getenv("GREYNOISE_API_KEY")
	}
	if cfg.AbuseIPDBApiKey == "" {
		cfg.AbuseIPDBApiKey = os.Getenv("ABUSEIPDB_API_KEY")
	}

	host := strInput(inputs, "host")
	isIP := net.ParseIP(host) != nil
	client := httpClient()
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

	if isIP {
		checkThreatFox(ctx, client, host, emit)
		checkFeodo(ctx, client, host, emit)
		checkSSLBL(ctx, client, host, emit)
		if cfg.OTXApiKey != "" {
			checkOTX(ctx, client, host, "IPv4", cfg.OTXApiKey, emit)
		}
		checkGreyNoise(ctx, client, host, cfg.GreyNoiseApiKey, emit)
		if cfg.AbuseIPDBApiKey != "" {
			checkAbuseIPDB(ctx, client, host, cfg.AbuseIPDBApiKey, emit)
		}
		checkTorExit(ctx, client, host, emit)
	} else {
		checkURLhaus(ctx, client, host, emit)
		checkThreatFox(ctx, client, host, emit)
		if cfg.OTXApiKey != "" {
			checkOTX(ctx, client, host, "domain", cfg.OTXApiKey, emit)
		}
	}

	return ctx.Err()
}

func checkURLhaus(ctx context.Context, c *http.Client, host string, emit func(connector.Finding)) {
	body := "host=" + host
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://urlhaus-api.abuse.ch/v1/host/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var result struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			URL       string   `json:"url"`
			URLStatus string   `json:"url_status"`
			Threat    string   `json:"threat"`
			Tags      []string `json:"tags"`
		} `json:"urls"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.QueryStatus != "is_host" {
		return
	}
	for _, u := range result.URLs {
		sev := "high"
		if u.URLStatus == "online" {
			sev = "critical"
		}
		emit(connector.Finding{
			Name:        "Malware URL (URLhaus)",
			Severity:    sev,
			Description: fmt.Sprintf("Host %s listed on URLhaus. URL: %s | Threat: %s | Status: %s", host, u.URL, u.Threat, u.URLStatus),
			MatchedAt:   u.URL,
			Tags:        append([]string{"ioc", "urlhaus", "malware-url"}, u.Tags...),
			References:  []string{"https://urlhaus.abuse.ch/"},
			Fingerprint: fingerprint("urlhaus", u.URL),
		})
	}
}

func checkThreatFox(ctx context.Context, c *http.Client, indicator string, emit func(connector.Finding)) {
	payload := map[string]string{"query": "search_ioc", "search_term": indicator}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://threatfox-api.abuse.ch/api/v1/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOCType    string `json:"ioc_type"`
			ThreatType string `json:"threat_type"`
			Malware    string `json:"malware"`
			Confidence int    `json:"confidence_level"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.QueryStatus != "ok" {
		return
	}
	for _, d := range result.Data {
		sev := "high"
		if d.Confidence >= 90 {
			sev = "critical"
		} else if d.Confidence < 50 {
			sev = "medium"
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("C2 / Threat IOC (ThreatFox) - %s", d.ThreatType),
			Severity:    sev,
			Description: fmt.Sprintf("Indicator %s associated with %s. Type: %s | Confidence: %d%%", indicator, d.Malware, d.IOCType, d.Confidence),
			MatchedAt:   indicator,
			Tags:        []string{"ioc", "threatfox", "c2", d.ThreatType},
			References:  []string{"https://threatfox.abuse.ch/"},
			Fingerprint: fingerprint("threatfox", indicator, d.Malware),
		})
	}
}

var feodoCache []string
var feodoLoaded bool

func checkFeodo(ctx context.Context, c *http.Client, ip string, emit func(connector.Finding)) {
	if !feodoLoaded {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", nil)
		resp, err := c.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var result []struct {
			IPAddress string `json:"ip_address"`
			Malware   string `json:"malware"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) != nil {
			return
		}
		for _, r := range result {
			feodoCache = append(feodoCache, r.IPAddress+"|"+r.Malware)
		}
		feodoLoaded = true
	}
	for _, entry := range feodoCache {
		parts := strings.SplitN(entry, "|", 2)
		if parts[0] == ip {
			emit(connector.Finding{
				Name:        "Botnet C2 Server (Feodo Tracker)",
				Severity:    "critical",
				Description: fmt.Sprintf("IP %s is a known botnet C2 server. Malware family: %s", ip, parts[1]),
				MatchedAt:   ip,
				Tags:        []string{"ioc", "feodo", "c2", "botnet", parts[1]},
				References:  []string{"https://feodotracker.abuse.ch/"},
				Fingerprint: fingerprint("feodo", ip),
			})
			return
		}
	}
}

var sslblCache []string
var sslblLoaded bool

func checkSSLBL(ctx context.Context, c *http.Client, ip string, emit func(connector.Finding)) {
	if !sslblLoaded {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://sslbl.abuse.ch/blacklist/sslipblacklist.json", nil)
		resp, err := c.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var result struct {
			Blacklist []struct {
				DstIP  string `json:"DstIP"`
				Reason string `json:"Reason"`
			} `json:"blacklist"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) != nil {
			return
		}
		for _, r := range result.Blacklist {
			sslblCache = append(sslblCache, r.DstIP+"|"+r.Reason)
		}
		sslblLoaded = true
	}
	for _, entry := range sslblCache {
		parts := strings.SplitN(entry, "|", 2)
		if parts[0] == ip {
			emit(connector.Finding{
				Name:        "Malicious SSL Certificate IP (SSLBL)",
				Severity:    "high",
				Description: fmt.Sprintf("IP %s on SSL Blacklist. Reason: %s", ip, parts[1]),
				MatchedAt:   ip,
				Tags:        []string{"ioc", "sslbl", "ssl", "malware"},
				References:  []string{"https://sslbl.abuse.ch/"},
				Fingerprint: fingerprint("sslbl", ip),
			})
			return
		}
	}
}

func checkOTX(ctx context.Context, c *http.Client, indicator, itype, apiKey string, emit func(connector.Finding)) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/%s/%s/general", itype, indicator)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("X-OTX-API-KEY", apiKey)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	var result struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name string `json:"name"`
			} `json:"pulses"`
		} `json:"pulse_info"`
		Reputation int `json:"reputation"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.PulseInfo.Count == 0 {
		return
	}
	var names []string
	for _, p := range result.PulseInfo.Pulses {
		names = append(names, p.Name)
	}
	n := 3
	if len(names) < n {
		n = len(names)
	}
	sev := "medium"
	if result.PulseInfo.Count >= 5 {
		sev = "high"
	}
	if result.PulseInfo.Count >= 10 || result.Reputation < -2 {
		sev = "critical"
	}
	emit(connector.Finding{
		Name:        fmt.Sprintf("OTX Threat Intelligence - %d pulse(s)", result.PulseInfo.Count),
		Severity:    sev,
		Description: fmt.Sprintf("Indicator %s in %d OTX pulses. Pulses: %s", indicator, result.PulseInfo.Count, strings.Join(names[:n], ", ")),
		MatchedAt:   indicator,
		Tags:        []string{"ioc", "otx", "threat-intel"},
		References:  []string{fmt.Sprintf("https://otx.alienvault.com/indicator/%s/%s", strings.ToLower(itype), indicator)},
		Fingerprint: fingerprint("otx", indicator),
	})
}

func checkGreyNoise(ctx context.Context, c *http.Client, ip, apiKey string, emit func(connector.Finding)) {
	var url string
	if apiKey != "" {
		url = fmt.Sprintf("https://api.greynoise.io/v2/noise/context/%s", ip)
	} else {
		url = fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if apiKey != "" {
		req.Header.Set("key", apiKey)
	}
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if json.Unmarshal(body, &result) != nil {
		return
	}
	classification, _ := result["classification"].(string)
	name, _ := result["name"].(string)
	noise, _ := result["noise"].(bool)
	riot, _ := result["riot"].(bool)
	if riot || (!noise && classification == "") {
		return
	}
	sev := "medium"
	if classification == "malicious" {
		sev = "high"
	}
	label := name
	if label == "" {
		label = classification
	}
	emit(connector.Finding{
		Name:        fmt.Sprintf("GreyNoise: %s", label),
		Severity:    sev,
		Description: fmt.Sprintf("IP %s tagged by GreyNoise as '%s'. Classification: %s", ip, label, classification),
		MatchedAt:   ip,
		Tags:        []string{"ioc", "greynoise", "scanner"},
		References:  []string{fmt.Sprintf("https://www.greynoise.io/viz/ip/%s", ip)},
		Fingerprint: fingerprint("greynoise", ip),
	})
}

func checkAbuseIPDB(ctx context.Context, c *http.Client, ip, apiKey string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.abuseipdb.com/api/v2/check", nil)
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			AbuseScore   int    `json:"abuseConfidenceScore"`
			TotalReports int    `json:"totalReports"`
			ISP          string `json:"isp"`
			UsageType    string `json:"usageType"`
			CountryCode  string `json:"countryCode"`
			LastReported string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Data.AbuseScore < 25 {
		return
	}
	sev := "medium"
	if result.Data.AbuseScore >= 50 {
		sev = "high"
	}
	if result.Data.AbuseScore >= 85 {
		sev = "critical"
	}
	emit(connector.Finding{
		Name:        fmt.Sprintf("AbuseIPDB: %d%% abuse confidence", result.Data.AbuseScore),
		Severity:    sev,
		Description: fmt.Sprintf("IP %s has %d%% abuse score, %d reports. ISP: %s | Country: %s | Type: %s | Last: %s", ip, result.Data.AbuseScore, result.Data.TotalReports, result.Data.ISP, result.Data.CountryCode, result.Data.UsageType, result.Data.LastReported),
		MatchedAt:   ip,
		Tags:        []string{"ioc", "abuseipdb", "abuse"},
		References:  []string{fmt.Sprintf("https://www.abuseipdb.com/check/%s", ip)},
		Fingerprint: fingerprint("abuseipdb", ip),
	})
}

var torCache map[string]bool
var torLoaded bool

func checkTorExit(ctx context.Context, c *http.Client, ip string, emit func(connector.Finding)) {
	if !torLoaded {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://check.torproject.org/torbulkexitlist", nil)
		resp, err := c.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		torCache = make(map[string]bool)
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				torCache[line] = true
			}
		}
		torLoaded = true
	}
	if !torCache[ip] {
		return
	}
	emit(connector.Finding{
		Name:        "Tor Exit Node",
		Severity:    "medium",
		Description: fmt.Sprintf("IP %s is an active Tor exit node.", ip),
		MatchedAt:   ip,
		Tags:        []string{"ioc", "tor", "anonymization", "proxy"},
		References:  []string{"https://check.torproject.org/", fmt.Sprintf("https://metrics.torproject.org/rs.html#search/%s", ip)},
		Fingerprint: fingerprint("tor", ip),
	})
}
