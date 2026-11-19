package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

type SupplierRiskConfig struct {
	OpenSanctionsApiKey string `json:"openSanctionsApiKey"`
	MaxFindings         int    `json:"maxFindings"`
}

type SupplierRiskAdapter struct{}

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func (SupplierRiskAdapter) Validate(_ context.Context, inputs map[string]any) error {
	entityType := strInput(inputs, "entityType")
	if entityType == "" {
		entityType = "organization"
	}

	switch entityType {
	case "organization", "brand", "person", "vessel", "aircraft":
		// ok
	default:
		return fmt.Errorf("unsupported entityType: %s — valid: organization, person, vessel, aircraft", entityType)
	}

	host := strInput(inputs, "host")
	name := strInput(inputs, "name")
	if host == "" && name == "" {
		return fmt.Errorf("host (domain) or name is required")
	}
	return nil
}

func (SupplierRiskAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[SupplierRiskConfig](ctx)
	if err != nil {
		cfg = &SupplierRiskConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 200
	}

	host := strInput(inputs, "host")
	entityType := strInput(inputs, "entityType")
	if entityType == "" {
		entityType = "organization"
	}

	// Name: explicit override > auto-extract from domain
	name := strInput(inputs, "name")
	if name == "" {
		name = host
		if !strings.Contains(host, " ") && strings.Contains(host, ".") {
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				name = parts[len(parts)-2]
			}
		}
	}

	country := strInput(inputs, "country")
	registrationNumber := strInput(inputs, "registrationNumber")

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
	case "organization", "brand":
		checkOpenSanctions(ctx, client, name, "Organization", country, registrationNumber, cfg.OpenSanctionsApiKey, emit)
		checkOFACScreening(ctx, client, name, country, emit)
		checkBISEntityList(ctx, client, name, country, emit)
		checkCMIC(name, emit)
		if host != "" && strings.Contains(host, ".") {
			checkCISAKEV(ctx, client, host, emit)
		}

	case "person":
		checkOpenSanctions(ctx, client, name, "Person", country, registrationNumber, cfg.OpenSanctionsApiKey, emit)
		checkOpenSanctions(ctx, client, name, "LegalEntity", country, registrationNumber, cfg.OpenSanctionsApiKey, emit)
		checkOFACScreening(ctx, client, name, country, emit)

	case "vessel":
		// IMO number or vessel name
		checkOpenSanctions(ctx, client, name, "Vessel", country, registrationNumber, cfg.OpenSanctionsApiKey, emit)
		checkOFACScreening(ctx, client, name, country, emit)

	case "aircraft":
		// Tail number (TC-ABC) or aircraft name
		checkOpenSanctions(ctx, client, name, "Aircraft", country, registrationNumber, cfg.OpenSanctionsApiKey, emit)
		checkOFACScreening(ctx, client, name, country, emit)
	}

	return ctx.Err()
}

// ── OpenSanctions yente ───────────────────────────────────────────────────────

func checkOpenSanctions(ctx context.Context, c *http.Client, query, schema, country, regNum, apiKey string, emit func(connector.Finding)) {
	props := map[string][]string{"name": {query}}
	if country != "" {
		props["country"] = []string{country}
	}
	if regNum != "" {
		switch schema {
		case "Organization", "LegalEntity":
			props["registrationNumber"] = []string{regNum}
		case "Vessel":
			props["imoNumber"] = []string{regNum}
		case "Aircraft":
			props["registrationNumber"] = []string{regNum}
		}
	}

	payload := map[string]any{
		"queries": map[string]any{
			"q1": map[string]any{
				"schema":     schema,
				"properties": props,
			},
		},
	}
	b, _ := json.Marshal(payload)

	endpoints := []struct {
		base string
		auth string
	}{
		{"http://localhost:8880", ""},
		{"https://api.opensanctions.org", apiKey},
	}

	for _, ep := range endpoints {
		reqURL := ep.base + "/match/sanctions"
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(b))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if ep.auth != "" {
			req.Header.Set("Authorization", "ApiKey "+ep.auth)
		}

		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Responses map[string]struct {
				Results []struct {
					ID         string              `json:"id"`
					Score      float64             `json:"score"`
					Name       string              `json:"caption"`
					Datasets   []string            `json:"datasets"`
					Properties map[string][]string `json:"properties"`
				} `json:"results"`
			} `json:"responses"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) != nil {
			continue
		}

		for _, r := range result.Responses {
			for _, match := range r.Results {
				if match.Score < 0.7 {
					continue
				}
				sev := "high"
				for _, ds := range match.Datasets {
					if strings.Contains(ds, "ofac") || strings.Contains(ds, "un_sc") || strings.Contains(ds, "eu_financial") {
						sev = "critical"
						break
					}
				}
				n := len(match.Datasets)
				if n > 5 {
					n = 5
				}
				datasets := strings.Join(match.Datasets[:n], ", ")

				// Extra info from properties
				var extraDetails []string
				for _, k := range []string{"nationality", "country", "birthDate", "imoNumber", "registrationNumber"} {
					if vals, ok := match.Properties[k]; ok && len(vals) > 0 {
						extraDetails = append(extraDetails, fmt.Sprintf("%s: %s", k, vals[0]))
					}
				}
				details := ""
				if len(extraDetails) > 0 {
					details = " | " + strings.Join(extraDetails, " | ")
				}

				emit(connector.Finding{
					Name:        fmt.Sprintf("Sanctions Match [%s] — %s (%.0f%% confidence)", schema, match.Name, match.Score*100),
					Severity:    sev,
					Description: fmt.Sprintf("Query '%s' matched OpenSanctions %s entity '%s' with %.0f%% confidence.%s\nDatasets: %s", query, schema, match.Name, match.Score*100, details, datasets),
					MatchedAt:   query,
					Tags:        append([]string{"supplier-risk", "sanctions", "opensanctions", strings.ToLower(schema)}, match.Datasets...),
					References:  []string{fmt.Sprintf("https://www.opensanctions.org/entities/%s/", match.ID)},
					Fingerprint: fingerprint("opensanctions", query, match.ID, schema),
				})
			}
		}
		return // success on first working endpoint
	}
}

// ── OFAC Consolidated Screening List ─────────────────────────────────────────

func checkOFACScreening(ctx context.Context, c *http.Client, query, country string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://data.trade.gov/consolidated_screening_list/v1/search", nil)
	q := req.URL.Query()
	q.Set("api_key", "OPEN")
	q.Set("q", query)
	if country != "" {
		q.Set("countries", country)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total   int `json:"total"`
		Results []struct {
			Name    string `json:"name"`
			Source  string `json:"source"`
			Type    string `json:"type"`
		} `json:"results"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Total == 0 {
		return
	}

	for _, r := range result.Results {
		emit(connector.Finding{
			Name:        fmt.Sprintf("OFAC Screening List Match — %s (%s)", r.Name, r.Source),
			Severity:    "critical",
			Description: fmt.Sprintf("Query '%s' matched '%s' on the US Consolidated Screening List. Source: %s | Type: %s", query, r.Name, r.Source, r.Type),
			MatchedAt:   query,
			Tags:        []string{"supplier-risk", "sanctions", "ofac", "usg"},
			References:  []string{"https://www.trade.gov/consolidated-screening-list"},
			Fingerprint: fingerprint("ofac-screening", query, r.Name),
		})
	}
}

// ── BIS Entity List ───────────────────────────────────────────────────────────

func checkBISEntityList(ctx context.Context, c *http.Client, query, country string, emit func(connector.Finding)) {
	reqURL := fmt.Sprintf("https://efts.bis.doc.gov/complete-search-of-export-control-orders?searchText=%s&fuzzy=true", query)
	req, _ := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Hits struct {
			Total int `json:"total"`
			Hits  []struct {
				Source struct {
					Name        string `json:"name"`
					Country     string `json:"country"`
					FR_Citation string `json:"fr_citation"`
					SDN_Type    string `json:"sdn_type"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Hits.Total == 0 {
		return
	}

	for _, hit := range result.Hits.Hits {
		s := hit.Source
		// Country filter if provided
		if country != "" && s.Country != "" && !strings.EqualFold(s.Country, country) {
			continue
		}
		emit(connector.Finding{
			Name:        fmt.Sprintf("BIS Entity List — %s (%s)", s.Name, s.Country),
			Severity:    "critical",
			Description: fmt.Sprintf("'%s' matched BIS Entity List entry '%s'. Country: %s | Type: %s | FR Citation: %s. Export controlled — US licenses required.", query, s.Name, s.Country, s.SDN_Type, s.FR_Citation),
			MatchedAt:   query,
			Tags:        []string{"supplier-risk", "export-control", "bis", "entity-list"},
			References:  []string{"https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list"},
			Fingerprint: fingerprint("bis", query, s.Name),
		})
	}
}

// ── CISA KEV vendor check ─────────────────────────────────────────────────────

func checkCISAKEV(ctx context.Context, c *http.Client, domain string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var kev struct {
		Vulnerabilities []struct {
			CVE         string `json:"cveID"`
			Vendor      string `json:"vendorProject"`
			Product     string `json:"product"`
			Description string `json:"shortDescription"`
			DueDate     string `json:"dueDate"`
		} `json:"vulnerabilities"`
	}
	if json.NewDecoder(resp.Body).Decode(&kev) != nil {
		return
	}

	parts := strings.Split(domain, ".")
	brand := parts[0]
	if len(parts) >= 2 {
		brand = parts[len(parts)-2]
	}
	brand = strings.ToLower(brand)

	count := 0
	for _, v := range kev.Vulnerabilities {
		if strings.Contains(strings.ToLower(v.Vendor), brand) || strings.Contains(strings.ToLower(v.Product), brand) {
			emit(connector.Finding{
				Name:        fmt.Sprintf("CISA KEV — %s %s (%s)", v.Vendor, v.Product, v.CVE),
				Severity:    "critical",
				Description: fmt.Sprintf("Active exploited vulnerability in vendor product associated with %s. CVE: %s | Product: %s %s | Due: %s | %s", domain, v.CVE, v.Vendor, v.Product, v.DueDate, v.Description),
				MatchedAt:   domain,
				CVEID:       []string{v.CVE},
				Tags:        []string{"supplier-risk", "cisa-kev", "cve", "actively-exploited"},
				References:  []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
				Fingerprint: fingerprint("cisa-kev", v.CVE, domain),
			})
			count++
			if count >= 10 {
				break
			}
		}
	}
}

// ── CMIC §1260H — Pentagon China Military Companies ───────────────────────────

var cmicList = map[string]struct {
	FullName string
	Risk     string
}{
	"huawei":    {"Huawei Technologies Co., Ltd.", "NDAA §889 — ABD federal alımlarında yasak; FCC güvenilmez tedarikçi"},
	"zte":       {"ZTE Corporation", "BIS Entity List (2018 ihracat yasağı); ABD 5G güvenlik uyarısı"},
	"hikvision": {"Hangzhou Hikvision Digital Technology", "NDAA §889 yasak; OFAC SDN yan kuruluşları; Xinjiang gözetim"},
	"dahua":     {"Dahua Technology Co., Ltd.", "NDAA §889 yasak; Xinjiang gözetim altyapısı"},
	"hytera":    {"Hytera Communications", "NDAA §889 yasak; FCC güvenilmez tedarikçi"},
	"dji":       {"SZ DJI Technology Co., Ltd.", "Pentagon CMIC listesi; ABD ordusu kullanımından men"},
	"smic":      {"Semiconductor Manufacturing International", "BIS Entity List; Çin askeri çip üretimi"},
	"sensetime": {"SenseTime Group", "OFAC SDN; Xinjiang gözetim AI"},
	"megvii":    {"Megvii Technology", "BIS Entity List; yüz tanıma/gözetim"},
	"bytedance": {"ByteDance / TikTok", "ABD ulusal güvenlik endişesi; veri gizliliği riski"},
	"lenovo":    {"Lenovo Group", "Pentagon CMIC değerlendirme kapsamı; arka kapı iddiaları"},
	"nuctech":   {"Nuctech Company", "BIS Entity List; nükleer teknoloji ihracat riski"},
}

func checkCMIC(query string, emit func(connector.Finding)) {
	q := strings.ToLower(query)
	for key, info := range cmicList {
		if strings.Contains(q, key) || strings.Contains(strings.ToLower(info.FullName), q) {
			emit(connector.Finding{
				Name:        fmt.Sprintf("CMIC §1260H — Pentagon China Military Company: %s", info.FullName),
				Severity:    "critical",
				Description: fmt.Sprintf("'%s' is on the Pentagon §1260H Chinese Military-Civil Fusion company list. %s", info.FullName, info.Risk),
				MatchedAt:   query,
				Tags:        []string{"supplier-risk", "cmic", "china", "military-civil-fusion", "pentagon"},
				References:  []string{"https://media.defense.gov/2023/Oct/05/2003313058/-1/-1/0/1260H-COMPANIES.PDF"},
				Fingerprint: fingerprint("cmic", key),
			})
		}
	}
}
