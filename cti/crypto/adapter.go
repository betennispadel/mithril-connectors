package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

type CryptoConfig struct {
	EtherscanApiKey string `json:"etherscanApiKey"`
	MaxFindings     int    `json:"maxFindings"`
}

type CryptoAdapter struct{}

var (
	btcRe = regexp.MustCompile(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}$`)
	ethRe = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
)

func strInput(inputs map[string]any, key string) string {
	v, _ := inputs[key].(string)
	return strings.TrimSpace(v)
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", h[:8])
}

func (CryptoAdapter) Validate(_ context.Context, inputs map[string]any) error {
	wallet := strInput(inputs, "host")
	if wallet == "" {
		return fmt.Errorf("wallet address is required")
	}
	if !btcRe.MatchString(wallet) && !ethRe.MatchString(wallet) {
		return fmt.Errorf("invalid crypto wallet address (BTC or ETH expected)")
	}
	return nil
}

func (CryptoAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg, err := connector.LoadConfig[CryptoConfig](ctx)
	if err != nil {
		cfg = &CryptoConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 200
	}
	if cfg.EtherscanApiKey == "" {
		cfg.EtherscanApiKey = os.Getenv("ETHERSCAN_API_KEY")
	}

	wallet := strInput(inputs, "host")
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

	checkOFACCrypto(ctx, client, wallet, emit)
	checkChainabuse(ctx, client, wallet, emit)
	checkYenteWallet(ctx, client, wallet, emit)
	if ethRe.MatchString(wallet) && cfg.EtherscanApiKey != "" {
		checkEtherscan(ctx, client, wallet, cfg.EtherscanApiKey, emit)
	}
	if btcRe.MatchString(wallet) {
		checkBlockchair(ctx, client, wallet, emit)
	}
	return ctx.Err()
}

var ofacCryptoCache map[string]bool
var ofacLoaded bool

func checkOFACCrypto(ctx context.Context, c *http.Client, wallet string, emit func(connector.Finding)) {
	if !ofacLoaded {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml", nil)
		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 200 {
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		re := regexp.MustCompile(`<detailValue>([13][a-zA-HJ-NP-Z0-9]{25,34}|bc1[a-z0-9]{39,59}|0x[a-fA-F0-9]{40})</detailValue>`)
		ofacCryptoCache = make(map[string]bool)
		for _, m := range re.FindAllSubmatch(body, -1) {
			ofacCryptoCache[string(m[1])] = true
		}
		ofacLoaded = true
	}
	if ofacCryptoCache[wallet] {
		emit(connector.Finding{
			Name:        "OFAC SDN — Sanctioned Crypto Wallet",
			Severity:    "critical",
			Description: fmt.Sprintf("Wallet %s is on the OFAC SDN list. Transactions may violate US sanctions law.", wallet),
			MatchedAt:   wallet,
			Tags:        []string{"crypto", "ofac", "sanctions"},
			References:  []string{"https://home.treasury.gov/policy-issues/financial-sanctions/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists"},
			Fingerprint: fingerprint("ofac-crypto", wallet),
		})
	}
}

func checkChainabuse(ctx context.Context, c *http.Client, wallet string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.chainabuse.com/v0/reports?address=%s", wallet), nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	var result struct {
		Count   int `json:"count"`
		Reports []struct {
			Category    string `json:"category"`
			Description string `json:"description"`
			CreatedAt   string `json:"created_at"`
			Chain       string `json:"chain"`
		} `json:"reports"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Count == 0 {
		return
	}
	sev := "medium"
	if result.Count >= 5 {
		sev = "high"
	}
	if result.Count >= 20 {
		sev = "critical"
	}
	cats := map[string]int{}
	for _, r := range result.Reports {
		cats[r.Category]++
	}
	var catList []string
	for cat, n := range cats {
		catList = append(catList, fmt.Sprintf("%s x%d", cat, n))
	}
	emit(connector.Finding{
		Name:        fmt.Sprintf("Chainabuse — %d community reports", result.Count),
		Severity:    sev,
		Description: fmt.Sprintf("Wallet %s has %d abuse reports. Categories: %s", wallet, result.Count, strings.Join(catList, ", ")),
		MatchedAt:   wallet,
		Tags:        []string{"crypto", "chainabuse", "abuse"},
		References:  []string{fmt.Sprintf("https://www.chainabuse.com/address/%s", wallet)},
		Fingerprint: fingerprint("chainabuse", wallet),
	})
}

func checkYenteWallet(ctx context.Context, c *http.Client, wallet string, emit func(connector.Finding)) {
	for _, base := range []string{"http://localhost:8880", "https://api.opensanctions.org"} {
		payload := map[string]any{"queries": map[string]any{"w1": map[string]any{"schema": "CryptoWallet", "properties": map[string][]string{"publicKey": {wallet}}}}}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequestWithContext(ctx, "POST", base+"/match/sanctions", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()
		var result struct {
			Responses map[string]struct {
				Results []struct {
					ID       string   `json:"id"`
					Score    float64  `json:"score"`
					Caption  string   `json:"caption"`
					Datasets []string `json:"datasets"`
				} `json:"results"`
			} `json:"responses"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) != nil {
			continue
		}
		for _, r := range result.Responses {
			for _, match := range r.Results {
				if match.Score < 0.8 {
					continue
				}
				emit(connector.Finding{
					Name:        fmt.Sprintf("OpenSanctions Wallet Match — %s", match.Caption),
					Severity:    "critical",
					Description: fmt.Sprintf("Wallet %s matched sanctioned entity '%s' (%.0f%%). Datasets: %s", wallet, match.Caption, match.Score*100, strings.Join(match.Datasets, ", ")),
					MatchedAt:   wallet,
					Tags:        append([]string{"crypto", "sanctions", "opensanctions"}, match.Datasets...),
					References:  []string{fmt.Sprintf("https://www.opensanctions.org/entities/%s/", match.ID)},
					Fingerprint: fingerprint("yente-wallet", wallet, match.ID),
				})
			}
		}
		return
	}
}

func checkEtherscan(ctx context.Context, c *http.Client, wallet, apiKey string, emit func(connector.Finding)) {
	url := fmt.Sprintf("https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address=%s&page=1&offset=100&sort=desc&apikey=%s", wallet, apiKey)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	var result struct {
		Status string `json:"status"`
		Result []struct {
			Hash      string `json:"hash"`
			TimeStamp string `json:"timeStamp"`
		} `json:"result"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Status != "1" || len(result.Result) == 0 {
		return
	}
	emit(connector.Finding{
		Name:        fmt.Sprintf("Etherscan — %d transactions found", len(result.Result)),
		Severity:    "info",
		Description: fmt.Sprintf("ETH wallet %s has %d recent transactions. Latest: %s", wallet, len(result.Result), result.Result[0].Hash),
		MatchedAt:   wallet,
		Tags:        []string{"crypto", "ethereum", "etherscan"},
		References:  []string{fmt.Sprintf("https://etherscan.io/address/%s", wallet)},
		Fingerprint: fingerprint("etherscan", wallet),
	})
}

func checkBlockchair(ctx context.Context, c *http.Client, wallet string, emit func(connector.Finding)) {
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.blockchair.com/bitcoin/dashboards/address/%s", wallet), nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()
	var result map[string]any
	if json.NewDecoder(resp.Body).Decode(&result) != nil {
		return
	}
	data, _ := result["data"].(map[string]any)
	if data == nil {
		return
	}
	addrData, _ := data[wallet].(map[string]any)
	if addrData == nil {
		return
	}
	addr, _ := addrData["address"].(map[string]any)
	if addr == nil {
		return
	}
	txCount, _ := addr["transaction_count"].(float64)
	balance, _ := addr["balance"].(float64)
	if txCount > 0 {
		emit(connector.Finding{
			Name:        fmt.Sprintf("Blockchair BTC — %.0f transactions", txCount),
			Severity:    "info",
			Description: fmt.Sprintf("BTC wallet %s: %.0f transactions, balance %.8f BTC", wallet, txCount, balance/1e8),
			MatchedAt:   wallet,
			Tags:        []string{"crypto", "bitcoin", "blockchair"},
			References:  []string{fmt.Sprintf("https://blockchair.com/bitcoin/address/%s", wallet)},
			Fingerprint: fingerprint("blockchair", wallet),
		})
	}
}
