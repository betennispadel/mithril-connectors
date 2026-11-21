package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runCrypto(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runChainabuse(ctx, target, em)
}

func runChainabuse(ctx context.Context, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://www.chainabuse.com/api/v0/reports?address=%s",
		url.QueryEscape(target))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Chainabuse error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		Reports []struct {
			ID          string `json:"id"`
			Address     string `json:"address"`
			Category    string `json:"category"`
			Description string `json:"description"`
			CreatedAt   string `json:"createdAt"`
		} `json:"reports"`
	}

	if json.Unmarshal(data, &result) != nil {
		return
	}

	for _, r := range result.Reports {
		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Crypto Abuse: %s — %s", r.Category, truncate(target, 30)),
			Severity:    "high",
			Description: fmt.Sprintf("Wallet '%s' reported for '%s': %s", target, r.Category, truncate(r.Description, 200)),
			MatchedAt:   target,
			Tags:        []string{"crypto", "pensieve", "chainabuse", r.Category},
			References:  []string{fmt.Sprintf("https://www.chainabuse.com/address/%s", target)},
			Fingerprint: fingerprint("pensieve", "chainabuse", r.ID),
		}) {
			return
		}
	}
}
