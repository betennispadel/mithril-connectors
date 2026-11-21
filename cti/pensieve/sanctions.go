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

func runSanctions(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	runOpenSanctions(ctx, cfg, target, em)
}

func runOpenSanctions(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://api.opensanctions.org/match/default?algorithm=best&q=%s",
		url.QueryEscape(target))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return
	}
	if cfg.OpenSanctionsApiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+cfg.OpenSanctionsApiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenSanctions error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		Results []struct {
			ID         string   `json:"id"`
			Caption    string   `json:"caption"`
			Schema     string   `json:"schema"`
			Datasets   []string `json:"datasets"`
			Score      float64  `json:"score"`
			Properties map[string][]string `json:"properties"`
		} `json:"results"`
	}

	if json.Unmarshal(data, &result) != nil {
		return
	}

	for _, r := range result.Results {
		if r.Score < 0.5 {
			continue
		}

		severity := "medium"
		if r.Score >= 0.8 {
			severity = "critical"
		} else if r.Score >= 0.6 {
			severity = "high"
		}

		datasets := ""
		for _, d := range r.Datasets {
			if datasets != "" {
				datasets += ", "
			}
			datasets += d
		}

		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Sanctions Match: %s", r.Caption),
			Severity:    severity,
			Description: fmt.Sprintf("Entity '%s' (type: %s) matched in sanctions databases: %s. Match score: %.0f%%.", r.Caption, r.Schema, datasets, r.Score*100),
			MatchedAt:   r.Caption,
			Tags:        []string{"sanctions", "pensieve", r.Schema},
			References:  []string{fmt.Sprintf("https://www.opensanctions.org/entities/%s/", r.ID)},
			Fingerprint: fingerprint("pensieve", "sanctions", r.ID),
		}) {
			return
		}
	}
}
