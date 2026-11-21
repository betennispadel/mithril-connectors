package main

import (
	"context"
	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type PensieveConfig struct {
	LeakRadarApiKey     string `json:"leakRadarApiKey"`
	HudsonRockApiKey    string `json:"hudsonRockApiKey"`
	TwitterBearerToken  string `json:"twitterBearerToken"`
	HasDataApiKey       string `json:"hasDataApiKey"`
	NewsDataApiKey      string `json:"newsDataApiKey"`
	OpenSanctionsApiKey string `json:"openSanctionsApiKey"`
	VirusTotalKey       string `json:"virusTotalKey"`
	MaxFindings         int    `json:"maxFindings"`
}

func loadConfig(ctx context.Context) *PensieveConfig {
	cfg, err := connector.LoadConfig[PensieveConfig](ctx)
	if err != nil {
		cfg = &PensieveConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 1000
	}
	return cfg
}
