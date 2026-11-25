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

	// VoidAccess enrichment keys — passed as env vars to the CLI
	AbuseIPDBApiKey      string `json:"abuseIpdbApiKey"`
	GreyNoiseApiKey      string `json:"greynoiseApiKey"`
	SecurityTrailsApiKey string `json:"securityTrailsApiKey"`
	OTXApiKey            string `json:"otxApiKey"`
	URLScanApiKey        string `json:"urlscanApiKey"`
	HybridAnalysisApiKey string `json:"hybridAnalysisApiKey"`
	NVDApiKey            string `json:"nvdApiKey"`
	GithubToken          string `json:"githubToken"`
	EtherscanApiKey      string `json:"etherscanApiKey"`
	BlockCypherToken     string `json:"blockCypherToken"`
	EmailRepApiKey       string `json:"emailRepApiKey"`
	XposedOrNotApiKey    string `json:"xposedOrNotApiKey"`
	ScrapingAntApiKey    string `json:"scrapingAntApiKey"`

	// VoidAccess scan depth: shallow | normal | deep (default: deep)
	ScanDepth string `json:"scanDepth"`
	// VoidAccess pace: quiet | normal | aggressive (default: normal)
	ScanPace string `json:"scanPace"`
}

// VoidAccessEnvVars returns key→value pairs to inject into the VoidAccess
// CLI environment. Only non-empty keys are included.
func (c *PensieveConfig) VoidAccessEnvVars() []string {
	pairs := []string{}
	add := func(k, v string) {
		if v != "" {
			pairs = append(pairs, k+"="+v)
		}
	}
	add("VT_API_KEY", c.VirusTotalKey)
	add("HIBP_API_KEY", c.HudsonRockApiKey) // HudsonRock uses HIBP protocol
	add("ABUSEIPDB_API_KEY", c.AbuseIPDBApiKey)
	add("GREYNOISE_API_KEY", c.GreyNoiseApiKey)
	add("SECURITYTRAILS_API_KEY", c.SecurityTrailsApiKey)
	add("OTX_API_KEY", c.OTXApiKey)
	add("URLSCAN_API_KEY", c.URLScanApiKey)
	add("HYBRID_ANALYSIS_API_KEY", c.HybridAnalysisApiKey)
	add("NVD_API_KEY", c.NVDApiKey)
	add("GITHUB_TOKEN", c.GithubToken)
	add("ETHERSCAN_API_KEY", c.EtherscanApiKey)
	add("BLOCKCYPHER_TOKEN", c.BlockCypherToken)
	add("EMAILREP_API_KEY", c.EmailRepApiKey)
	add("XPOSEDORNOT_API_KEY", c.XposedOrNotApiKey)
	add("SCRAPINGANT_API_KEY", c.ScrapingAntApiKey)
	return pairs
}

func loadConfig(ctx context.Context) *PensieveConfig {
	cfg, err := connector.LoadConfig[PensieveConfig](ctx)
	if err != nil {
		cfg = &PensieveConfig{}
	}
	if cfg.MaxFindings == 0 {
		cfg.MaxFindings = 1000
	}
	if cfg.ScanDepth == "" {
		cfg.ScanDepth = "deep"
	}
	if cfg.ScanPace == "" {
		cfg.ScanPace = "normal"
	}
	return cfg
}
