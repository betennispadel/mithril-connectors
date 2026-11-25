package main

import (
	"context"
	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type PensieveConfig struct {
	// --- Our own adapter keys ---
	LeakRadarApiKey     string `json:"leakRadarApiKey"`
	HudsonRockApiKey    string `json:"hudsonRockApiKey"`
	TwitterBearerToken  string `json:"twitterBearerToken"`
	HasDataApiKey       string `json:"hasDataApiKey"`
	NewsDataApiKey      string `json:"newsDataApiKey"`
	OpenSanctionsApiKey string `json:"openSanctionsApiKey"`
	MaxFindings         int    `json:"maxFindings"`

	// --- VoidAccess enrichment keys ---
	VirusTotalKey        string `json:"virusTotalKey"`
	AbuseIPDBApiKey      string `json:"abuseIpdbApiKey"`
	GreyNoiseApiKey      string `json:"greynoiseApiKey"`
	SecurityTrailsApiKey string `json:"securityTrailsApiKey"`
	OTXApiKey            string `json:"otxApiKey"`
	URLScanApiKey        string `json:"urlscanApiKey"`
	HybridAnalysisApiKey string `json:"hybridAnalysisApiKey"`
	NVDApiKey            string `json:"nvdApiKey"`
	GithubToken          string `json:"githubToken"`
	GitlabToken          string `json:"gitlabToken"`
	EtherscanApiKey      string `json:"etherscanApiKey"`
	BlockCypherToken     string `json:"blockCypherToken"`
	EmailRepApiKey       string `json:"emailRepApiKey"`
	HIBPApiKey           string `json:"hibpApiKey"`
	ShodanApiKey         string `json:"shodanApiKey"`
	XposedOrNotApiKey    string `json:"xposedOrNotApiKey"`
	DeeplApiKey          string `json:"deeplApiKey"`
	DarkSearchApiKey     string `json:"darkSearchApiKey"`

	// --- VoidAccess clearnet proxy (ScrapingAnt) ---
	ScrapingAntApiKey        string `json:"scrapingAntApiKey"`
	ScrapingAntProxyUsername string `json:"scrapingAntProxyUsername"`
	ScrapingAntProxyPassword string `json:"scrapingAntProxyPassword"`

	// --- Telegram integration ---
	TelegramApiId    string `json:"telegramApiId"`
	TelegramApiHash  string `json:"telegramApiHash"`
	TelegramChannels string `json:"telegramChannels"`

	// --- VoidAccess LLM (enables query refinement + AI summary) ---
	OpenRouterApiKey string `json:"openRouterApiKey"`

	// --- Scan settings ---
	ScanDepth string `json:"scanDepth"`
	ScanPace  string `json:"scanPace"`
}

// VoidAccessEnvVars returns key=value pairs to inject into the VoidAccess
// CLI environment. Only non-empty keys are included.
func (c *PensieveConfig) VoidAccessEnvVars() []string {
	pairs := []string{}
	add := func(k, v string) {
		if v != "" {
			pairs = append(pairs, k+"="+v)
		}
	}

	// Enrichment keys (must match voidaccess_cli/config.py ENRICHMENT_KEYS)
	add("VT_API_KEY", c.VirusTotalKey)
	add("ABUSEIPDB_API_KEY", c.AbuseIPDBApiKey)
	add("GREYNOISE_API_KEY", c.GreyNoiseApiKey)
	add("SECURITYTRAILS_API_KEY", c.SecurityTrailsApiKey)
	add("OTX_API_KEY", c.OTXApiKey)
	add("URLSCAN_API_KEY", c.URLScanApiKey)
	add("HYBRID_ANALYSIS_API_KEY", c.HybridAnalysisApiKey)
	add("GITHUB_TOKEN", c.GithubToken)
	add("GITLAB_TOKEN", c.GitlabToken)
	add("ETHERSCAN_API_KEY", c.EtherscanApiKey)
	add("BLOCKCYPHER_TOKEN", c.BlockCypherToken)
	add("EMAILREP_API_KEY", c.EmailRepApiKey)
	add("HIBP_API_KEY", c.HIBPApiKey)
	add("SHODAN_API_KEY", c.ShodanApiKey)
	add("XPOSEDORNOT_API_KEY", c.XposedOrNotApiKey)
	add("DEEPL_API_KEY", c.DeeplApiKey)
	add("DARKSEARCH_API_KEY", c.DarkSearchApiKey)

	// ScrapingAnt clearnet proxy
	add("SCRAPINGANT_API_KEY", c.ScrapingAntApiKey)
	add("SCRAPINGANT_PROXY_USERNAME", c.ScrapingAntProxyUsername)
	add("SCRAPINGANT_PROXY_PASSWORD", c.ScrapingAntProxyPassword)

	// Telegram
	add("TELEGRAM_API_ID", c.TelegramApiId)
	add("TELEGRAM_API_HASH", c.TelegramApiHash)
	add("TELEGRAM_CHANNELS", c.TelegramChannels)

	// LLM — enables query refinement, relevance filtering, AI summary
	add("OPENROUTER_API_KEY", c.OpenRouterApiKey)

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
