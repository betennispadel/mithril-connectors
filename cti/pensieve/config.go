package main

import (
	"context"
	"strings"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

// defaultTelegramChannels is the built-in threat intelligence channel list.
// These are monitored automatically when no custom channels are configured.
// Organized by category for maintainability.
var defaultTelegramChannels = []string{
	// ── Defender / CTI News ──────────────────────────────────────
	"vxunderground",           // Malware samples, threat actor news, research
	"falconfeeds",             // Real-time ransomware + dark web tracker (3000+ actors)
	"ctinow",                  // Cyber Threat Intelligence aggregator
	"ransomwatcher",           // Data leak notifications

	// ── Ransomware Groups ────────────────────────────────────────
	"snatch_info",             // Snatch ransomware
	"snatch_news",             // Snatch news feed
	"bl00dy_Ransomware_Gang",  // Bl00dy ransomware
	"k1llsec",                 // Kill Security ransomware
	"thebrotherhoodcorp",      // The Brotherhood ransomware
	"OSINT_without_borders",   // Medusa ransomware "information support"

	// ── Hacktivist — Pro-Russian ─────────────────────────────────
	"noname05716",             // NoName057(16) — DDoS on NATO countries
	"noname05716eng",          // NoName057(16) English
	"CyberArmyofRussia_Reborn", // Cyber Army of Russia — critical infra
	"ZAllianceRU",             // Z-Pentest Alliance — SCADA/OT targeting (oil, water, energy)
	"Killneto",                // Killnet — DDoS campaigns
	"KILLNETddos",             // Killnet DDoS operations
	"itarmyofrussianews",      // IT Army of Russia

	// ── Hacktivist — Pro-Palestinian / MENA ──────────────────────
	"DarkStormTeams",          // Dark Storm Team — DDoS + defacement
	"RipperSec",               // RipperSec — SCADA intrusion claims
	"dragonforceio",           // DragonForce Malaysia — hacktivism + ransomware
	"Handala_hack",            // Handala — Israel-targeted leaks
	"Handala_backup",          // Handala backup leaks

	// ── Hacktivist — Pro-Ukraine ─────────────────────────────────
	"itarmyofukraine2022",     // IT Army of Ukraine

	// ── Hacktivist — Other ───────────────────────────────────────
	"TeamIndianCyberForce",    // Indian Cyber Force
	"CyberJihadMovement",      // Cyber Jihad Movement
	"ARABIAN_GHOSTS",          // Arabian Ghosts
	"Anonymous_Guys_313",      // Anonymous Guys
	"AnonPioneers",            // AnonPioneers

	// ── DDoS Operators ───────────────────────────────────────────
	"alixsecenglish",          // Alixsec
	"azzasec_back",            // AzzaSec
	"inteid",                  // Inteid

	// ── Data Leak / Breach ───────────────────────────────────────
	"breachdetector",          // Data leak monitor
	"DataLeakHome",            // Data leak notifications
	"baseleeak",               // BaseLeak — breach data
	"dropleak",                // Database catalog
	"gulfdocs",                // Middle East focused leaks
	"UndergroundDataLeaks",    // TEAM UNDERGROUND

	// ── Access Broker / Forums ───────────────────────────────────
	"DarkForumsHub",           // Dark web forum hub
	"zerodayforums",           // Zero-day forums
	"DangerZoneForum",         // Danger Zone forum

	// ── Infostealer / Logs ───────────────────────────────────────
	"metastealer_official",    // Metastealer
	"Phorcy",                  // Phorcy Stealer
	"jester_stealer_channel",  // Jester Stealer

	// ── SCADA / ICS / OT ────────────────────────────────────────
	"scadahacking",            // SCADA & ICS Security
	"ics_security",            // ICS/SCADA Security feeds
	"eksguvenligi",            // Global ICS/SCADA Cyber Security Feeds
}

type PensieveConfig struct {
	// --- Our own adapter keys ---
	LeakRadarApiKey     string `json:"leakRadarApiKey"`
	HudsonRockApiKey    string `json:"hudsonRockApiKey"`
	TwitterUsername      string `json:"twitterUsername"`
	TwitterPassword      string `json:"twitterPassword"`
	TwitterEmail         string `json:"twitterEmail"`
	TwitterEmailPassword string `json:"twitterEmailPassword"`
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
	TelegramPhone    string `json:"telegramPhone"`
	TelegramChannels string `json:"telegramChannels"`

	// --- VoidAccess LLM (enables query refinement + AI summary) ---
	OpenRouterApiKey string `json:"openRouterApiKey"`

	// --- Scan settings ---
	ScanDepth string `json:"scanDepth"`
	ScanPace  string `json:"scanPace"`

	// --- LLM model override ---
	LlmModel string `json:"llmModel"`

	// --- Extended config fields ---
	MaxmindLicenseKey      string `json:"maxmindLicenseKey"`
	GitlabScrapingEnabled  bool   `json:"gitlabScrapingEnabled"`
	BlockchainExplorerUrls string `json:"blockchainExplorerUrls"`
	DnsProviders           string `json:"dnsProviders"`
	FastModeEnabled        bool   `json:"fastModeEnabled"`
}

// GetTelegramChannels returns the configured channels or the built-in defaults.
func (c *PensieveConfig) GetTelegramChannels() string {
	if c.TelegramChannels != "" {
		return c.TelegramChannels
	}
	return strings.Join(defaultTelegramChannels, ",")
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

	// Enrichment keys — mapped to VoidAccess FastAPI env var names
	add("VIRUSTOTAL_API_KEY", c.VirusTotalKey)
	add("ABUSEIPDB_API_KEY", c.AbuseIPDBApiKey)
	add("GREYNOISE_API_KEY", c.GreyNoiseApiKey)
	add("SECURITYTRAILS_API_KEY", c.SecurityTrailsApiKey)
	add("OTX_API_KEY", c.OTXApiKey)
	add("URLSCAN_API_KEY", c.URLScanApiKey)
	add("HYBRIDANALYSIS_API_KEY", c.HybridAnalysisApiKey)
	add("GITHUB_TOKEN", c.GithubToken)
	add("GITLAB_TOKEN", c.GitlabToken)
	add("ETHERSCAN_API_KEY", c.EtherscanApiKey)
	add("BLOCKCYPHER_TOKEN", c.BlockCypherToken)
	add("EMAILREP_API_KEY", c.EmailRepApiKey)
	add("HAVE_I_BEEN_PWNED_API_KEY", c.HIBPApiKey)
	add("SHODAN_API_KEY", c.ShodanApiKey)
	add("XPOSEDORNOT_API_KEY", c.XposedOrNotApiKey)
	add("DEEPL_API_KEY", c.DeeplApiKey)
	add("DARKSEARCH_API_KEY", c.DarkSearchApiKey)
	add("NVD_API_KEY", c.NVDApiKey)

	// ScrapingAnt clearnet proxy
	add("SCRAPINGANT_API_KEY", c.ScrapingAntApiKey)
	add("SCRAPINGANT_PROXY_USERNAME", c.ScrapingAntProxyUsername)
	add("SCRAPINGANT_PROXY_PASSWORD", c.ScrapingAntProxyPassword)

	// Telegram — use defaults if no custom channels configured
	add("TELEGRAM_API_ID", c.TelegramApiId)
	add("TELEGRAM_API_HASH", c.TelegramApiHash)
	add("TELEGRAM_PHONE", c.TelegramPhone)
	add("TELEGRAM_CHANNELS", c.GetTelegramChannels())

	// Twitter (twscrape session-based)
	add("TWITTER_USERNAME", c.TwitterUsername)
	add("TWITTER_PASSWORD", c.TwitterPassword)
	add("TWITTER_EMAIL", c.TwitterEmail)
	add("TWITTER_EMAIL_PASSWORD", c.TwitterEmailPassword)

	// LLM — VoidAccess uses LLM_PROVIDER + LLM_API_KEY (not OPENROUTER_API_KEY)
	if c.OpenRouterApiKey != "" {
		add("LLM_PROVIDER", "openrouter")
		add("LLM_API_KEY", c.OpenRouterApiKey)
		add("LLM_MODEL", c.GetLLMModel())
	}

	// Sidecar-specific vars
	add("TOR_PROXY_HOST", "127.0.0.1")
	add("TOR_PROXY_PORT", "9050")
	add("GITHUB_SCRAPING_ENABLED", boolStr(c.GithubToken != ""))
	add("PASTE_SCRAPING_ENABLED", "true")
	add("RSS_FEEDS_ENABLED", "true")
	add("JWT_SECRET_KEY", "pensieve-sidecar-internal-2026")

	// Extended config env vars
	add("MAXMIND_LICENSE_KEY", c.MaxmindLicenseKey)
	add("GITLAB_SCRAPING_ENABLED", boolStr(c.GitlabScrapingEnabled))
	add("BLOCKCHAIN_EXPLORER_URLS", c.BlockchainExplorerUrls)
	add("DNS_PROVIDERS", c.DnsProviders)
	add("PLAYWRIGHT_HEADLESS_MODE", "true")
	add("PLAYWRIGHT_TIMEOUT_MS", "30000")
	add("FAST_MODE_ENABLED", boolStr(c.FastModeEnabled))
	add("PROGRESS_EVENTS_ENABLED", "true")
	add("EMBEDDINGS_ENABLED", "false")
	add("IP_REPUTATION_ENABLED", "true")
	add("DOMAIN_REPUTATION_ENABLED", "true")
	add("HASH_REPUTATION_ENABLED", "true")
	add("EMAIL_REPUTATION_ENABLED", "true")
	add("TOR_MAX_RETRIES", "3")
	add("TOR_CIRCUIT_ROTATION_ENABLED", "true")
	add("PHASE_TIMEOUT_SECONDS", "300")
	add("RECOVERY_ENABLED", "true")

	return pairs
}

// GetLLMModel returns the configured LLM model or the default.
func (c *PensieveConfig) GetLLMModel() string {
	if c.LlmModel != "" {
		return c.LlmModel
	}
	return "openrouter/deepseek/deepseek-chat"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
