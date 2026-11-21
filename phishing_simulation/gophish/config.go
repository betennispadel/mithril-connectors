package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

// Config mirrors the configSchema in manifest.yaml.
type Config struct {
	SMTPHost       string `json:"smtpHost"`
	SMTPUser       string `json:"smtpUser"`
	SMTPPass       string `json:"smtpPass"`
	FromAddress    string `json:"fromAddress"`
	TemplatePreset string `json:"templatePreset"`
	CustomSubject  string `json:"customTemplateSubject"`
	CustomHTML     string `json:"customTemplateHTML"`
	LandingPreset  string `json:"landingPreset"`

	CaptureCredentials bool   `json:"captureCredentials"`
	CapturePasswords   bool   `json:"capturePasswords"`
	RedirectURL        string `json:"redirectURL"`

	CampaignDurationMinutes int `json:"campaignDurationMinutes"`
	PollIntervalSeconds     int `json:"pollIntervalSeconds"`
}

func loadConfig(ctx context.Context) (*Config, error) {
	cfg, err := connector.LoadConfig[Config](ctx)
	if err != nil {
		return nil, fmt.Errorf("fatal: %w", err)
	}
	if strings.TrimSpace(cfg.SMTPHost) == "" {
		return nil, fmt.Errorf("fatal: smtpHost is required in config profile")
	}
	if strings.TrimSpace(cfg.FromAddress) == "" {
		return nil, fmt.Errorf("fatal: fromAddress is required in config profile")
	}
	if cfg.CampaignDurationMinutes <= 0 {
		cfg.CampaignDurationMinutes = 60
	}
	if cfg.PollIntervalSeconds <= 0 {
		cfg.PollIntervalSeconds = 30
	}
	if cfg.TemplatePreset == "" {
		cfg.TemplatePreset = "password-reset"
	}
	if cfg.LandingPreset == "" {
		cfg.LandingPreset = "generic-login"
	}
	return cfg, nil
}
