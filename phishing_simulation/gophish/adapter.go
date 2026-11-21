package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type GoPhishAdapter struct{}

func (a *GoPhishAdapter) Validate(_ context.Context, inputs map[string]any) error {
	raw, _ := inputs["target"].(string)
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("target domain required")
	}
	recipients, _ := inputs["recipients"].(string)
	if strings.TrimSpace(recipients) == "" {
		return fmt.Errorf("recipients required: at least one email address")
	}
	return nil
}

func (a *GoPhishAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target := connector.HostOnly(inputs["target"].(string))
	recipientsRaw, _ := inputs["recipients"].(string)

	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}

	recipients := parseRecipients(recipientsRaw)
	if len(recipients) == 0 {
		return fmt.Errorf("fatal: no valid recipients parsed")
	}

	apiKey, cleanup, err := startGophish(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	client := newGophishClient(gophishAddr, apiKey)
	campaignName := fmt.Sprintf("imperius-%s-%d", target, time.Now().Unix())

	smtp, err := client.createSMTP(ctx, smtpProfile{
		Name:             campaignName + "-smtp",
		Host:             cfg.SMTPHost,
		Username:         cfg.SMTPUser,
		Password:         cfg.SMTPPass,
		FromAddress:      cfg.FromAddress,
		IgnoreCertErrors: true,
	})
	if err != nil {
		return fmt.Errorf("fatal: create SMTP profile: %w", err)
	}
	defer func() { _ = client.deleteSMTP(ctx, smtp.ID) }()

	tmpl := resolveTemplate(cfg)
	gpTmpl, err := client.createTemplate(ctx, gpTemplate{
		Name:    campaignName + "-template",
		Subject: tmpl.Subject,
		HTML:    tmpl.HTML,
	})
	if err != nil {
		return fmt.Errorf("fatal: create template: %w", err)
	}
	defer func() { _ = client.deleteTemplate(ctx, gpTmpl.ID) }()

	lp := resolveLandingPage(cfg)
	gpLP, err := client.createPage(ctx, gpPage{
		Name:               campaignName + "-page",
		HTML:               lp.HTML,
		CaptureCredentials: cfg.CaptureCredentials,
		CapturePasswords:   cfg.CapturePasswords,
		RedirectURL:        cfg.RedirectURL,
	})
	if err != nil {
		return fmt.Errorf("fatal: create landing page: %w", err)
	}
	defer func() { _ = client.deletePage(ctx, gpLP.ID) }()

	group, err := client.createGroup(ctx, gpGroup{
		Name:    campaignName + "-group",
		Targets: recipients,
	})
	if err != nil {
		return fmt.Errorf("fatal: create group: %w", err)
	}
	defer func() { _ = client.deleteGroup(ctx, group.ID) }()

	now := time.Now().UTC()
	campaign, err := client.createCampaign(ctx, gpCampaign{
		Name:       campaignName,
		LaunchDate: now,
		SendByDate: now.Add(5 * time.Minute),
		URL:        gophishAddr,
		Template:   gpTemplateRef{Name: gpTmpl.Name},
		Page:       gpPageRef{Name: gpLP.Name},
		SMTP:       gpSMTPRef{Name: smtp.Name},
		Groups:     []gpGroupRef{{Name: group.Name}},
	})
	if err != nil {
		return fmt.Errorf("fatal: create campaign: %w", err)
	}

	log.Printf("Campaign %d launched for %s with %d recipients", campaign.ID, target, len(recipients))

	duration := time.Duration(cfg.CampaignDurationMinutes) * time.Minute
	pollInt := time.Duration(cfg.PollIntervalSeconds) * time.Second
	deadline := time.Now().Add(duration)

	ticker := time.NewTicker(pollInt)
	defer ticker.Stop()

	emittedEvents := make(map[string]bool)

poll:
	for {
		select {
		case <-ctx.Done():
			_ = client.completeCampaign(ctx, campaign.ID)
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				break poll
			}

			camp, err := client.getCampaign(ctx, campaign.ID)
			if err != nil {
				log.Printf("poll error: %v", err)
				continue
			}

			for _, event := range camp.Timeline {
				key := fmt.Sprintf("%s|%s|%s", event.Email, event.Message, event.Time.String())
				if emittedEvents[key] {
					continue
				}
				emittedEvents[key] = true

				if f, ok := eventToFinding(event, target); ok {
					out <- f
				}
			}

			if camp.Status == "Completed" {
				break poll
			}
		}
	}

	_ = client.completeCampaign(ctx, campaign.ID)

	summary, err := client.getCampaignSummary(ctx, campaign.ID)
	if err != nil {
		log.Printf("warning: could not get campaign summary: %v", err)
	} else {
		emitSummaryFindings(summary.Stats, target, len(recipients), out)
	}

	if err := client.deleteCampaign(ctx, campaign.ID); err != nil {
		log.Printf("cleanup: delete campaign: %v", err)
	}

	return nil
}

func parseRecipients(raw string) []gpTarget {
	var targets []gpTarget
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ",", 4)
		email := strings.TrimSpace(parts[0])
		if email == "" || !strings.Contains(email, "@") {
			continue
		}
		t := gpTarget{Email: email}
		if len(parts) > 1 {
			t.FirstName = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			t.LastName = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			t.Position = strings.TrimSpace(parts[3])
		}
		targets = append(targets, t)
	}
	return targets
}

func resolveTemplate(cfg *Config) emailTemplate {
	if strings.TrimSpace(cfg.CustomHTML) != "" {
		subject := cfg.CustomSubject
		if subject == "" {
			subject = "Important: Action Required"
		}
		return emailTemplate{Subject: subject, HTML: cfg.CustomHTML}
	}
	if t, ok := emailTemplates[cfg.TemplatePreset]; ok {
		if cfg.CustomSubject != "" {
			t.Subject = cfg.CustomSubject
		}
		return t
	}
	return emailTemplates["password-reset"]
}

func resolveLandingPage(cfg *Config) landingPage {
	if lp, ok := landingPages[cfg.LandingPreset]; ok {
		return lp
	}
	return landingPages["generic-login"]
}

func eventToFinding(event gpEvent, target string) (connector.Finding, bool) {
	switch event.Message {
	case "Email Opened":
		return connector.Finding{
			Name:        "Phishing Email Opened",
			Severity:    "low",
			Description: fmt.Sprintf("User %s opened the phishing simulation email", event.Email),
			Host:        target,
			MatchedAt:   event.Email,
			Tags:        []string{"phishing", "social-engineering", "email-opened"},
			Timestamp:   event.Time,
		}, true
	case "Clicked Link":
		return connector.Finding{
			Name:        "Phishing Link Clicked",
			Severity:    "medium",
			Description: fmt.Sprintf("User %s clicked the phishing simulation link", event.Email),
			Host:        target,
			MatchedAt:   event.Email,
			Tags:        []string{"phishing", "social-engineering", "link-clicked"},
			Timestamp:   event.Time,
		}, true
	case "Submitted Data":
		return connector.Finding{
			Name:        "Credentials Submitted to Phishing Page",
			Severity:    "critical",
			Description: fmt.Sprintf("User %s submitted credentials on the simulated phishing page", event.Email),
			Host:        target,
			MatchedAt:   event.Email,
			Tags:        []string{"phishing", "social-engineering", "credential-harvest"},
			Timestamp:   event.Time,
		}, true
	case "Email Reported":
		return connector.Finding{
			Name:        "Phishing Email Correctly Reported",
			Severity:    "info",
			Description: fmt.Sprintf("User %s correctly identified and reported the phishing email", event.Email),
			Host:        target,
			MatchedAt:   event.Email,
			Tags:        []string{"phishing", "awareness-positive", "email-reported"},
			Timestamp:   event.Time,
		}, true
	default:
		return connector.Finding{}, false
	}
}

func emitSummaryFindings(stats gpCampaignSummary, target string, totalRecipients int, out chan<- connector.Finding) {
	if stats.Total == 0 {
		return
	}

	clickRate := float64(stats.Clicked) / float64(stats.Total) * 100
	out <- connector.Finding{
		Name:     "Phishing Simulation: Click-Through Rate",
		Severity: rateSeverity(clickRate),
		Description: fmt.Sprintf(
			"%.1f%% of targeted employees (%d/%d) clicked the phishing link. "+
				"Emails sent: %d, Opened: %d, Clicked: %d, Submitted credentials: %d, Reported: %d",
			clickRate, stats.Clicked, stats.Total,
			stats.Sent, stats.Opened, stats.Clicked, stats.SubmittedData, stats.EmailReported,
		),
		Host:      target,
		MatchedAt: target,
		Tags:      []string{"phishing", "simulation-summary", "click-rate"},
		Timestamp: time.Now(),
	}

	if stats.SubmittedData > 0 {
		submitRate := float64(stats.SubmittedData) / float64(stats.Total) * 100
		sev := "high"
		if submitRate > 25 {
			sev = "critical"
		}
		out <- connector.Finding{
			Name:     "Phishing Simulation: Credential Submission Rate",
			Severity: sev,
			Description: fmt.Sprintf(
				"%.1f%% of targeted employees (%d/%d) submitted credentials on the phishing page",
				submitRate, stats.SubmittedData, stats.Total,
			),
			Host:      target,
			MatchedAt: target,
			Tags:      []string{"phishing", "simulation-summary", "credential-submission"},
			Timestamp: time.Now(),
		}
	}

	if stats.EmailReported > 0 {
		reportRate := float64(stats.EmailReported) / float64(stats.Total) * 100
		out <- connector.Finding{
			Name:     "Phishing Simulation: Report Rate",
			Severity: "info",
			Description: fmt.Sprintf(
				"%.1f%% of targeted employees (%d/%d) correctly reported the phishing email",
				reportRate, stats.EmailReported, stats.Total,
			),
			Host:      target,
			MatchedAt: target,
			Tags:      []string{"phishing", "simulation-summary", "report-rate"},
			Timestamp: time.Now(),
		}
	}
}

func rateSeverity(rate float64) string {
	switch {
	case rate >= 40:
		return "critical"
	case rate >= 25:
		return "high"
	case rate >= 10:
		return "medium"
	case rate > 0:
		return "low"
	default:
		return "info"
	}
}
