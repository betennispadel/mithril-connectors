package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

var telegramChannels = []string{
	"vxunderground",
	"breachdetector",
	"kelvinsecteam",
	"leakbase",
	"ransomwarenews",
	"darkwebinformer",
}

func runTelegram(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}
	keyword := strings.ToLower(target)

	for _, channel := range telegramChannels {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Use t.me/s/ (public preview) for scraping
		req, err := http.NewRequestWithContext(ctx, "GET",
			fmt.Sprintf("https://t.me/s/%s", channel), nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		html := string(data)
		if !strings.Contains(strings.ToLower(html), keyword) {
			continue
		}

		// Extract matching message blocks
		msgPattern := regexp.MustCompile(`<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>`)
		matches := msgPattern.FindAllStringSubmatch(html, -1)

		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			text := stripHTML(m[1])
			if !strings.Contains(strings.ToLower(text), keyword) {
				continue
			}

			severity := "medium"
			lowerText := strings.ToLower(text)
			if strings.Contains(lowerText, "leak") || strings.Contains(lowerText, "breach") || strings.Contains(lowerText, "ransomware") {
				severity = "high"
			}
			if strings.Contains(lowerText, "credential") || strings.Contains(lowerText, "password") {
				severity = "critical"
			}

			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("Telegram: @%s — %s", channel, truncate(text, 50)),
				Severity:    severity,
				Description: fmt.Sprintf("Mention of '%s' found in Telegram channel @%s: %s", target, channel, truncate(text, 300)),
				MatchedAt:   fmt.Sprintf("https://t.me/%s", channel),
				Tags:        []string{"social-monitor", "pensieve", "telegram", channel},
				References:  []string{fmt.Sprintf("https://t.me/%s", channel)},
				Fingerprint: fingerprint("pensieve", "telegram", channel, truncate(text, 100)),
			}) {
				return
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func stripHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return strings.TrimSpace(re.ReplaceAllString(s, ""))
}
