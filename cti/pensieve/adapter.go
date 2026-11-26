package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

type PensieveAdapter struct{}

func (PensieveAdapter) Validate(_ context.Context, inputs map[string]any) error {
	if strInput(inputs, "target") == "" {
		return fmt.Errorf("target is required")
	}
	if strInput(inputs, "ctiTargetType") == "" {
		return fmt.Errorf("ctiTargetType is required")
	}
	return nil
}

func (PensieveAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	cfg := loadConfig(ctx)
	target := strInput(inputs, "target")
	targetType := strInput(inputs, "ctiTargetType")
	em := newEmitter(ctx, out, cfg.MaxFindings)

	// VoidAccess FastAPI sidecar for dark web intelligence
	va := newVoidAccessClient()
	defer va.Stop()

	// Start the VoidAccess sidecar (Tor + FastAPI)
	if err := va.Start(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "pensieve: VoidAccess sidecar start failed:", err)
	}

	var wg sync.WaitGroup

	// Route to sub-adapters based on target type
	switch targetType {
	case "DOMAIN":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarDomain(ctx, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runBrandProtection(ctx, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runIOCDomain(ctx, cfg, target, em) }()

	case "IP":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runIOCIP(ctx, cfg, target, em) }()

	case "EMAIL":
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarEmail(ctx, cfg, target, em) }()
		}
		if cfg.HudsonRockApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runHudsonRock(ctx, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()

	case "USERNAME":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarUsername(ctx, cfg, target, em) }()
		}

	case "KEYWORD":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		if cfg.TwitterBearerToken != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runTwitter(ctx, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runTelegram(ctx, cfg, target, em) }()
		if cfg.HasDataApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runHasData(ctx, cfg, target, em) }()
		}
		if cfg.NewsDataApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runNewsData(ctx, cfg, target, em) }()
		}

	case "CRYPTO_WALLET":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runCrypto(ctx, cfg, target, em) }()

	case "ORGANIZATION":
		if cfg.OpenSanctionsApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runSanctions(ctx, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()

	case "THREAT_ACTOR":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runRansomware(ctx, cfg, target, em) }()

	case "FILE_HASH":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runIOCHash(ctx, cfg, target, em) }()

	case "CVE":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()

	case "TELEGRAM_CHANNEL":
		wg.Add(1)
		go func() { defer wg.Done(); runTelegram(ctx, cfg, target, em) }()

	case "URL", "ONION":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runBrandProtection(ctx, cfg, target, em) }()

	case "PHONE":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()

	case "ASN":
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()

	case "APP_PACKAGE":
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarApp(ctx, cfg, target, em) }()
		}

	default:
		wg.Add(1)
		go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
	}

	wg.Wait()
	return ctx.Err()
}
