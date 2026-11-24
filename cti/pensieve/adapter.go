package main

import (
	"context"
	"fmt"
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

	// VoidAccess CLI client for dark web intelligence
	va := newVoidAccessClient()
	defer va.Stop()

	var wg sync.WaitGroup

	// Route to sub-adapters based on target type
	switch targetType {
	case "DOMAIN":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarDomain(ctx, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runBrandProtection(ctx, cfg, target, em) }()
		wg.Add(1)
		go func() { defer wg.Done(); runIOCDomain(ctx, cfg, target, em) }()

	case "IP":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
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
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}

	case "USERNAME":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarUsername(ctx, cfg, target, em) }()
		}

	case "KEYWORD":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
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
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runCrypto(ctx, cfg, target, em) }()

	case "ORGANIZATION":
		if cfg.OpenSanctionsApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runSanctions(ctx, cfg, target, em) }()
		}
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}

	case "THREAT_ACTOR":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runRansomware(ctx, cfg, target, em) }()

	case "FILE_HASH":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runIOCHash(ctx, cfg, target, em) }()

	case "CVE":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}

	case "TELEGRAM_CHANNEL":
		wg.Add(1)
		go func() { defer wg.Done(); runTelegram(ctx, cfg, target, em) }()

	case "URL", "ONION":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); runBrandProtection(ctx, cfg, target, em) }()

	case "PHONE":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}

	case "ASN":
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}

	case "APP_PACKAGE":
		if cfg.LeakRadarApiKey != "" {
			wg.Add(1)
			go func() { defer wg.Done(); runLeakRadarApp(ctx, cfg, target, em) }()
		}

	default:
		// Fallback: at least try VoidAccess darkweb
		if true {
			wg.Add(1)
			go func() { defer wg.Done(); runDarkweb(ctx, va, cfg, target, em) }()
		}
	}

	wg.Wait()
	return ctx.Err()
}
