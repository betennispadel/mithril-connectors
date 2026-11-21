package main

import (
	"context"
	"fmt"
	"os"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runDarkweb(ctx context.Context, va *VoidAccessClient, target string, em *emitter) {
	inv, err := va.Investigate(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VoidAccess darkweb error: %v\n", err)
		return
	}

	for _, entity := range inv.Entities {
		severity := classifyEntitySeverity(entity)
		tags := append([]string{"darkweb", "pensieve", entity.Type}, entity.Tags...)

		name := fmt.Sprintf("Dark Web: %s — %s", entity.Type, truncate(entity.Value, 60))
		desc := fmt.Sprintf("Entity '%s' (type: %s) discovered via dark web intelligence.", entity.Value, entity.Type)
		if entity.Source != "" {
			desc += fmt.Sprintf(" Source: %s.", entity.Source)
		}

		if !em.emit(connector.Finding{
			Name:        name,
			Severity:    severity,
			Description: desc,
			MatchedAt:   entity.Value,
			Tags:        tags,
			Fingerprint: fingerprint("pensieve", "darkweb", entity.Type, entity.Value),
		}) {
			return
		}
	}
}

func classifyEntitySeverity(e VoidAccessEntity) string {
	if e.ThreatScore >= 80 {
		return "critical"
	}
	if e.ThreatScore >= 60 {
		return "high"
	}
	if e.ThreatScore >= 40 {
		return "medium"
	}
	if e.ThreatScore >= 20 {
		return "low"
	}
	return "info"
}
