package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runDarkweb(ctx context.Context, va *VoidAccessClient, cfg *PensieveConfig, target string, em *emitter) {
	result, err := va.Investigate(ctx, target, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VoidAccess darkweb error: %v\n", err)
		return
	}

	inv := &result.Investigation

	// Build entity ID → entity map for relationship resolution
	entityByID := make(map[string]VoidAccessEntity, len(result.Entities))
	for _, e := range result.Entities {
		entityByID[e.ID] = e
	}

	// Build entity ID → community map
	// Emit entities as findings — with full detail
	for _, entity := range result.Entities {
		if entity.Suppressed {
			continue
		}

		severity := classifyEntitySeverity(entity)
		entityType := normalizeEntityType(entity.Type)
		category := entityTypeToCategory(entityType)

		// Build rich tags
		tags := []string{"pensieve", category, entityType}
		if entity.HighSignal {
			tags = append(tags, "high-signal")
		}
		if entity.CrossReferenced {
			tags = append(tags, "cross-referenced")
		}
		if entity.FreshnessTag != "" {
			tags = append(tags, entity.FreshnessTag)
		}
		if entity.ExtractionMethod != "" {
			tags = append(tags, "method:"+entity.ExtractionMethod)
		}
		tags = append(tags, entity.Tags...)

		name := buildEntityName(entityType, entity)
		desc := buildEntityDescription(entity, inv)

		var refs []string
		if entity.SourceURL != "" {
			refs = append(refs, entity.SourceURL)
		}

		if !em.emit(connector.Finding{
			Name:        name,
			Severity:    severity,
			Description: desc,
			MatchedAt:   entity.Value,
			Tags:        tags,
			References:  refs,
			Fingerprint: fingerprint("pensieve", "voidaccess", entity.Type, entity.Value),
		}) {
			return
		}

		// Emit enrichment finding if entity has rich context
		if entity.ContextSnippet != "" {
			metaDesc := fmt.Sprintf("Enrichment data for %s '%s'.", entityType, entity.Value)
			metaDesc += fmt.Sprintf("\n\nContext: %s", entity.ContextSnippet)

			metaTags := []string{"pensieve", "enrichment", category, entityType}
			if !em.emit(connector.Finding{
				Name:        fmt.Sprintf("Intel: %s — %s", entityType, truncate(entity.Value, 50)),
				Severity:    severity,
				Description: metaDesc,
				MatchedAt:   entity.Value,
				Tags:        metaTags,
				References:  refs,
				Fingerprint: fingerprint("pensieve", "enrichment", entity.Type, entity.Value),
			}) {
				return
			}
		}
	}

	// Emit relationships as findings
	for _, rel := range result.Relationships {
		src, srcOk := entityByID[rel.SourceID]
		tgt, tgtOk := entityByID[rel.TargetID]
		if !srcOk || !tgtOk {
			continue
		}
		if src.Suppressed || tgt.Suppressed {
			continue
		}

		relSeverity := "medium"
		if rel.Confidence > 0.8 {
			relSeverity = "high"
		}

		relName := fmt.Sprintf("Relation: %s %s %s",
			truncate(src.Value, 30), rel.RelationType, truncate(tgt.Value, 30))
		relDesc := fmt.Sprintf("Relationship discovered: %s (%s) —[%s]→ %s (%s). Confidence: %.0f%%.",
			src.Value, normalizeEntityType(src.Type),
			rel.RelationType,
			tgt.Value, normalizeEntityType(tgt.Type),
			rel.Confidence*100)
		if rel.SourceURL != "" {
			relDesc += fmt.Sprintf(" Found on: %s", rel.SourceURL)
		}

		relTags := []string{"pensieve", "relationship", rel.RelationType,
			normalizeEntityType(src.Type), normalizeEntityType(tgt.Type)}

		var relRefs []string
		if rel.SourceURL != "" {
			relRefs = append(relRefs, rel.SourceURL)
		}

		if !em.emit(connector.Finding{
			Name:        relName,
			Severity:    relSeverity,
			Description: relDesc,
			MatchedAt:   src.Value + " → " + tgt.Value,
			Tags:        relTags,
			References:  relRefs,
			Fingerprint: fingerprint("pensieve", "relation", rel.SourceID, rel.TargetID, rel.RelationType),
		}) {
			return
		}
	}

	// Emit investigation summary
	if inv.Summary != "" {
		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Investigation Summary: %s", truncate(inv.Query, 40)),
			Severity:    "info",
			Description: inv.Summary,
			MatchedAt:   inv.Query,
			Tags:        []string{"pensieve", "summary", "darkweb"},
			References:  []string{},
			Fingerprint: fingerprint("pensieve", "summary", inv.ID),
		}) {
			return
		}
	}

	// Emit notable pages as findings
	for _, page := range result.Pages {
		if page.URL == "" {
			continue
		}
		pageSource := page.Source
		if pageSource == "" {
			pageSource = "unknown"
		}

		pageTags := []string{"pensieve", "source-page", "darkweb"}
		if strings.Contains(page.URL, ".onion") {
			pageTags = append(pageTags, "onion")
		}

		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Source: %s", truncate(page.URL, 60)),
			Severity:    "info",
			Description: fmt.Sprintf("Intelligence source page discovered via %s engine. URL: %s", pageSource, page.URL),
			MatchedAt:   page.URL,
			Tags:        pageTags,
			References:  []string{page.URL},
			Fingerprint: fingerprint("pensieve", "page", page.URL),
		}) {
			return
		}
	}

	// ── Emit structured result as special finding ──
	// This carries the full VoidAccess output (entities, relationships, graph,
	// communities, investigation metadata) so the backend can write directly
	// to cti_assets, cti_asset_relations, cti_investigations, cti_pages
	// without regex re-extraction.
	structuredJSON, err := json.Marshal(result)
	if err == nil {
		em.emit(connector.Finding{
			Name:        "__pensieve_structured_result__",
			Severity:    "info",
			Description: string(structuredJSON),
			MatchedAt:   inv.Query,
			Tags:        []string{"__structured__", "pensieve"},
			References:  []string{},
			Fingerprint: fingerprint("pensieve", "structured", inv.ID),
		})
	}
}

func classifyEntitySeverity(e VoidAccessEntity) string {
	if e.PriorityScore >= 80 {
		return "critical"
	}
	if e.PriorityScore >= 60 {
		return "high"
	}
	if e.PriorityScore >= 40 {
		return "medium"
	}
	if e.PriorityScore >= 20 {
		return "low"
	}
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
	if e.HighSignal {
		return "medium"
	}
	if e.CrossReferenced {
		return "low"
	}
	return "info"
}

func normalizeEntityType(t string) string {
	t = strings.ToUpper(strings.TrimSpace(t))
	switch t {
	case "IP_ADDRESS", "IP", "IPV4", "IPV6":
		return "IP"
	case "DOMAIN", "DOMAIN_NAME":
		return "DOMAIN"
	case "EMAIL", "EMAIL_ADDRESS":
		return "EMAIL"
	case "CVE", "CVE_NUMBER":
		return "CVE"
	case "MALWARE", "MALWARE_FAMILY":
		return "MALWARE"
	case "THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "ACTOR_ALIAS":
		return "THREAT_ACTOR"
	case "RANSOMWARE_GROUP":
		return "RANSOMWARE_GROUP"
	case "MITRE_TECHNIQUE":
		return "MITRE_TECHNIQUE"
	case "ORGANIZATION_NAME", "ORGANIZATION":
		return "ORGANIZATION"
	case "URL":
		return "URL"
	case "FILE_HASH", "HASH", "HASH_MD5", "HASH_SHA1", "HASH_SHA256", "HASH_SHA512":
		return "FILE_HASH"
	case "CRYPTOCURRENCY_ADDRESS", "CRYPTO_WALLET", "BTC_ADDRESS", "ETH_ADDRESS", "MONERO_ADDRESS":
		return "CRYPTO_WALLET"
	case "TELEGRAM_USERNAME":
		return "TELEGRAM_CHANNEL"
	default:
		if t == "" {
			return "UNKNOWN"
		}
		return t
	}
}

func entityTypeToCategory(t string) string {
	switch t {
	case "IP", "DOMAIN", "URL", "FILE_HASH":
		return "ioc"
	case "CVE", "MITRE_TECHNIQUE":
		return "ioc"
	case "EMAIL":
		return "data-leak"
	case "MALWARE", "RANSOMWARE_GROUP":
		return "darkweb"
	case "THREAT_ACTOR":
		return "darkweb"
	case "ORGANIZATION":
		return "darkweb"
	case "CRYPTO_WALLET":
		return "crypto"
	default:
		return "darkweb"
	}
}

func buildEntityName(entityType string, e VoidAccessEntity) string {
	value := truncate(e.Value, 60)
	switch entityType {
	case "IP":
		return fmt.Sprintf("IP Address: %s", value)
	case "DOMAIN":
		return fmt.Sprintf("Domain: %s", value)
	case "EMAIL":
		return fmt.Sprintf("Email: %s", value)
	case "CVE":
		return fmt.Sprintf("CVE: %s", value)
	case "MALWARE":
		return fmt.Sprintf("Malware: %s", value)
	case "RANSOMWARE_GROUP":
		return fmt.Sprintf("Ransomware Group: %s", value)
	case "THREAT_ACTOR":
		return fmt.Sprintf("Threat Actor: %s", value)
	case "MITRE_TECHNIQUE":
		return fmt.Sprintf("MITRE ATT&CK: %s", value)
	case "ORGANIZATION":
		return fmt.Sprintf("Organization: %s", value)
	case "FILE_HASH":
		return fmt.Sprintf("Hash: %s", value)
	case "CRYPTO_WALLET":
		return fmt.Sprintf("Crypto Wallet: %s", value)
	case "URL":
		return fmt.Sprintf("URL: %s", value)
	default:
		return fmt.Sprintf("%s: %s", entityType, value)
	}
}

func buildEntityDescription(e VoidAccessEntity, inv *VoidAccessInvestigation) string {
	entityType := normalizeEntityType(e.Type)
	parts := []string{}

	parts = append(parts, fmt.Sprintf("Entity '%s' (type: %s) discovered via dark web intelligence investigation for '%s'.",
		e.Value, entityType, inv.Query))

	if e.Confidence > 0 {
		parts = append(parts, fmt.Sprintf("Confidence: %.0f%%.", e.Confidence*100))
	}
	if e.SourceCount > 1 {
		parts = append(parts, fmt.Sprintf("Corroborated by %d independent sources.", e.SourceCount))
	}
	if e.ExtractionMethod != "" {
		parts = append(parts, fmt.Sprintf("Extraction method: %s.", e.ExtractionMethod))
	}
	if e.SourceURL != "" {
		parts = append(parts, fmt.Sprintf("Source: %s.", e.SourceURL))
	}
	if e.ContextSnippet != "" {
		parts = append(parts, fmt.Sprintf("\n\nContext: \"%s\"", e.ContextSnippet))
	}
	if e.HighSignal {
		parts = append(parts, "HIGH SIGNAL entity.")
	}
	if e.CrossReferenced {
		parts = append(parts, fmt.Sprintf("Cross-referenced across %d investigations.", e.InvestigationCount))
	}
	if e.FreshnessTag != "" {
		parts = append(parts, fmt.Sprintf("Freshness: %s.", e.FreshnessTag))
	}

	return strings.Join(parts, " ")
}
