package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// VoidAccessClient wraps the voidaccess CLI tool.
type VoidAccessClient struct{}

// VoidAccessEntity — full entity from VoidAccess JSON output.
type VoidAccessEntity struct {
	ID                   string         `json:"id"`
	Type                 string         `json:"entity_type"`
	Value                string         `json:"value"`
	CanonicalValue       string         `json:"canonical_value"`
	Confidence           float64        `json:"confidence"`
	ContextSnippet       string         `json:"context_snippet"`
	ExtractionMethod     string         `json:"extraction_method"`
	SourceCount          int            `json:"source_count"`
	InvestigationCount   int            `json:"investigation_count"`
	CrossReferenced      bool           `json:"cross_referenced"`
	CorroboratingSources any            `json:"corroborating_sources"`
	SourceURL            string         `json:"source_url"`
	SourceQuality        float64        `json:"source_quality"`
	FirstSeen            string         `json:"first_seen"`
	LastSeen             string         `json:"last_seen"`
	PriorityScore        float64        `json:"priority_score"`
	HighSignal           bool           `json:"high_signal"`
	FreshnessTag         string         `json:"freshness_tag"`
	Rank                 int            `json:"rank"`
	Suppressed           bool           `json:"suppressed"`
	SuppressionReason    string         `json:"suppression_reason"`
	ThreatScore          int            `json:"threat_score"`
	Tags                 []string       `json:"tags"`
	Metadata             map[string]any `json:"metadata"`
}

type VoidAccessRelationship struct {
	SourceID     string  `json:"source_id"`
	TargetID     string  `json:"target_id"`
	RelationType string  `json:"relation_type"`
	Confidence   float64 `json:"confidence"`
	PageID       string  `json:"page_id"`
	SourceURL    string  `json:"source_url"`
}

type VoidAccessPage struct {
	PageID string `json:"page_id"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

type VoidAccessInvestigation struct {
	ID            string                   `json:"id"`
	Status        string                   `json:"status"`
	Query         string                   `json:"query"`
	RefinedQuery  string                   `json:"refined_query"`
	Summary       string                   `json:"summary"`
	SummaryKind   string                   `json:"summary_kind"`
	SourcesUsed   map[string]any           `json:"sources_used"`
	Entities      []VoidAccessEntity       `json:"entities"`
	Relationships []VoidAccessRelationship `json:"relationships"`
	PagesScraped  []VoidAccessPage         `json:"pages_scraped"`
	Communities   map[string]int           `json:"communities"`
	ContentSafety map[string]int           `json:"content_safety"`
	CreatedAt     string                   `json:"created_at"`
}

func newVoidAccessClient() *VoidAccessClient {
	return &VoidAccessClient{}
}

func (c *VoidAccessClient) Investigate(ctx context.Context, query string, cfg *PensieveConfig) (*VoidAccessInvestigation, error) {
	workDir, err := os.MkdirTemp("", "voidaccess-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create workdir: %w", err)
	}
	defer os.RemoveAll(workDir)

	outputDir := filepath.Join(workDir, "results")
	os.MkdirAll(outputDir, 0755)

	eventsFile := filepath.Join(workDir, "events.jsonl")

	// Determine depth and pace from config
	depth := cfg.ScanDepth
	if depth != "shallow" && depth != "normal" && depth != "deep" {
		depth = "deep"
	}
	pace := cfg.ScanPace
	if pace != "quiet" && pace != "normal" && pace != "aggressive" {
		pace = "normal"
	}

	args := []string{
		"investigate", query,
		"--output", outputDir,
		"--no-llm",
		"--format", "json",
		"--depth", depth,
		"--pace", pace,
		"--events-jsonl", eventsFile,
		"--quiet",
	}

	cmd := exec.CommandContext(ctx, "voidaccess", args...)
	cmd.Dir = workDir

	// Build environment: base + DB + VoidAccess enrichment keys
	env := append(os.Environ(),
		"DATABASE_URL=sqlite:///"+filepath.Join(workDir, "va.db"),
		"HOME="+workDir,
		"VOIDACCESS_DISABLE_QUEUE_WORKER=true",
		// Enable concurrent collection for faster results
		"VOIDACCESS_CONCURRENT_COLLECT=1",
		// Increase enrichment timeout for deep scans
		"VOIDACCESS_ENRICHMENT_TIMEOUT=300",
	)

	// Inject all configured enrichment API keys
	for _, kv := range cfg.VoidAccessEnvVars() {
		env = append(env, kv)
	}

	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	// Initialize SQLite schema before running CLI
	initCmd := exec.CommandContext(ctx, "python3", "-c",
		"from db import Base, get_engine; Base.metadata.create_all(get_engine())")
	initCmd.Env = env
	initCmd.Dir = workDir
	if initOut, initErr := initCmd.CombinedOutput(); initErr != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: db init warning: %v %s\n", initErr, string(initOut))
	}

	// Start Tor daemon so VoidAccess can reach .onion sites
	torDataDir := filepath.Join(workDir, "tor-data")
	os.MkdirAll(torDataDir, 0700)

	torArgs := []string{
		"--RunAsDaemon", "0",
		"--SocksPort", "9050",
		"--DataDirectory", torDataDir,
		"--Log", "notice stderr",
	}
	if httpsProxy := os.Getenv("HTTPS_PROXY"); httpsProxy != "" {
		torrcPath := filepath.Join(workDir, "torrc")
		torrcContent := buildTorrc(httpsProxy)
		if torrcContent != "" {
			os.WriteFile(torrcPath, []byte(torrcContent), 0600)
			torArgs = append(torArgs, "-f", torrcPath)
			fmt.Fprintf(os.Stderr, "voidaccess: tor using HTTPS proxy for bootstrap\n")
		}
	}

	torCmd := exec.CommandContext(ctx, "tor", torArgs...)
	torCmd.Stdout = os.Stderr
	torCmd.Stderr = os.Stderr
	torCmd.Env = env
	if torErr := torCmd.Start(); torErr != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: tor start warning: %v\n", torErr)
	} else {
		defer torCmd.Process.Kill()
		for i := 0; i < 60; i++ {
			conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:9050", time.Second)
			if dialErr == nil {
				conn.Close()
				fmt.Fprintf(os.Stderr, "voidaccess: tor ready\n")
				break
			}
			time.Sleep(time.Second)
		}
	}

	fmt.Fprintf(os.Stderr, "voidaccess: running investigate %q (depth=%s, pace=%s)\n", query, depth, pace)
	start := time.Now()

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: command failed after %v: %v\n", time.Since(start), err)
	} else {
		fmt.Fprintf(os.Stderr, "voidaccess: completed in %v\n", time.Since(start))
	}

	// Find the JSON output file
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read output dir: %w", err)
	}

	var jsonFile string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonFile = filepath.Join(outputDir, e.Name())
			break
		}
	}

	if jsonFile == "" {
		return nil, fmt.Errorf("no JSON output file found in %s", outputDir)
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results: %w", err)
	}

	var inv VoidAccessInvestigation
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	fmt.Fprintf(os.Stderr, "voidaccess: parsed %d entities, %d relationships, %d pages\n",
		len(inv.Entities), len(inv.Relationships), len(inv.PagesScraped))

	return &inv, nil
}

// buildTorrc parses an HTTP(S) proxy URL and returns torrc content
// with HTTPSProxy directives so Tor can bootstrap through egress proxy.
func buildTorrc(proxyURL string) string {
	u := strings.TrimPrefix(proxyURL, "http://")
	u = strings.TrimPrefix(u, "https://")

	var userInfo, hostPort string
	if at := strings.LastIndex(u, "@"); at >= 0 {
		userInfo = u[:at]
		hostPort = u[at+1:]
	} else {
		hostPort = u
	}

	hostPort = strings.TrimRight(hostPort, "/")
	if hostPort == "" {
		return ""
	}

	lines := []string{
		"HTTPSProxy " + hostPort,
	}

	if userInfo != "" {
		if !strings.Contains(userInfo, ":") {
			userInfo = userInfo + ":x"
		}
		lines = append(lines, "HTTPSProxyAuthenticator "+userInfo)
	}

	return strings.Join(lines, "\n") + "\n"
}

func (c *VoidAccessClient) Stop() {
	// No-op for CLI-based client
}
