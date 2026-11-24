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
// Instead of an API server, it shells out to `voidaccess investigate`
// and parses the JSON output file.
type VoidAccessClient struct{}

type VoidAccessEntity struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Source      string                 `json:"source"`
	Confidence  float64                `json:"confidence"`
	ThreatScore int                    `json:"threat_score"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]any         `json:"metadata"`
	Relations   []VoidAccessRelation   `json:"relations"`
}

type VoidAccessRelation struct {
	TargetID     string  `json:"target_id"`
	RelationType string  `json:"relation_type"`
	Confidence   float64 `json:"confidence"`
}

type VoidAccessInvestigation struct {
	ID            string             `json:"id"`
	Status        string             `json:"status"`
	Query         string             `json:"query"`
	Summary       string             `json:"summary"`
	Entities      []VoidAccessEntity `json:"entities"`
	Relationships []map[string]any   `json:"relationships"`
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

	args := []string{
		"investigate", query,
		"--output", outputDir,
		"--no-llm",
		"--format", "json",
	}

	cmd := exec.CommandContext(ctx, "voidaccess", args...)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		"DATABASE_URL=sqlite:///"+filepath.Join(workDir, "va.db"),
		"HOME="+workDir,
		"VOIDACCESS_DISABLE_QUEUE_WORKER=true",
	)
	// Map Pensieve config keys to VoidAccess env vars
	if cfg != nil {
		if cfg.VirusTotalKey != "" {
			cmd.Env = append(cmd.Env, "VT_API_KEY="+cfg.VirusTotalKey)
		}
		if cfg.HudsonRockApiKey != "" {
			cmd.Env = append(cmd.Env, "HIBP_API_KEY="+cfg.HudsonRockApiKey)
		}
	}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	// Initialize SQLite schema before running CLI
	initCmd := exec.CommandContext(ctx, "python", "-c",
		"from db import Base, get_engine; Base.metadata.create_all(get_engine())")
	initCmd.Env = cmd.Env
	initCmd.Dir = workDir
	if initOut, initErr := initCmd.CombinedOutput(); initErr != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: db init warning: %v %s\n", initErr, string(initOut))
	}

	// Start Tor daemon so VoidAccess can reach .onion sites
	torDataDir := filepath.Join(workDir, "tor-data")
	os.MkdirAll(torDataDir, 0700)
	torCmd := exec.CommandContext(ctx, "tor",
		"--RunAsDaemon", "0",
		"--SocksPort", "9050",
		"--DataDirectory", torDataDir,
		"--Log", "warn stderr",
	)
	torCmd.Stdout = os.Stderr
	torCmd.Stderr = os.Stderr
	torCmd.Env = cmd.Env
	if torErr := torCmd.Start(); torErr != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: tor start warning: %v\n", torErr)
	} else {
		defer torCmd.Process.Kill()
		for i := 0; i < 30; i++ {
			conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:9050", time.Second)
			if dialErr == nil {
				conn.Close()
				fmt.Fprintf(os.Stderr, "voidaccess: tor ready\n")
				break
			}
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Fprintf(os.Stderr, "voidaccess: running investigate %q\n", query)
	start := time.Now()

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: command failed after %v: %v\n", time.Since(start), err)
		// Don't return error — try to read partial results
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

	return &inv, nil
}

func (c *VoidAccessClient) Stop() {
	// No-op for CLI-based client
}
