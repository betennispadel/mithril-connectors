package main

import (
	"context"
	"encoding/json"
	"fmt"
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

func (c *VoidAccessClient) Investigate(ctx context.Context, query string) (*VoidAccessInvestigation, error) {
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
		"--no-tor",
		"--format", "json",
	}

	cmd := exec.CommandContext(ctx, "voidaccess", args...)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		"DATABASE_URL=sqlite:///"+filepath.Join(workDir, "va.db"),
		"HOME="+workDir,
		"VOIDACCESS_DISABLE_QUEUE_WORKER=true",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

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
