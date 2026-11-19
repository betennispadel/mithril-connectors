package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/gitrepo"
)

// SemgrepConfig is decoded from OASM_CONFIG / per-job config profile.
type SemgrepConfig struct {
	Rulesets    []string `json:"rulesets"`
	Severity    []string `json:"severity"`
	MaxFindings int      `json:"maxFindings"`
}

// SemgrepAdapter implements connector.Adapter.
type SemgrepAdapter struct{}

// Validate checks that the required repository input is present.
func (SemgrepAdapter) Validate(ctx context.Context, inputs map[string]any) error {
	_, err := gitrepo.ParseInputs(inputs)
	return err
}

// fixProxyAuth rewrites http://TOKEN@host:port → http://TOKEN:@host:port so that
// git doesn't prompt for a password when using the egress proxy.
var proxyTokenRe = regexp.MustCompile(`(https?://)([^:/@\s]+)(@)`)

func fixProxyAuth() {
	proxyVars := []string{
		"WORKER_EGRESS_PROXY",
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
	}
	for _, k := range proxyVars {
		v := os.Getenv(k)
		if v == "" || v == "off" {
			continue
		}
		fixed := proxyTokenRe.ReplaceAllString(v, "${1}${2}:${2}${3}")
		if fixed != v {
			os.Setenv(k, fixed)
		}
	}

	// Also write to global git config so sub-processes inherit it.
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(k); v != "" && v != "off" {
			exec.Command("git", "config", "--global", "http.proxy", v).Run()
			break
		}
	}
}

// Execute clones the repository, runs semgrep, and streams findings.
func (SemgrepAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	// Fix egress proxy credentials before any git operation.
	fixProxyAuth()

	cfg, err := connector.LoadConfig[SemgrepConfig](ctx)
	if err != nil {
		return fmt.Errorf("fatal: load config: %w", err)
	}

	rulesets := cfg.Rulesets
	if len(rulesets) == 0 {
		rulesets = []string{"auto"}
	}
	maxFindings := cfg.MaxFindings
	if maxFindings == 0 {
		maxFindings = 500
	}

	severityFilter := map[string]bool{}
	for _, s := range cfg.Severity {
		severityFilter[strings.ToLower(s)] = true
	}

	in, err := gitrepo.ParseInputs(inputs)
	if err != nil {
		return fmt.Errorf("fatal: %w", err)
	}

	checkout, err := gitrepo.Clone(ctx, in, gitrepo.Options{})
	if err != nil {
		return fmt.Errorf("retryable: clone: %w", err)
	}
	defer checkout.Close()

	resultsFile := filepath.Join(os.TempDir(), fmt.Sprintf("semgrep-%s.json", checkout.Commit[:8]))
	defer os.Remove(resultsFile)

	args := []string{"scan"}
	for _, r := range rulesets {
		args = append(args, "--config="+r)
	}
	args = append(args, "--json", "-o", resultsFile, "--no-git-ignore", ".")

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	cmd.Dir = checkout.Dir
	out2, runErr := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("retryable: semgrep cancelled: %w", ctx.Err())
	}
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// exit 1 = findings present, normal
		} else {
			return fmt.Errorf("retryable: semgrep failed (exit %v): %s", runErr, truncate(string(out2), 500))
		}
	}

	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil
	}

	var report semgrepReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("retryable: parse semgrep output: %w", err)
	}

	sent := 0
	for _, r := range report.Results {
		if maxFindings > 0 && sent >= maxFindings {
			break
		}

		sev := mapSeverity(r.Extra.Severity)

		if len(severityFilter) > 0 && !severityFilter[sev] {
			continue
		}

		var cwes []string
		for _, c := range r.Extra.Metadata.CWE {
			cwes = append(cwes, normalizeCWE(c))
		}

		fingerprint := r.Extra.Fingerprint
		if fingerprint == "" {
			fingerprint = fmt.Sprintf("%s:%s:%d", r.CheckID, r.Path, r.Start.Line)
		}

		f := connector.Finding{
			Name:        r.CheckID,
			Severity:    sev,
			Description: r.Extra.Message,
			FilePath:    r.Path,
			LineStart:   int32(r.Start.Line),
			LineEnd:     int32(r.End.Line),
			Fingerprint: fingerprint,
			CWEID:       cwes,
			References:  r.Extra.Metadata.References,
			Commit:      checkout.Commit,
			MatchedAt:   fmt.Sprintf("%s:%d", r.Path, r.Start.Line),
		}

		select {
		case out <- f:
			sent++
		case <-ctx.Done():
			return fmt.Errorf("retryable: cancelled after %d findings: %w", sent, ctx.Err())
		}
	}

	return nil
}

type semgrepReport struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Severity    string          `json:"severity"`
	Message     string          `json:"message"`
	Fingerprint string          `json:"fingerprint"`
	Metadata    semgrepMetadata `json:"metadata"`
}

type semgrepMetadata struct {
	CWE        []string `json:"cwe"`
	References []string `json:"references"`
}

func mapSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "ERROR", "HIGH", "CRITICAL":
		return "high"
	case "WARNING", "MEDIUM":
		return "medium"
	default:
		return "info"
	}
}

func normalizeCWE(s string) string {
	parts := strings.SplitN(s, ":", 2)
	cwe := strings.TrimSpace(parts[0])
	if strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
		return strings.ToUpper(cwe)
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
