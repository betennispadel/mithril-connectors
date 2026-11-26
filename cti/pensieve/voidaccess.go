package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ── VoidAccess API response types ──────────────────────────────────────────

type VoidAccessEntity struct {
	ID                   string         `json:"id"`
	Type                 string         `json:"entity_type"`
	Value                string         `json:"value"`
	CanonicalValue       string         `json:"canonical_value"`
	Confidence           float64        `json:"confidence"`
	ContextSnippet       string         `json:"context_snippet"`
	HistoricalContext     string        `json:"historical_context"`
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
	ID           string  `json:"id"`
	SourceID     string  `json:"entity_a_id"`
	TargetID     string  `json:"entity_b_id"`
	RelationType string  `json:"relationship_type"`
	Confidence   float64 `json:"confidence"`
	SourcePageID string  `json:"source_page_id"`
	SourceURL    string  `json:"source_url"`
	FirstSeen    string  `json:"first_seen"`
}

type VoidAccessPage struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Source    string `json:"source"`
	Language  string `json:"language"`
	ByteSize  int    `json:"byte_size"`
}

type VoidAccessInvestigation struct {
	ID                 string            `json:"id"`
	RunID              string            `json:"run_id"`
	Status             string            `json:"status"`
	Query              string            `json:"query"`
	RefinedQuery       string            `json:"refined_query"`
	ModelUsed          string            `json:"model_used"`
	Summary            string            `json:"summary"`
	CurrentStep        int               `json:"current_step"`
	CurrentStepLabel   string            `json:"current_step_label"`
	TotalSteps         int               `json:"total_steps"`
	EntityCount        int               `json:"entity_count"`
	RelationshipCount  int               `json:"relationship_count"`
	PageCount          int               `json:"page_count"`
	GraphStatus        string            `json:"graph_status"`
	SourcesUsed        map[string]any    `json:"sources_used"`
	Communities        map[string]int    `json:"communities"`
	InfraClusters      any               `json:"infrastructure_clusters"`
	CreatedAt          string            `json:"created_at"`
}

// VoidAccessGraph is the raw graph from VoidAccess /investigations/{id}/graph.
// Contains nodes, edges, communities — ready for sigma.js rendering.
type VoidAccessGraph struct {
	Nodes       []map[string]any `json:"nodes"`
	Edges       []map[string]any `json:"edges"`
	Communities map[string]int   `json:"communities"`
	NodeCount   int              `json:"node_count"`
	EdgeCount   int              `json:"edge_count"`
}

// VoidAccessResult is the full structured result from a VoidAccess investigation.
// It is serialized as JSON and embedded in the __pensieve_structured_result__ finding.
type VoidAccessResult struct {
	Investigation VoidAccessInvestigation `json:"investigation"`
	Entities      []VoidAccessEntity      `json:"entities"`
	Relationships []VoidAccessRelationship `json:"relationships"`
	Pages         []VoidAccessPage        `json:"pages"`
	Graph         *VoidAccessGraph        `json:"graph,omitempty"`
}

// ── VoidAccess API Client ──────────────────────────────────────────────────

type VoidAccessClient struct {
	baseURL    string
	httpClient *http.Client
	workDir    string
	torCmd     *exec.Cmd
	apiCmd     *exec.Cmd
	token      string
}

func newVoidAccessClient() *VoidAccessClient {
	return &VoidAccessClient{
		baseURL:    "http://127.0.0.1:8000",
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// Start launches the VoidAccess FastAPI sidecar + Tor daemon.
func (c *VoidAccessClient) Start(ctx context.Context, cfg *PensieveConfig) error {
	workDir, err := os.MkdirTemp("", "voidaccess-*")
	if err != nil {
		return fmt.Errorf("failed to create workdir: %w", err)
	}
	c.workDir = workDir

	// Build environment
	env := append(os.Environ(),
		"HOME="+workDir,
	)
	for _, kv := range cfg.VoidAccessEnvVars() {
		env = append(env, kv)
	}

	// 1. Start Tor
	c.startTor(ctx, env)

	// 2. Start FastAPI sidecar
	fmt.Fprintf(os.Stderr, "voidaccess: starting FastAPI sidecar on port 8000\n")
	apiCmd := exec.CommandContext(ctx, "python3", "-m", "uvicorn", "api.main:app",
		"--host", "0.0.0.0", "--port", "8000", "--log-level", "warning")
	apiCmd.Dir = workDir
	apiCmd.Env = env
	apiCmd.Stdout = os.Stderr
	apiCmd.Stderr = os.Stderr
	if err := apiCmd.Start(); err != nil {
		return fmt.Errorf("failed to start VoidAccess API: %w", err)
	}
	c.apiCmd = apiCmd

	// 3. Wait for health
	if err := c.waitForHealth(ctx, 120*time.Second); err != nil {
		return fmt.Errorf("VoidAccess API health check failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "voidaccess: API sidecar ready\n")

	// 4. Get auth token (create default user + login)
	if err := c.authenticate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: auth warning (continuing without auth): %v\n", err)
	}

	return nil
}

func (c *VoidAccessClient) startTor(ctx context.Context, env []string) {
	torDataDir := filepath.Join(c.workDir, "tor-data")
	os.MkdirAll(torDataDir, 0700)

	torArgs := []string{
		"--RunAsDaemon", "0",
		"--SocksPort", "9050",
		"--DataDirectory", torDataDir,
		"--Log", "notice stderr",
	}

	if httpsProxy := os.Getenv("HTTPS_PROXY"); httpsProxy != "" {
		torrcPath := filepath.Join(c.workDir, "torrc")
		torrcContent := buildTorrc(httpsProxy)
		if torrcContent != "" {
			os.WriteFile(torrcPath, []byte(torrcContent), 0600)
			torArgs = append(torArgs, "-f", torrcPath)
		}
	}

	torCmd := exec.CommandContext(ctx, "tor", torArgs...)
	torCmd.Stdout = os.Stderr
	torCmd.Stderr = os.Stderr
	torCmd.Env = env
	if err := torCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: tor start warning: %v\n", err)
		return
	}
	c.torCmd = torCmd

	// Wait for Tor to be ready
	for i := 0; i < 60; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:9050", time.Second)
		if err == nil {
			conn.Close()
			fmt.Fprintf(os.Stderr, "voidaccess: tor ready\n")
			return
		}
		time.Sleep(time.Second)
	}
	fmt.Fprintf(os.Stderr, "voidaccess: tor failed to start within 60s\n")
}

func (c *VoidAccessClient) waitForHealth(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, _ := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
		resp, err := c.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout after %v", timeout)
}

func (c *VoidAccessClient) authenticate(ctx context.Context) error {
	// Try to login with default admin credentials
	loginBody, _ := json.Marshal(map[string]string{
		"email":    "admin@pensieve.local",
		"password": "pensieve-sidecar-2026",
	})

	// First try to create the user (may already exist)
	createBody, _ := json.Marshal(map[string]string{
		"email":    "admin@pensieve.local",
		"password": "pensieve-sidecar-2026",
	})
	createReq, _ := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/auth/register", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createResp, _ := c.httpClient.Do(createReq)
	if createResp != nil {
		createResp.Body.Close()
	}

	// Login
	loginReq, _ := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := c.httpClient.Do(loginReq)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	defer loginResp.Body.Close()

	var loginResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginResult); err != nil {
		return fmt.Errorf("login parse failed: %w", err)
	}
	c.token = loginResult.AccessToken
	return nil
}

func (c *VoidAccessClient) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data[:min(len(data), 200)]))
	}
	return data, nil
}

// Investigate runs a full VoidAccess investigation via the REST API.
func (c *VoidAccessClient) Investigate(ctx context.Context, query string, cfg *PensieveConfig) (*VoidAccessResult, error) {
	fmt.Fprintf(os.Stderr, "voidaccess: starting investigation for %q\n", query)
	start := time.Now()

	// 1. Start investigation
	startBody := map[string]any{
		"query": query,
	}
	if cfg.OpenRouterApiKey != "" {
		startBody["model"] = "openrouter/deepseek/deepseek-chat"
	}

	data, err := c.doRequest(ctx, "POST", "/api/investigations/start", startBody)
	if err != nil {
		// Fallback: try CLI mode
		fmt.Fprintf(os.Stderr, "voidaccess: API start failed (%v), falling back to CLI\n", err)
		return c.investigateCLI(ctx, query, cfg)
	}

	var startResp struct {
		RunID  string `json:"run_id"`
		Status string `json:"status"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(data, &startResp); err != nil {
		return nil, fmt.Errorf("failed to parse start response: %w", err)
	}

	runID := startResp.RunID
	if runID == "" {
		runID = startResp.ID
	}
	fmt.Fprintf(os.Stderr, "voidaccess: investigation started, run_id=%s\n", runID)

	// 2. Poll for completion
	var inv VoidAccessInvestigation
	pollTimeout := 30 * time.Minute
	pollDeadline := time.Now().Add(pollTimeout)

	for time.Now().Before(pollDeadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		data, err := c.doRequest(ctx, "GET", "/api/investigations/"+runID, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "voidaccess: poll error: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := json.Unmarshal(data, &inv); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Fprintf(os.Stderr, "voidaccess: step %d/%d — %s (entities: %d)\n",
			inv.CurrentStep, inv.TotalSteps, inv.CurrentStepLabel, inv.EntityCount)

		switch inv.Status {
		case "completed", "completed_no_results":
			goto done
		case "failed", "cancelled":
			return nil, fmt.Errorf("investigation %s: %s", inv.Status, inv.Summary)
		}

		time.Sleep(5 * time.Second)
	}
	return nil, fmt.Errorf("investigation timed out after %v", pollTimeout)

done:
	fmt.Fprintf(os.Stderr, "voidaccess: completed in %v — %d entities, %d pages\n",
		time.Since(start), inv.EntityCount, inv.PageCount)

	// 3. Fetch entities
	entities, err := c.fetchEntities(ctx, runID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: entity fetch warning: %v\n", err)
	}

	// 4. Fetch relationships
	relationships, err := c.fetchRelationships(ctx, runID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: relationship fetch warning: %v\n", err)
	}

	// 5. Fetch pages
	pages, err := c.fetchPages(ctx, runID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: pages fetch warning: %v\n", err)
	}

	// 6. Fetch graph (nodes, edges, communities from VoidAccess)
	graph, err := c.fetchGraph(ctx, runID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "voidaccess: graph fetch warning: %v\n", err)
	}

	return &VoidAccessResult{
		Investigation: inv,
		Entities:      entities,
		Relationships: relationships,
		Pages:         pages,
		Graph:         graph,
	}, nil
}

func (c *VoidAccessClient) fetchEntities(ctx context.Context, runID string) ([]VoidAccessEntity, error) {
	var all []VoidAccessEntity
	skip := 0
	limit := 200

	for {
		path := fmt.Sprintf("/api/investigations/%s/entities?skip=%d&limit=%d", runID, skip, limit)
		data, err := c.doRequest(ctx, "GET", path, nil)
		if err != nil {
			return all, err
		}

		var resp struct {
			Items []VoidAccessEntity `json:"items"`
			Total int                `json:"total"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			// Try direct array
			var items []VoidAccessEntity
			if err2 := json.Unmarshal(data, &items); err2 != nil {
				return all, err
			}
			all = append(all, items...)
			break
		}

		all = append(all, resp.Items...)
		if len(resp.Items) < limit || len(all) >= resp.Total {
			break
		}
		skip += limit
	}

	return all, nil
}

func (c *VoidAccessClient) fetchRelationships(ctx context.Context, runID string) ([]VoidAccessRelationship, error) {
	data, err := c.doRequest(ctx, "GET", "/api/investigations/"+runID+"/relationships", nil)
	if err != nil {
		return nil, err
	}

	var rels []VoidAccessRelationship
	if err := json.Unmarshal(data, &rels); err != nil {
		var resp struct {
			Items []VoidAccessRelationship `json:"items"`
		}
		if err2 := json.Unmarshal(data, &resp); err2 != nil {
			return nil, err
		}
		return resp.Items, nil
	}
	return rels, nil
}

func (c *VoidAccessClient) fetchPages(ctx context.Context, runID string) ([]VoidAccessPage, error) {
	data, err := c.doRequest(ctx, "GET", "/api/investigations/"+runID+"/entities?type=page", nil)
	if err != nil {
		// Pages might be under a different endpoint
		return nil, err
	}

	var pages []VoidAccessPage
	json.Unmarshal(data, &pages)
	return pages, nil
}

func (c *VoidAccessClient) fetchGraph(ctx context.Context, runID string) (*VoidAccessGraph, error) {
	data, err := c.doRequest(ctx, "GET", "/api/investigations/"+runID+"/graph", nil)
	if err != nil {
		return nil, err
	}

	var graph VoidAccessGraph
	if err := json.Unmarshal(data, &graph); err != nil {
		// Try alternate format: raw NetworkX JSON
		var raw map[string]any
		if err2 := json.Unmarshal(data, &raw); err2 != nil {
			return nil, err
		}
		// Extract what we can
		if nodes, ok := raw["nodes"].([]any); ok {
			for _, n := range nodes {
				if nm, ok := n.(map[string]any); ok {
					graph.Nodes = append(graph.Nodes, nm)
				}
			}
		}
		if edges, ok := raw["edges"].([]any); ok {
			for _, e := range edges {
				if em, ok := e.(map[string]any); ok {
					graph.Edges = append(graph.Edges, em)
				}
			}
		}
		if communities, ok := raw["communities"].(map[string]any); ok {
			graph.Communities = make(map[string]int)
			for k, v := range communities {
				if fv, ok := v.(float64); ok {
					graph.Communities[k] = int(fv)
				}
			}
		}
		if nc, ok := raw["node_count"].(float64); ok {
			graph.NodeCount = int(nc)
		}
		if ec, ok := raw["edge_count"].(float64); ok {
			graph.EdgeCount = int(ec)
		}
	}

	return &graph, nil
}

// investigateCLI is the fallback when the API is not available.
// It runs the CLI and parses the JSON output file (legacy mode).
func (c *VoidAccessClient) investigateCLI(ctx context.Context, query string, cfg *PensieveConfig) (*VoidAccessResult, error) {
	outputDir := filepath.Join(c.workDir, "results")
	os.MkdirAll(outputDir, 0755)

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
		"--format", "json",
		"--depth", depth,
		"--pace", pace,
		"--quiet",
	}
	if cfg.OpenRouterApiKey == "" {
		args = append(args[:4], append([]string{"--no-llm"}, args[4:]...)...)
	}

	cmd := exec.CommandContext(ctx, "voidaccess", args...)
	cmd.Dir = c.workDir
	env := append(os.Environ(), "HOME="+c.workDir)
	for _, kv := range cfg.VoidAccessEnvVars() {
		env = append(env, kv)
	}
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	fmt.Fprintf(os.Stderr, "voidaccess: CLI fallback — investigate %q\n", query)
	start := time.Now()
	cmd.Run()
	fmt.Fprintf(os.Stderr, "voidaccess: CLI completed in %v\n", time.Since(start))

	// Find JSON output
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("no output dir: %w", err)
	}

	var jsonFile string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonFile = filepath.Join(outputDir, e.Name())
			break
		}
	}
	if jsonFile == "" {
		return nil, fmt.Errorf("no JSON output found")
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, err
	}

	// CLI output format is a single investigation object with embedded entities
	var cliResult struct {
		VoidAccessInvestigation
		Entities      []VoidAccessEntity       `json:"entities"`
		Relationships []VoidAccessRelationship  `json:"relationships"`
		PagesScraped  []VoidAccessPage          `json:"pages_scraped"`
	}
	if err := json.Unmarshal(data, &cliResult); err != nil {
		return nil, fmt.Errorf("parse CLI output: %w", err)
	}

	return &VoidAccessResult{
		Investigation: cliResult.VoidAccessInvestigation,
		Entities:      cliResult.Entities,
		Relationships: cliResult.Relationships,
		Pages:         cliResult.PagesScraped,
	}, nil
}

func (c *VoidAccessClient) Stop() {
	if c.apiCmd != nil && c.apiCmd.Process != nil {
		c.apiCmd.Process.Kill()
	}
	if c.torCmd != nil && c.torCmd.Process != nil {
		c.torCmd.Process.Kill()
	}
	if c.workDir != "" {
		os.RemoveAll(c.workDir)
	}
}

// buildTorrc generates torrc content for proxy bootstrap.
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

	lines := []string{"HTTPSProxy " + hostPort}
	if userInfo != "" {
		if !strings.Contains(userInfo, ":") {
			userInfo = userInfo + ":x"
		}
		lines = append(lines, "HTTPSProxyAuthenticator "+userInfo)
	}
	return strings.Join(lines, "\n") + "\n"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
