package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const voidAccessPort = "8099"
const voidAccessBase = "http://127.0.0.1:" + voidAccessPort

type VoidAccessClient struct {
	baseURL string
	client  *http.Client
	cmd     *exec.Cmd
}

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
	ID       string `json:"id"`
	Status   string `json:"status"`
	Query    string `json:"query"`
	Entities []VoidAccessEntity `json:"entities"`
}

func startVoidAccess(ctx context.Context) (*VoidAccessClient, error) {
	cmd := exec.CommandContext(ctx, "python", "-m", "voidaccess.api",
		"--port", voidAccessPort,
		"--host", "127.0.0.1",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start VoidAccess: %w", err)
	}

	client := &VoidAccessClient{
		baseURL: voidAccessBase,
		client:  &http.Client{Timeout: 300 * time.Second},
		cmd:     cmd,
	}

	// Wait for health check
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.client.Get(client.baseURL + "/api/status")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return client, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	cmd.Process.Kill()
	return nil, fmt.Errorf("VoidAccess failed to start within 60s")
}

func (c *VoidAccessClient) Investigate(ctx context.Context, query string) (*VoidAccessInvestigation, error) {
	body := fmt.Sprintf(`{"query": %q}`, query)
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/investigations", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VoidAccess investigate request failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("VoidAccess returned %d: %s", resp.StatusCode, string(data))
	}

	var inv VoidAccessInvestigation
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("failed to parse investigation: %w", err)
	}

	// Poll until completed
	for inv.Status == "pending" || inv.Status == "running" {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/investigations/%s", c.baseURL, inv.ID), nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err := json.Unmarshal(data, &inv); err != nil {
			return nil, err
		}
	}

	// Fetch entities
	req2, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/investigations/%s/entities", c.baseURL, inv.ID), nil)
	resp2, err := c.client.Do(req2)
	if err != nil {
		return &inv, nil
	}
	defer resp2.Body.Close()
	data2, _ := io.ReadAll(resp2.Body)
	json.Unmarshal(data2, &inv.Entities)

	return &inv, nil
}

func (c *VoidAccessClient) Stop() {
	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
}
