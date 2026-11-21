package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

const leakRadarBase = "https://api.leakradar.com/v1"

type leakRadarClient struct {
	apiKey string
	client *http.Client
}

func newLeakRadarClient(apiKey string) *leakRadarClient {
	return &leakRadarClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *leakRadarClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", leakRadarBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("LeakRadar %s returned %d: %s", path, resp.StatusCode, truncate(string(data), 200))
	}
	return data, nil
}

type leakRadarResult struct {
	Source      string `json:"source"`
	Date        string `json:"date"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	HashedPwd   string `json:"hashed_password"`
	IP          string `json:"ip"`
	Phone       string `json:"phone"`
	Domain      string `json:"domain"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

func runLeakRadarDomain(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	c := newLeakRadarClient(cfg.LeakRadarApiKey)
	path := "/domain/" + url.PathEscape(target)
	data, err := c.get(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LeakRadar domain error: %v\n", err)
		return
	}

	var results []leakRadarResult
	if err := json.Unmarshal(data, &results); err != nil {
		fmt.Fprintf(os.Stderr, "LeakRadar parse error: %v\n", err)
		return
	}

	for _, r := range results {
		emitLeakFinding(r, target, "domain", em)
	}
}

func runLeakRadarEmail(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	c := newLeakRadarClient(cfg.LeakRadarApiKey)
	path := "/email/" + url.PathEscape(target)
	data, err := c.get(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LeakRadar email error: %v\n", err)
		return
	}

	var results []leakRadarResult
	if err := json.Unmarshal(data, &results); err != nil {
		return
	}

	for _, r := range results {
		emitLeakFinding(r, target, "email", em)
	}
}

func runLeakRadarUsername(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	c := newLeakRadarClient(cfg.LeakRadarApiKey)
	path := "/username/" + url.PathEscape(target)
	data, err := c.get(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LeakRadar username error: %v\n", err)
		return
	}

	var results []leakRadarResult
	if err := json.Unmarshal(data, &results); err != nil {
		return
	}

	for _, r := range results {
		emitLeakFinding(r, target, "username", em)
	}
}

func runLeakRadarApp(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	c := newLeakRadarClient(cfg.LeakRadarApiKey)
	path := "/app/" + url.PathEscape(target)
	data, err := c.get(ctx, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LeakRadar app error: %v\n", err)
		return
	}

	var results []leakRadarResult
	if err := json.Unmarshal(data, &results); err != nil {
		return
	}

	for _, r := range results {
		emitLeakFinding(r, target, "app", em)
	}
}

func emitLeakFinding(r leakRadarResult, target, entityType string, em *emitter) {
	severity := "high"
	if r.Password != "" || r.HashedPwd != "" {
		severity = "critical"
	}

	matchedAt := r.Email
	if matchedAt == "" {
		matchedAt = r.Username
	}
	if matchedAt == "" {
		matchedAt = target
	}

	name := fmt.Sprintf("Data Leak: %s", r.Source)
	desc := fmt.Sprintf("Credential leak found in '%s'.", r.Source)
	if r.Date != "" {
		desc += fmt.Sprintf(" Date: %s.", r.Date)
	}
	if r.Email != "" {
		desc += fmt.Sprintf(" Email: %s.", r.Email)
	}
	if r.Password != "" {
		desc += " Contains plaintext password."
	} else if r.HashedPwd != "" {
		desc += " Contains hashed password."
	}

	tags := []string{"data-leak", "pensieve", entityType}
	if r.Password != "" || r.HashedPwd != "" {
		tags = append(tags, "credential")
	}

	em.emit(connector.Finding{
		Name:        name,
		Severity:    severity,
		Description: desc,
		MatchedAt:   matchedAt,
		Tags:        tags,
		Fingerprint: fingerprint("pensieve", "leakradar", r.Source, matchedAt),
	})
}
