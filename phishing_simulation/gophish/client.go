package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// gophishClient wraps the GoPhish REST API.
type gophishClient struct {
	base   string // e.g. "https://127.0.0.1:3333"
	apiKey string
	http   *http.Client
}

func newGophishClient(base, apiKey string) *gophishClient {
	return &gophishClient{
		base:   base,
		apiKey: apiKey,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsSkipVerify(),
			},
		},
	}
}

func (c *gophishClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path+"?api_key="+c.apiKey, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("retryable: gophish API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gophish API %s %s returned %d: %s", method, path, resp.StatusCode, string(data))
	}
	return data, nil
}

// --- SMTP / Sending Profile ---

type smtpProfile struct {
	ID               int64             `json:"id,omitempty"`
	Name             string            `json:"name"`
	InterfaceType    string            `json:"interface_type"`
	Host             string            `json:"host"`
	Username         string            `json:"username,omitempty"`
	Password         string            `json:"password,omitempty"`
	FromAddress      string            `json:"from_address"`
	IgnoreCertErrors bool              `json:"ignore_cert_errors"`
	Headers          []smtpHeader      `json:"headers,omitempty"`
}

type smtpHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (c *gophishClient) createSMTP(ctx context.Context, p smtpProfile) (*smtpProfile, error) {
	p.InterfaceType = "SMTP"
	data, err := c.do(ctx, "POST", "/api/smtp/", p)
	if err != nil {
		return nil, err
	}
	var out smtpProfile
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) deleteSMTP(ctx context.Context, id int64) error {
	_, err := c.do(ctx, "DELETE", fmt.Sprintf("/api/smtp/%d", id), nil)
	return err
}

// --- Template ---

type gpTemplate struct {
	ID      int64            `json:"id,omitempty"`
	Name    string           `json:"name"`
	Subject string           `json:"subject"`
	HTML    string           `json:"html"`
	Text    string           `json:"text,omitempty"`
}

func (c *gophishClient) createTemplate(ctx context.Context, t gpTemplate) (*gpTemplate, error) {
	data, err := c.do(ctx, "POST", "/api/templates/", t)
	if err != nil {
		return nil, err
	}
	var out gpTemplate
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) deleteTemplate(ctx context.Context, id int64) error {
	_, err := c.do(ctx, "DELETE", fmt.Sprintf("/api/templates/%d", id), nil)
	return err
}

// --- Landing Page ---

type gpPage struct {
	ID                 int64  `json:"id,omitempty"`
	Name               string `json:"name"`
	HTML               string `json:"html"`
	CaptureCredentials bool   `json:"capture_credentials"`
	CapturePasswords   bool   `json:"capture_passwords"`
	RedirectURL        string `json:"redirect_url,omitempty"`
}

func (c *gophishClient) createPage(ctx context.Context, p gpPage) (*gpPage, error) {
	data, err := c.do(ctx, "POST", "/api/pages/", p)
	if err != nil {
		return nil, err
	}
	var out gpPage
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) deletePage(ctx context.Context, id int64) error {
	_, err := c.do(ctx, "DELETE", fmt.Sprintf("/api/pages/%d", id), nil)
	return err
}

// --- Group ---

type gpGroup struct {
	ID      int64        `json:"id,omitempty"`
	Name    string       `json:"name"`
	Targets []gpTarget   `json:"targets"`
}

type gpTarget struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Position  string `json:"position,omitempty"`
}

func (c *gophishClient) createGroup(ctx context.Context, g gpGroup) (*gpGroup, error) {
	data, err := c.do(ctx, "POST", "/api/groups/", g)
	if err != nil {
		return nil, err
	}
	var out gpGroup
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) deleteGroup(ctx context.Context, id int64) error {
	_, err := c.do(ctx, "DELETE", fmt.Sprintf("/api/groups/%d", id), nil)
	return err
}

// --- Campaign ---

type gpCampaign struct {
	ID            int64            `json:"id,omitempty"`
	Name          string           `json:"name"`
	CreatedDate   time.Time        `json:"created_date,omitempty"`
	LaunchDate    time.Time        `json:"launch_date"`
	SendByDate    time.Time        `json:"send_by_date,omitempty"`
	CompletedDate *time.Time       `json:"completed_date,omitempty"`
	Status        string           `json:"status,omitempty"`
	URL           string           `json:"url"`
	Template      gpTemplateRef    `json:"template"`
	Page          gpPageRef        `json:"page"`
	SMTP          gpSMTPRef        `json:"smtp"`
	Groups        []gpGroupRef     `json:"groups"`
	Results       []gpResult       `json:"results,omitempty"`
	Timeline      []gpEvent        `json:"timeline,omitempty"`
}

type gpTemplateRef struct{ Name string `json:"name"` }
type gpPageRef     struct{ Name string `json:"name"` }
type gpSMTPRef     struct{ Name string `json:"name"` }
type gpGroupRef    struct{ Name string `json:"name"` }

type gpResult struct {
	ID        string  `json:"id"`
	Email     string  `json:"email"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	Position  string  `json:"position"`
	Status    string  `json:"status"`
	IP        string  `json:"ip"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Reported  bool    `json:"reported"`
}

type gpEvent struct {
	Email   string    `json:"email"`
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
	Details string    `json:"details"`
}

type gpCampaignSummary struct {
	Total         int `json:"total"`
	Sent          int `json:"sent"`
	Opened        int `json:"opened"`
	Clicked       int `json:"clicked"`
	SubmittedData int `json:"submitted_data"`
	EmailReported int `json:"email_reported"`
	Error         int `json:"error"`
}

type gpCampaignStats struct {
	Stats gpCampaignSummary `json:"stats"`
}

func (c *gophishClient) createCampaign(ctx context.Context, camp gpCampaign) (*gpCampaign, error) {
	data, err := c.do(ctx, "POST", "/api/campaigns/", camp)
	if err != nil {
		return nil, err
	}
	var out gpCampaign
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) getCampaign(ctx context.Context, id int64) (*gpCampaign, error) {
	data, err := c.do(ctx, "GET", fmt.Sprintf("/api/campaigns/%d", id), nil)
	if err != nil {
		return nil, err
	}
	var out gpCampaign
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) getCampaignSummary(ctx context.Context, id int64) (*gpCampaignStats, error) {
	data, err := c.do(ctx, "GET", fmt.Sprintf("/api/campaigns/%d/summary", id), nil)
	if err != nil {
		return nil, err
	}
	var out gpCampaignStats
	return &out, json.Unmarshal(data, &out)
}

func (c *gophishClient) completeCampaign(ctx context.Context, id int64) error {
	_, err := c.do(ctx, "GET", fmt.Sprintf("/api/campaigns/%d/complete", id), nil)
	return err
}

func (c *gophishClient) deleteCampaign(ctx context.Context, id int64) error {
	_, err := c.do(ctx, "DELETE", fmt.Sprintf("/api/campaigns/%d", id), nil)
	return err
}
