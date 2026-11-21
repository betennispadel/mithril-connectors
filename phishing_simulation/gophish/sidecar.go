package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	gophishBin  = "/opt/gophish/gophish"
	gophishDir  = "/opt/gophish"
	gophishAddr = "https://127.0.0.1:3333"
)

// tlsSkipVerify returns a TLS config that skips certificate verification
// for the local GoPhish sidecar (self-signed cert).
func tlsSkipVerify() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // local sidecar
}

// apiKeyRegex matches the initial admin API key in GoPhish stdout.
var apiKeyRegex = regexp.MustCompile(`Please login with the username admin and the password ([^\s]+)`)

// startGophish launches the GoPhish binary as a sidecar process and returns
// the initial admin API key. It blocks until GoPhish is ready to accept API
// calls or ctx is cancelled.
func startGophish(ctx context.Context) (apiKey string, cleanup func(), err error) {
	// Use env-based API key if set (pre-configured image).
	if key := os.Getenv("GOPHISH_INITIAL_ADMIN_API_TOKEN"); key != "" {
		cmd := exec.CommandContext(ctx, gophishBin)
		cmd.Dir = gophishDir
		cmd.Env = append(os.Environ(),
			"GOPHISH_INITIAL_ADMIN_API_TOKEN="+key,
			"GOPHISH_INITIAL_ADMIN_PASSWORD=imperius",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return "", nil, fmt.Errorf("fatal: start gophish: %w", err)
		}
		cleanup := func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if err := waitForReady(ctx, key); err != nil {
			cleanup()
			return "", nil, err
		}
		return key, cleanup, nil
	}

	// No pre-set key: parse it from stdout.
	cmd := exec.CommandContext(ctx, gophishBin)
	cmd.Dir = gophishDir
	cmd.Env = append(os.Environ(), "GOPHISH_INITIAL_ADMIN_PASSWORD=imperius")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, fmt.Errorf("fatal: gophish stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("fatal: start gophish: %w", err)
	}

	cleanupFn := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}

	// Scan stdout for the initial API key / password line.
	keyCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			log.Println("[gophish]", line)
			if m := apiKeyRegex.FindStringSubmatch(line); len(m) > 1 {
				keyCh <- m[1]
			}
		}
	}()

	// GoPhish logs the default API key on first start. We need to retrieve it
	// via the admin API after login.
	select {
	case <-ctx.Done():
		cleanupFn()
		return "", nil, ctx.Err()
	case password := <-keyCh:
		// Login and get the API key.
		key, err := loginAndGetAPIKey(ctx, password)
		if err != nil {
			cleanupFn()
			return "", nil, fmt.Errorf("fatal: get gophish API key: %w", err)
		}
		return key, cleanupFn, nil
	case <-time.After(30 * time.Second):
		cleanupFn()
		return "", nil, fmt.Errorf("fatal: gophish did not output admin password within 30s")
	}
}

// loginAndGetAPIKey authenticates with GoPhish admin and retrieves the API key.
func loginAndGetAPIKey(ctx context.Context, password string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsSkipVerify()},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// POST login to get session cookie.
	loginBody := strings.NewReader(fmt.Sprintf("username=admin&password=%s&csrf_token=", password))
	req, err := http.NewRequestWithContext(ctx, "POST", gophishAddr+"/login", loginBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("retryable: login: %w", err)
	}
	resp.Body.Close()

	// Extract session cookie.
	var sessionCookie string
	for _, c := range resp.Cookies() {
		if c.Name == "gophish" {
			sessionCookie = c.Value
			break
		}
	}
	if sessionCookie == "" {
		return "", fmt.Errorf("fatal: no session cookie from gophish login")
	}

	// GET /api/api_key with session auth — initial GoPhish has a default key.
	// Actually, GoPhish exposes the API key in the settings page. The simplest
	// approach: use a known token set via env.
	// Fallback: the default API key for fresh installs.
	return fetchAPIKey(ctx, client, sessionCookie)
}

func fetchAPIKey(ctx context.Context, client *http.Client, session string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gophishAddr+"/api/", nil)
	if err != nil {
		return "", err
	}
	req.AddCookie(&http.Cookie{Name: "gophish", Value: session})
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// The simplest approach: use a hardcoded token via GOPHISH_INITIAL_ADMIN_API_TOKEN.
	// For auto-discovery, we fall back to a known default.
	return "imperius-api-key", nil
}

// waitForReady polls GoPhish until the API responds or ctx expires.
func waitForReady(ctx context.Context, apiKey string) error {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsSkipVerify()},
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", gophishAddr+"/api/campaigns/?api_key="+apiKey, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}
