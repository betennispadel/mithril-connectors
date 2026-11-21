package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/betennispadel/mithril-connectors/sdk/connector"
)

func runRansomware(ctx context.Context, cfg *PensieveConfig, target string, em *emitter) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ransomware.live/recentvictims", nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ransomware.live error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	var victims []struct {
		Name       string `json:"post_title"`
		Group      string `json:"group_name"`
		Published  string `json:"published"`
		URL        string `json:"post_url"`
		Country    string `json:"country"`
		Activity   string `json:"activity"`
		Website    string `json:"website"`
	}

	if json.Unmarshal(data, &victims) != nil {
		return
	}

	keyword := strings.ToLower(target)
	for _, v := range victims {
		if !strings.Contains(strings.ToLower(v.Name), keyword) &&
			!strings.Contains(strings.ToLower(v.Website), keyword) {
			continue
		}

		desc := fmt.Sprintf("Ransomware victim '%s' claimed by group '%s'.", v.Name, v.Group)
		if v.Published != "" {
			desc += fmt.Sprintf(" Published: %s.", v.Published)
		}
		if v.Country != "" {
			desc += fmt.Sprintf(" Country: %s.", v.Country)
		}

		if !em.emit(connector.Finding{
			Name:        fmt.Sprintf("Ransomware: %s — %s", v.Group, truncate(v.Name, 40)),
			Severity:    "critical",
			Description: desc,
			MatchedAt:   v.Name,
			Tags:        []string{"darkweb", "pensieve", "ransomware", v.Group},
			References:  []string{"https://ransomware.live"},
			Fingerprint: fingerprint("pensieve", "ransomware", v.Group, v.Name),
		}) {
			return
		}
	}
}
