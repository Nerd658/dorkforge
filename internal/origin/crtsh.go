package origin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CRTEntry struct {
	IssuerCaID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	EntryTimestamp string `json:"entry_timestamp"`
	ID             int64  `json:"id"`

}

func QueryCRTLog(ctx context.Context, domain string, baseURL string) ([]CRTEntry, []string, error) {
	if baseURL == "" {
		baseURL = "https://crt.sh"
	}

	endpoint := fmt.Sprintf("%s/?q=%%25.%s&output=json", baseURL, url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", "DorkForge-CertIntel/1.1 (+https://github.com/Nerd658/dorkforge)")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("crt.sh returned HTTP status %d", resp.StatusCode)
	}

	var entries []CRTEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, nil, fmt.Errorf("failed to decode crt.sh JSON response: %w", err)
	}

	subdomainMap := make(map[string]bool)
	subdomainMap[strings.ToLower(domain)] = true

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			clean := strings.ToLower(strings.TrimSpace(name))
			if strings.HasPrefix(clean, "*.") {
				clean = clean[2:]
			}
			if clean != "" && !strings.Contains(clean, "*") && strings.HasSuffix(clean, domain) {
				subdomainMap[clean] = true
			}
		}
	}

	subdomains := make([]string, 0, len(subdomainMap))
	for sub := range subdomainMap {
		subdomains = append(subdomains, sub)
	}

	return entries, subdomains, nil
}
