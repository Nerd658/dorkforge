package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type ShodanLocation struct {
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
}

type ShodanMatch struct {
	IPStr     string         `json:"ip_str"`
	Port      int            `json:"port"`
	Hostnames []string       `json:"hostnames"`
	Org       string         `json:"org"`
	ISP       string         `json:"isp"`
	Product   string         `json:"product"`
	Location  ShodanLocation `json:"location"`
	Timestamp string         `json:"timestamp"`
}

type ShodanSearchResult struct {
	Total   int           `json:"total"`
	Matches []ShodanMatch `json:"matches"`
	Error   string        `json:"error,omitempty"`
}

func QueryShodan(ctx context.Context, apiKey string, query string, baseURL string) (*ShodanSearchResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("shodan API key is empty")
	}

	if baseURL == "" {
		baseURL = "https://api.shodan.io"
	}

	endpoint := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&minify=true",
		baseURL,
		url.QueryEscape(apiKey),
		url.QueryEscape(query),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "DorkForge/1.0 (+https://github.com/Nerd658/dorkforge)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan API HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return nil, fmt.Errorf("shodan API error (%d): %s", resp.StatusCode, apiErr.Error)
		}
		return nil, fmt.Errorf("shodan API returned status %d", resp.StatusCode)
	}

	var res ShodanSearchResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode shodan response: %w", err)
	}

	return &res, nil
}
