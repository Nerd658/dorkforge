package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type GoogleCSESnippetItem struct {
	Title   string `json:"title"`
	Link    string `json:"link"`
	Snippet string `json:"snippet"`
}

type GoogleCSESearchResult struct {
	SearchInformation struct {
		TotalResults string `json:"totalResults"`
	} `json:"searchInformation"`
	Items []GoogleCSESnippetItem `json:"items"`
	Error struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

func QueryGoogleCSE(ctx context.Context, apiKey string, cxID string, query string, baseURL string) (*GoogleCSESearchResult, error) {
	if apiKey == "" || cxID == "" {
		return nil, fmt.Errorf("google API key and CX ID are required")
	}

	if baseURL == "" {
		baseURL = "https://www.googleapis.com"
	}

	endpoint := fmt.Sprintf("%s/customsearch/v1?key=%s&cx=%s&q=%s",
		baseURL,
		url.QueryEscape(apiKey),
		url.QueryEscape(cxID),
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
		return nil, fmt.Errorf("google CSE API HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res GoogleCSESearchResult
		_ = json.NewDecoder(resp.Body).Decode(&res)
		if res.Error.Message != "" {
			return nil, fmt.Errorf("google CSE API error (%d): %s", resp.StatusCode, res.Error.Message)
		}
		return nil, fmt.Errorf("google CSE API returned status %d", resp.StatusCode)
	}

	var res GoogleCSESearchResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode Google CSE response: %w", err)
	}

	return &res, nil
}
