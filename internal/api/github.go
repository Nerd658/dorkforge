package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type GitHubRepo struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
	HTMLURL  string `json:"html_url"`
}

type GitHubTextMatch struct {
	Fragment string `json:"fragment"`
	Property string `json:"property"`
}

type GitHubCodeItem struct {
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	HTMLURL     string            `json:"html_url"`
	Repository  GitHubRepo        `json:"repository"`
	TextMatches []GitHubTextMatch `json:"text_matches,omitempty"`
}

type GitHubSearchResult struct {
	TotalCount        int              `json:"total_count"`
	IncompleteResults bool             `json:"incomplete_results"`
	Items             []GitHubCodeItem `json:"items"`
}

func QueryGitHubCode(ctx context.Context, token string, query string, baseURL string) (*GitHubSearchResult, error) {
	if token == "" {
		return nil, fmt.Errorf("gitHub token is empty")
	}

	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	endpoint := fmt.Sprintf("%s/search/code?q=%s",
		baseURL,
		url.QueryEscape(query),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3.text-match+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "DorkForge/1.0 (+https://github.com/Nerd658/dorkforge)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitHub API HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Message != "" {
			return nil, fmt.Errorf("gitHub API error (%d): %s", resp.StatusCode, apiErr.Message)
		}
		return nil, fmt.Errorf("gitHub API returned status %d", resp.StatusCode)
	}

	var res GitHubSearchResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode gitHub response: %w", err)
	}

	return &res, nil
}
