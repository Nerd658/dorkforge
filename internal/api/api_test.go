package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryShodanMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "test_shodan_key" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"error": "Invalid API key"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"total": 1,
			"matches": [
				{
					"ip_str": "198.51.100.42",
					"port": 443,
					"hostnames": ["sub.example.com"],
					"org": "Example Org",
					"location": {"country_code": "US", "city": "Ashburn"}
				}
			]
		}`)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := QueryShodan(ctx, "test_shodan_key", "ssl.cert.subject.CN:example.com", server.URL)
	if err != nil {
		t.Fatalf("QueryShodan failed: %v", err)
	}

	if res.Total != 1 || len(res.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", res.Total)
	}

	if res.Matches[0].IPStr != "198.51.100.42" {
		t.Errorf("expected IP 198.51.100.42, got %s", res.Matches[0].IPStr)
	}
}

func TestQueryGitHubCodeMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test_github_token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"message": "Bad credentials"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"total_count": 1,
			"incomplete_results": false,
			"items": [
				{
					"name": ".env",
					"path": "config/.env",
					"html_url": "https://github.com/user/repo/blob/main/config/.env",
					"repository": {
						"id": 1234,
						"name": "repo",
						"full_name": "user/repo",
						"private": false,
						"html_url": "https://github.com/user/repo"
					}
				}
			]
		}`)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := QueryGitHubCode(ctx, "test_github_token", "example.com filename:.env", server.URL)
	if err != nil {
		t.Fatalf("QueryGitHubCode failed: %v", err)
	}

	if res.TotalCount != 1 || len(res.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", res.TotalCount)
	}

	if res.Items[0].Name != ".env" {
		t.Errorf("expected file .env, got %s", res.Items[0].Name)
	}
}
