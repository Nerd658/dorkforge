package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestClassifyURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
		category models.Category
	}{
		{"https://example.com/.env", true, models.CategoryConfigs},
		{"https://example.com/backup.sql", true, models.CategoryBackups},
		{"https://example.com/admin/login.php", true, models.CategoryAdmin},
		{"https://example.com/api/v1/users", true, models.CategoryAPIEndpoints},
		{"https://example.com/confidential.pdf", true, models.CategoryDocs},
		{"https://example.com/app.css", false, ""},
		{"https://example.com/logo.png", false, ""},
	}

	for _, tt := range tests {
		sens, cat := ClassifyURL(tt.url)
		if sens != tt.expected {
			t.Errorf("url %s: expected sensitive=%v, got %v", tt.url, tt.expected, sens)
		}
		if tt.expected && cat != tt.category {
			t.Errorf("url %s: expected category=%s, got %s", tt.url, tt.category, cat)
		}
	}
}

func TestFetchAllMock(t *testing.T) {
	wbServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			["original", "mimetype", "statuscode", "timestamp"],
			["https://example.com/.env", "text/plain", "200", "20230101000000"],
			["https://example.com/about", "text/html", "200", "20230101000000"]
		]`))
	}))
	defer wbServer.Close()

	otxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"url_list": [
				{
					"url": "https://example.com/backup.sql",
					"date": "2023-01-01",
					"httpcode": 200,
					"result": { "urlworker": { "mime": "application/sql" } }
				}
			]
		}`))
	}))
	defer otxServer.Close()

	oldWB := waybackCDXURL
	oldOTX := alienVaultOTXURL
	waybackCDXURL = wbServer.URL
	alienVaultOTXURL = otxServer.URL
	defer func() {
		waybackCDXURL = oldWB
		alienVaultOTXURL = oldOTX
	}()

	opts := DefaultFetchOptions()
	opts.Timeout = 2 * time.Second

	res, err := FetchAll(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.TotalURLs < 2 {
		t.Errorf("expected at least 2 URLs, got %d", res.TotalURLs)
	}
	if res.SensitiveURLs < 2 {
		t.Errorf("expected at least 2 sensitive URLs (.env, backup.sql), got %d", res.SensitiveURLs)
	}
}
