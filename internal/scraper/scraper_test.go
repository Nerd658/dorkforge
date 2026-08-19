package scraper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractCleanTargetURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2F.env&rut=...",
			expected: "https://example.com/.env",
		},
		{
			input:    "https://example.com/admin/login",
			expected: "https://example.com/admin/login",
		},
		{
			input:    "http://target.org/backup.sql",
			expected: "http://target.org/backup.sql",
		},
	}

	for _, tt := range tests {
		got := ExtractCleanTargetURL(tt.input)
		if got != tt.expected {
			t.Errorf("ExtractCleanTargetURL(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestScrapeDuckDuckGoMock(t *testing.T) {
	mockHTML := `
	<html>
	<body>
	<div class="result results_links">
		<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fsecret.env&rut=1">Exposed Config File</a>
		<a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fsecret.env&rut=1">DB_PASSWORD=123</a>
	</div>
	<div class="result results_links">
		<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fbackup.sql&rut=1">SQL Dump File</a>
	</div>
	</body>
	</html>
	`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(mockHTML))
	}))
	defer ts.Close()

	oldURL := duckDuckGoHTMLURL
	duckDuckGoHTMLURL = ts.URL
	defer func() {
		duckDuckGoHTMLURL = oldURL
	}()

	opts := DefaultScraperOptions()
	opts.Timeout = 2 * time.Second

	res, err := ScrapeDuckDuckGo(context.Background(), "site:example.com filename:.env", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.TotalFound != 2 {
		t.Fatalf("expected 2 results, got %d", res.TotalFound)
	}
	if res.Items[0].TargetURL != "https://example.com/secret.env" {
		t.Errorf("expected target URL https://example.com/secret.env, got %s", res.Items[0].TargetURL)
	}
}
