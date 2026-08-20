package origin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIsCDNIP(t *testing.T) {
	isCDN, provider := IsCDNIP("104.16.1.1")
	if !isCDN || provider != "Cloudflare" {
		t.Errorf("expected 104.16.1.1 to be Cloudflare, got isCDN=%v, provider=%s", isCDN, provider)
	}

	isCDN2, _ := IsCDNIP("13.140.162.31")
	if isCDN2 {
		t.Errorf("expected 13.140.162.31 to NOT be CDN IP")
	}
}

func TestDomainMatching(t *testing.T) {
	if !matchesDomain("api.example.com", "example.com") {
		t.Errorf("expected api.example.com to match example.com")
	}
	if !matchesDomain("*.example.com", "api.example.com") {
		t.Errorf("expected *.example.com to match api.example.com")
	}
	if matchesDomain("otherdomain.org", "example.com") {
		t.Errorf("expected otherdomain.org NOT to match example.com")
	}
}

func TestQueryCRTLogMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `[
			{
				"issuer_ca_id": 1,
				"issuer_name": "Let's Encrypt",
				"common_name": "example.com",
				"name_value": "example.com\napi.example.com\n*.sub.example.com",
				"entry_timestamp": "2026-08-01T00:00:00Z",
				"id": 12345
			}
		]`)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	entries, subdomains, err := QueryCRTLog(ctx, "example.com", server.URL)
	if err != nil {
		t.Fatalf("QueryCRTLog failed: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}

	hasAPI := false
	for _, sub := range subdomains {
		if sub == "api.example.com" {
			hasAPI = true
			break
		}
	}

	if !hasAPI {
		t.Errorf("expected subdomains list to contain 'api.example.com'")
	}
}

func TestVerifyOriginCandidateMock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<html><head><title>Origin App</title></head><body>Origin Backend</body></html>`)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	host, portStr, _ := strings.Cut(u.Host, ":")
	port := 80
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res := VerifyOriginCandidate(ctx, host, port, "example.com", "api.example.com")
	if res.HTTPStatus != http.StatusOK {
		t.Errorf("expected HTTPStatus 200, got %d", res.HTTPStatus)
	}
	if res.HTTPTitle != "Origin App" {
		t.Errorf("expected HTTPTitle 'Origin App', got %q", res.HTTPTitle)
	}
}

func TestRunOriginDiscoveryFast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	opts := DefaultOriginOptions()
	opts.Concurrency = 2
	report, err := RunOriginDiscovery(ctx, "example.com", opts)
	if err != nil {
		t.Fatalf("RunOriginDiscovery failed: %v", err)
	}

	if report.Target != "example.com" {
		t.Errorf("expected target 'example.com', got %s", report.Target)
	}
}
