package prober

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestProbeSingle(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret12345\nAWS_SECRET_ACCESS_KEY=abcd"))
		case "/admin":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("<html><head><title>Access Denied</title></head><body>403 Forbidden</body></html>"))
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not found"))
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer ts.Close()

	client := ts.Client()
	ctx := context.Background()

	// 1. Test .env exposed
	resEnv := ProbeSingle(ctx, client, ProbeTarget{
		URL:      ts.URL + "/.env",
		Category: models.CategoryConfigs,
		Severity: models.SeverityCritical,
		Title:    "Exposed .env",
	}, "TestAgent")

	if resEnv.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resEnv.StatusCode)
	}
	if !resEnv.IsExposed {
		t.Errorf("expected .env to be marked exposed")
	}

	// 2. Test 403 Forbidden admin
	resAdmin := ProbeSingle(ctx, client, ProbeTarget{
		URL:      ts.URL + "/admin",
		Category: models.CategoryAdmin,
		Severity: models.SeverityHigh,
		Title:    "Admin portal",
	}, "TestAgent")

	if resAdmin.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", resAdmin.StatusCode)
	}
	if resAdmin.HTMLTitle != "Access Denied" {
		t.Errorf("expected HTMLTitle 'Access Denied', got %q", resAdmin.HTMLTitle)
	}
}

func TestProbeBatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer ts.Close()

	targets := []ProbeTarget{
		{URL: ts.URL + "/1", Category: models.CategoryConfigs, Severity: models.SeverityCritical},
		{URL: ts.URL + "/2", Category: models.CategorySecrets, Severity: models.SeverityCritical},
		{URL: ts.URL + "/3", Category: models.CategoryAdmin, Severity: models.SeverityHigh},
	}

	opts := DefaultProbeOptions()
	opts.Concurrency = 2
	opts.Timeout = 2 * time.Second

	results := ProbeBatch(context.Background(), targets, opts)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestDeriveProbeURLs(t *testing.T) {
	targets := DeriveProbeURLsFromDomain("https://example.com/subpath")
	if len(targets) == 0 {
		t.Fatal("expected derived targets, got 0")
	}

	hasEnv := false
	for _, tg := range targets {
		if tg.URL == "https://example.com/.env" {
			hasEnv = true
			break
		}
	}
	if !hasEnv {
		t.Error("expected https://example.com/.env in derived targets")
	}
}
