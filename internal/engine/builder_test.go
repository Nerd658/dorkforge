package engine

import (
	"strings"
	"testing"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestSanitizeTarget(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/some/path", "example.com"},
		{"http://SUB.TARGET.COM:8080/", "sub.target.com"},
		{"  portal.internal.net  ", "portal.internal.net"},
	}

	for _, tt := range tests {
		got := SanitizeTarget(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeTarget(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractOrgName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example"},
		{"app.sub.enterprise.org", "enterprise"},
		{"standalone", "standalone"},
	}

	for _, tt := range tests {
		got := ExtractOrgName(tt.input)
		if got != tt.expected {
			t.Errorf("ExtractOrgName(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestGenerateSearchURL(t *testing.T) {
	query := "site:example.com ext:env"
	googleURL := GenerateSearchURL(models.EngineGoogle, query)
	if !strings.HasPrefix(googleURL, "https://www.google.com/search?q=") {
		t.Errorf("unexpected Google URL: %s", googleURL)
	}

	githubURL := GenerateSearchURL(models.EngineGitHub, query)
	if !strings.Contains(githubURL, "https://github.com/search?q=") || !strings.Contains(githubURL, "type=code") {
		t.Errorf("unexpected GitHub URL: %s", githubURL)
	}

	shodanURL := GenerateSearchURL(models.EngineShodan, query)
	if !strings.HasPrefix(shodanURL, "https://www.shodan.io/search?query=") {
		t.Errorf("unexpected Shodan URL: %s", shodanURL)
	}
}

func TestBuildScanSummary(t *testing.T) {
	catalog := []models.Dork{
		{
			ID:            "test-1",
			Title:         "Critical Test",
			Category:      models.CategoryConfigs,
			Severity:      models.SeverityCritical,
			Engine:        models.EngineGoogle,
			QueryTemplate: "site:{{TARGET}} test",
		},
		{
			ID:            "test-2",
			Title:         "Low Test",
			Category:      models.CategoryDocs,
			Severity:      models.SeverityLow,
			Engine:        models.EngineGoogle,
			QueryTemplate: "site:{{TARGET}} docs",
		},
	}

	filters := FilterOptions{
		MinSeverity: models.SeverityHigh,
	}

	summary := BuildScanSummary("https://acme.org/test", catalog, filters)
	if summary.Target != "acme.org" {
		t.Errorf("expected target 'acme.org', got %q", summary.Target)
	}
	if summary.TotalDorks != 1 {
		t.Errorf("expected 1 result after severity filter, got %d", summary.TotalDorks)
	}
	if summary.Results[0].RenderedQuery != "site:acme.org test" {
		t.Errorf("unexpected rendered query: %s", summary.Results[0].RenderedQuery)
	}
}
