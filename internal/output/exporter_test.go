package output

import (
	"strings"
	"testing"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestExportFormats(t *testing.T) {
	summary := models.ScanSummary{
		Target:      "test.com",
		GeneratedAt: "2026-08-19T00:00:00Z",
		TotalDorks:  1,
		SeverityCounts: map[models.Severity]int{
			models.SeverityCritical: 1,
		},
		Results: []models.ResolvedDork{
			{
				Dork: models.Dork{
					ID:            "test-01",
					Title:         "Exposed Env",
					Category:      models.CategoryConfigs,
					Severity:      models.SeverityCritical,
					Engine:        models.EngineGoogle,
					QueryTemplate: "site:test.com ext:env",
					Remediation:   "Block .env access",
				},
				Target:        "test.com",
				RenderedQuery: "site:test.com ext:env",
				SearchURL:     "https://www.google.com/search?q=site%3Atest.com+ext%3Aenv",
			},
		},
	}

	jsonBytes, err := ExportJSON(summary)
	if err != nil || !strings.Contains(string(jsonBytes), "test.com") {
		t.Errorf("ExportJSON failed: %v", err)
	}

	mdBytes := ExportMarkdown(summary)
	if !strings.Contains(string(mdBytes), "# Security Dorking") || !strings.Contains(string(mdBytes), "Exposed Env") {
		t.Errorf("ExportMarkdown failed")
	}

	htmlBytes := ExportHTML(summary)
	if !strings.Contains(string(htmlBytes), "Dorkforge Security Reconnaissance") {
		t.Errorf("ExportHTML failed")
	}

	urlBytes := ExportURLs(summary)
	if !strings.Contains(string(urlBytes), "https://www.google.com/search") {
		t.Errorf("ExportURLs failed")
	}
}
