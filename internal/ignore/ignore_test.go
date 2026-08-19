package ignore

import (
	"os"
	"testing"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestIgnoreRules(t *testing.T) {
	content := `# Test DFGIgnore
dork_id: google-s3-public-bucket
category: employees-osint
url: *known-sitemap.xml*
`
	tmpFile, err := os.CreateTemp("", ".dfgignore_*")
	if err != nil {
		t.Fatalf("failed to create temp ignore file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	rules, err := LoadIgnoreRules(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadIgnoreRules failed: %v", err)
	}

	d1 := models.Dork{ID: "google-s3-public-bucket", Category: models.CategoryCloud}
	d2 := models.Dork{ID: "other-dork", Category: models.CategoryEmployeesOSINT}
	d3 := models.Dork{ID: "other-dork", Category: models.CategoryConfigs}

	if !rules.ShouldIgnoreDork(d1) {
		t.Errorf("expected d1 (by id) to be ignored")
	}
	if !rules.ShouldIgnoreDork(d2) {
		t.Errorf("expected d2 (by category) to be ignored")
	}
	if rules.ShouldIgnoreDork(d3) {
		t.Errorf("expected d3 to not be ignored")
	}

	if !rules.ShouldIgnoreURL("https://example.com/known-sitemap.xml") {
		t.Errorf("expected URL pattern match to be ignored")
	}

	summary := &models.ScanSummary{
		TotalDorks: 3,
		Results: []models.ResolvedDork{
			{Dork: d1, SearchURL: "https://google.com/1"},
			{Dork: d2, SearchURL: "https://google.com/2"},
			{Dork: d3, SearchURL: "https://google.com/3"},
		},
	}

	filtered := rules.FilterScanResults(summary)
	if filtered.TotalDorks != 1 {
		t.Errorf("expected 1 result after filtering, got %d", filtered.TotalDorks)
	}
}
