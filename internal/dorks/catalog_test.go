package dorks

import (
	"strings"
	"testing"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestCatalogIntegrity(t *testing.T) {
	if len(DefaultCatalog) == 0 {
		t.Fatal("expected DefaultCatalog to contain dork signatures, got 0")
	}

	seenIDs := make(map[string]bool)

	for i, d := range DefaultCatalog {
		if d.ID == "" {
			t.Errorf("dork at index %d has empty ID", i)
		}
		if seenIDs[d.ID] {
			t.Errorf("duplicate dork ID found: %s", d.ID)
		}
		seenIDs[d.ID] = true

		if d.Title == "" {
			t.Errorf("dork %s has empty Title", d.ID)
		}
		if d.Description == "" {
			t.Errorf("dork %s has empty Description", d.ID)
		}
		if !models.IsValidCategory(string(d.Category)) {
			t.Errorf("dork %s has invalid category: %s", d.ID, d.Category)
		}
		if d.Severity.Rank() == 0 {
			t.Errorf("dork %s has invalid severity: %s", d.ID, d.Severity)
		}
		if !models.IsValidEngine(string(d.Engine)) {
			t.Errorf("dork %s has invalid engine: %s", d.ID, d.Engine)
		}
		if strings.TrimSpace(d.QueryTemplate) == "" {
			t.Errorf("dork %s has empty QueryTemplate", d.ID)
		}
	}
}
