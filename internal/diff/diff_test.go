package diff

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestCompareSummaries(t *testing.T) {
	d1 := models.Dork{ID: "d1", Title: "Dork 1"}
	d2 := models.Dork{ID: "d2", Title: "Dork 2"}
	d3 := models.Dork{ID: "d3", Title: "Dork 3"}

	prev := models.ScanSummary{
		Target:      "example.com",
		GeneratedAt: "2026-08-01T00:00:00Z",
		Results: []models.ResolvedDork{
			{Dork: d1, RenderedQuery: "site:example.com d1"},
			{Dork: d2, RenderedQuery: "site:example.com d2"},
		},
	}

	curr := models.ScanSummary{
		Target:      "example.com",
		GeneratedAt: "2026-08-19T00:00:00Z",
		Results: []models.ResolvedDork{
			{Dork: d2, RenderedQuery: "site:example.com d2"},
			{Dork: d3, RenderedQuery: "site:example.com d3"},
		},
	}

	diff := CompareSummaries(curr, prev)
	if diff.NewCount != 1 {
		t.Errorf("expected 1 new result, got %d", diff.NewCount)
	}
	if diff.NewResults[0].Dork.ID != "d3" {
		t.Errorf("expected new dork ID 'd3', got %s", diff.NewResults[0].Dork.ID)
	}

	if diff.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved result, got %d", diff.ResolvedCount)
	}
	if diff.ResolvedResults[0].Dork.ID != "d1" {
		t.Errorf("expected resolved dork ID 'd1', got %s", diff.ResolvedResults[0].Dork.ID)
	}

	// Test file loading
	tmpFile, err := os.CreateTemp("", "prev_*.json")
	if err != nil {
		t.Fatalf("failed to create temp json: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	data, _ := json.Marshal(prev)
	_ = os.WriteFile(tmpFile.Name(), data, 0644)

	loaded, err := LoadPreviousSummary(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPreviousSummary failed: %v", err)
	}

	if loaded.Target != "example.com" {
		t.Errorf("expected loaded target 'example.com', got %s", loaded.Target)
	}
}
