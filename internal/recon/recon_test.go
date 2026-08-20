package recon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Nerd658/dorkforge/internal/models"
)

func TestDefaultReconOptions(t *testing.T) {
	opts := DefaultReconOptions()
	if opts.FetchLimit <= 0 {
		t.Errorf("expected FetchLimit > 0, got %d", opts.FetchLimit)
	}
	if opts.FetchTimeout <= 0 {
		t.Errorf("expected FetchTimeout > 0, got %v", opts.FetchTimeout)
	}
}

func TestRunReconFast(t *testing.T) {
	opts := ReconOptions{
		SkipFetch:   true,
		SkipLive:    true,
		SkipProbe:   true,
		SkipOrigin:  true,
		Categories:  []models.Category{models.CategoryConfigs},
		MinSeverity: models.SeverityHigh,
	}

	phaseEvents := make(map[string]bool)
	onPhase := func(phase, status string) {
		phaseEvents[phase+"_"+status] = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := RunRecon(ctx, "example.com", opts, onPhase)
	if err != nil {
		t.Fatalf("RunRecon failed: %v", err)
	}

	if result.Target != "example.com" {
		t.Errorf("expected target 'example.com', got %q", result.Target)
	}
	if result.Scan == nil {
		t.Fatal("expected scan summary, got nil")
	}
	if len(result.Scan.Results) == 0 {
		t.Errorf("expected filtered scan results, got 0")
	}
	if !phaseEvents["Scan_started"] || !phaseEvents["Scan_completed"] {
		t.Errorf("expected scan phase callback events")
	}

	// Test HTML generation
	htmlBytes := ExportReconHTML(result)
	if len(htmlBytes) == 0 || !strings.Contains(string(htmlBytes), "example.com") {
		t.Errorf("ExportReconHTML failed to produce valid HTML")
	}

	// Test Markdown generation
	mdBytes := ExportReconMarkdown(result)
	if len(mdBytes) == 0 || !strings.Contains(string(mdBytes), "example.com") {
		t.Errorf("ExportReconMarkdown failed to produce valid Markdown")
	}

	// Test JSON generation
	jsonBytes, err := ExportReconJSON(result)
	if err != nil || len(jsonBytes) == 0 {
		t.Errorf("ExportReconJSON failed: %v", err)
	}
}
