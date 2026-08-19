package diff

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Nerd658/dorkforge/internal/models"
)

type DiffResult struct {
	Target           string                `json:"target"`
	PreviousScanDate string                `json:"previous_scan_date"`
	CurrentScanDate  string                `json:"current_scan_date"`
	NewCount         int                   `json:"new_count"`
	ResolvedCount    int                   `json:"resolved_count"`
	NewResults       []models.ResolvedDork `json:"new_results"`
	ResolvedResults  []models.ResolvedDork `json:"resolved_results"`
}

func LoadPreviousSummary(filePath string) (*models.ScanSummary, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read previous summary file %s: %w", filePath, err)
	}

	var summary models.ScanSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil, fmt.Errorf("failed to parse previous summary JSON: %w", err)
	}

	return &summary, nil
}

func CompareSummaries(current models.ScanSummary, previous models.ScanSummary) DiffResult {
	prevMap := make(map[string]models.ResolvedDork)
	for _, res := range previous.Results {
		key := res.Dork.ID + ":" + res.RenderedQuery
		prevMap[key] = res
	}

	currMap := make(map[string]models.ResolvedDork)
	var newResults []models.ResolvedDork

	for _, res := range current.Results {
		key := res.Dork.ID + ":" + res.RenderedQuery
		currMap[key] = res
		if _, found := prevMap[key]; !found {
			newResults = append(newResults, res)
		}
	}

	var resolvedResults []models.ResolvedDork
	for key, res := range prevMap {
		if _, found := currMap[key]; !found {
			resolvedResults = append(resolvedResults, res)
		}
	}

	return DiffResult{
		Target:           current.Target,
		PreviousScanDate: previous.GeneratedAt,
		CurrentScanDate:  current.GeneratedAt,
		NewCount:         len(newResults),
		ResolvedCount:    len(resolvedResults),
		NewResults:       newResults,
		ResolvedResults:  resolvedResults,
	}
}
