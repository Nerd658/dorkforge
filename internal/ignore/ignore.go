package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nerd658/dorkforge/internal/models"
)

type IgnoreRules struct {
	DorkIDs    map[string]bool
	Categories map[string]bool
	URLPatterns []string
}

func NewIgnoreRules() *IgnoreRules {
	return &IgnoreRules{
		DorkIDs:    make(map[string]bool),
		Categories: make(map[string]bool),
		URLPatterns: make([]string, 0),
	}
}

func LoadIgnoreRules(filePath string) (*IgnoreRules, error) {
	rules := NewIgnoreRules()

	if filePath == "" {
		filePath = ".dfgignore"
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return rules, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])

			switch key {
			case "dork_id", "id":
				rules.DorkIDs[strings.ToLower(val)] = true
			case "category", "cat":
				rules.Categories[strings.ToLower(val)] = true
			case "url", "pattern":
				rules.URLPatterns = append(rules.URLPatterns, strings.ToLower(val))
			}
		} else {
			rules.URLPatterns = append(rules.URLPatterns, strings.ToLower(line))
		}
	}

	return rules, scanner.Err()
}

func (r *IgnoreRules) ShouldIgnoreDork(dork models.Dork) bool {
	if r == nil {
		return false
	}
	if r.DorkIDs[strings.ToLower(dork.ID)] {
		return true
	}
	if r.Categories[strings.ToLower(string(dork.Category))] {
		return true
	}
	return false
}

func (r *IgnoreRules) ShouldIgnoreURL(rawURL string) bool {
	if r == nil || len(r.URLPatterns) == 0 {
		return false
	}
	normURL := strings.ToLower(rawURL)
	for _, pattern := range r.URLPatterns {
		cleanPat := strings.Trim(pattern, "*")
		if cleanPat != "" && strings.Contains(normURL, cleanPat) {
			return true
		}
		if matched, _ := filepath.Match(pattern, normURL); matched {
			return true
		}
	}
	return false
}

func (r *IgnoreRules) FilterScanResults(summary *models.ScanSummary) models.ScanSummary {
	if r == nil || summary == nil {
		return *summary
	}

	filtered := *summary
	filteredResults := make([]models.ResolvedDork, 0, len(summary.Results))

	for _, res := range summary.Results {
		if r.ShouldIgnoreDork(res.Dork) || r.ShouldIgnoreURL(res.SearchURL) {
			continue
		}
		filteredResults = append(filteredResults, res)
	}

	filtered.Results = filteredResults
	filtered.TotalDorks = len(filteredResults)

	counts := make(map[models.Severity]int)
	for _, res := range filteredResults {
		counts[res.Dork.Severity]++
	}
	filtered.SeverityCounts = counts

	return filtered
}
