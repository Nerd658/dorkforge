package engine

import (
	"net/url"
	"strings"
	"time"

	"github.com/Nerd658/dorkforge/internal/models"
)

type FilterOptions struct {
	Categories  []models.Category
	MinSeverity models.Severity
	Engines     []models.Engine
	SearchQuery string
}

func SanitizeTarget(raw string) string {
	target := strings.TrimSpace(raw)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "ftp://")

	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	if idx := strings.Index(target, ":"); idx != -1 {
		target = target[:idx]
	}
	return strings.ToLower(strings.TrimSpace(target))
}

func ExtractOrgName(target string) string {
	sanitized := SanitizeTarget(target)
	parts := strings.Split(sanitized, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return sanitized
}

func GenerateSearchURL(engine models.Engine, query string) string {
	escapedQuery := url.QueryEscape(query)
	switch engine {
	case models.EngineGoogle:
		return "https://www.google.com/search?q=" + escapedQuery
	case models.EngineGitHub:
		return "https://github.com/search?q=" + escapedQuery + "&type=code"
	case models.EngineDuckDuckGo:
		return "https://duckduckgo.com/?q=" + escapedQuery
	case models.EngineBing:
		return "https://www.bing.com/search?q=" + escapedQuery
	case models.EngineShodan:
		return "https://www.shodan.io/search?query=" + escapedQuery
	default:
		return "https://www.google.com/search?q=" + escapedQuery
	}
}

func RenderQuery(template string, target string) string {
	org := ExtractOrgName(target)
	q := strings.ReplaceAll(template, "{{TARGET}}", target)
	q = strings.ReplaceAll(q, "{{DOMAIN}}", target)
	q = strings.ReplaceAll(q, "{{ORG}}", org)
	return q
}

func MatchesFilter(dork models.Dork, filters FilterOptions) bool {
	// Category filter
	if len(filters.Categories) > 0 {
		matchedCategory := false
		for _, cat := range filters.Categories {
			if dork.Category == cat {
				matchedCategory = true
				break
			}
		}
		if !matchedCategory {
			return false
		}
	}

	// Severity filter
	if filters.MinSeverity != "" {
		if dork.Severity.Rank() < filters.MinSeverity.Rank() {
			return false
		}
	}

	// Engine filter
	if len(filters.Engines) > 0 {
		matchedEngine := false
		for _, eng := range filters.Engines {
			if dork.Engine == eng {
				matchedEngine = true
				break
			}
		}
		if !matchedEngine {
			return false
		}
	}

	// Text search filter
	if filters.SearchQuery != "" {
		search := strings.ToLower(filters.SearchQuery)
		inTitle := strings.Contains(strings.ToLower(dork.Title), search)
		inDesc := strings.Contains(strings.ToLower(dork.Description), search)
		inTemplate := strings.Contains(strings.ToLower(dork.QueryTemplate), search)

		inTags := false
		for _, t := range dork.Tags {
			if strings.Contains(strings.ToLower(t), search) {
				inTags = true
				break
			}
		}

		if !inTitle && !inDesc && !inTemplate && !inTags {
			return false
		}
	}

	return true
}

func BuildScanSummary(target string, catalog []models.Dork, filters FilterOptions) models.ScanSummary {
	sanitizedTarget := SanitizeTarget(target)
	summary := models.ScanSummary{
		Target:         sanitizedTarget,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		SeverityCounts: make(map[models.Severity]int),
		CategoryCounts: make(map[models.Category]int),
		EngineCounts:   make(map[models.Engine]int),
		Results:        make([]models.ResolvedDork, 0),
	}

	for _, dork := range catalog {
		if !MatchesFilter(dork, filters) {
			continue
		}

		rendered := RenderQuery(dork.QueryTemplate, sanitizedTarget)
		searchURL := GenerateSearchURL(dork.Engine, rendered)

		summary.Results = append(summary.Results, models.ResolvedDork{
			Dork:          dork,
			Target:        sanitizedTarget,
			RenderedQuery: rendered,
			SearchURL:     searchURL,
		})

		summary.SeverityCounts[dork.Severity]++
		summary.CategoryCounts[dork.Category]++
		summary.EngineCounts[dork.Engine]++
	}

	summary.TotalDorks = len(summary.Results)
	return summary
}
