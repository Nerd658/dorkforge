package engine

import (
	"net"
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

// IsCIDR checks if target string is an IP address or CIDR range.
func IsCIDR(target string) bool {
	norm := strings.TrimSpace(target)
	if net.ParseIP(norm) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(norm)
	return err == nil
}

// IsASN checks if target string is an Autonomous System Number (e.g. AS15169).
func IsASN(target string) bool {
	norm := strings.ToUpper(strings.TrimSpace(target))
	if strings.HasPrefix(norm, "AS") && len(norm) > 2 {
		for _, c := range norm[2:] {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// SanitizeTarget cleans and normalizes a target domain without allocations when already clean.
func SanitizeTarget(raw string) string {
	target := strings.TrimSpace(raw)
	if strings.HasPrefix(target, "https://") {
		target = target[8:]
	} else if strings.HasPrefix(target, "http://") {
		target = target[7:]
	} else if strings.HasPrefix(target, "ftp://") {
		target = target[6:]
	}

	norm := strings.TrimSpace(target)
	if IsCIDR(norm) || IsASN(norm) {
		return norm
	}

	if idx := strings.IndexByte(target, '/'); idx != -1 {
		target = target[:idx]
	}
	if idx := strings.IndexByte(target, ':'); idx != -1 {
		target = target[:idx]
	}
	return strings.ToLower(strings.TrimSpace(target))
}

// ExtractOrgName extracts the primary organization identifier from a domain name.
func ExtractOrgName(target string) string {
	sanitized := SanitizeTarget(target)
	parts := strings.Split(sanitized, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return sanitized
}

// GenerateSearchURL creates direct search URLs for each engine.
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

// RenderQuery renders a template replacing target and organization tokens.
func RenderQuery(template string, target string) string {
	return RenderQueryFast(template, target, "")
}

// RenderQueryFast renders query template with pre-computed org name for maximum performance.
func RenderQueryFast(template, target, org string) string {
	if !strings.Contains(template, "{{") {
		return template
	}
	q := template

	if IsCIDR(target) {
		if strings.Contains(q, "ssl.cert.subject.CN:\"{{TARGET}}\"") {
			return strings.ReplaceAll(q, "ssl.cert.subject.CN:\"{{TARGET}}\"", "net:\""+target+"\"")
		}
		if strings.Contains(q, "site:{{TARGET}}") {
			return strings.ReplaceAll(q, "site:{{TARGET}}", "net:\""+target+"\"")
		}
	} else if IsASN(target) {
		asnUpper := strings.ToUpper(target)
		if strings.Contains(q, "ssl.cert.subject.CN:\"{{TARGET}}\"") {
			return strings.ReplaceAll(q, "ssl.cert.subject.CN:\"{{TARGET}}\"", "asn:\""+asnUpper+"\"")
		}
		if strings.Contains(q, "site:{{TARGET}}") {
			return strings.ReplaceAll(q, "site:{{TARGET}}", "asn:\""+asnUpper+"\"")
		}
	}

	if strings.Contains(q, "{{TARGET}}") {
		q = strings.ReplaceAll(q, "{{TARGET}}", target)
	}
	if strings.Contains(q, "{{DOMAIN}}") {
		q = strings.ReplaceAll(q, "{{DOMAIN}}", target)
	}
	if strings.Contains(q, "{{ORG}}") {
		if org == "" {
			org = ExtractOrgName(target)
		}
		q = strings.ReplaceAll(q, "{{ORG}}", org)
	}
	return q
}

// MatchesFilter checks if a dork matches all active user filters.
func MatchesFilter(dork models.Dork, filters FilterOptions) bool {
	// Category filter
	if len(filters.Categories) > 0 {
		matchedCategory := false
		for i := range filters.Categories {
			if dork.Category == filters.Categories[i] {
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
		for i := range filters.Engines {
			if dork.Engine == filters.Engines[i] {
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

// BuildScanSummary compiles scan results with pre-allocated slices and pre-computed org name.
func BuildScanSummary(target string, catalog []models.Dork, filters FilterOptions) models.ScanSummary {
	sanitizedTarget := SanitizeTarget(target)
	orgName := ExtractOrgName(sanitizedTarget)

	results := make([]models.ResolvedDork, 0, len(catalog))
	sevCounts := make(map[models.Severity]int, 4)
	catCounts := make(map[models.Category]int, 12)
	engCounts := make(map[models.Engine]int, 5)

	for i := range catalog {
		dork := catalog[i]
		if !MatchesFilter(dork, filters) {
			continue
		}

		rendered := RenderQueryFast(dork.QueryTemplate, sanitizedTarget, orgName)
		searchURL := GenerateSearchURL(dork.Engine, rendered)

		results = append(results, models.ResolvedDork{
			Dork:          dork,
			Target:        sanitizedTarget,
			RenderedQuery: rendered,
			SearchURL:     searchURL,
		})

		sevCounts[dork.Severity]++
		catCounts[dork.Category]++
		engCounts[dork.Engine]++
	}

	return models.ScanSummary{
		Target:         sanitizedTarget,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		TotalDorks:     len(results),
		SeverityCounts: sevCounts,
		CategoryCounts: catCounts,
		EngineCounts:   engCounts,
		Results:        results,
	}
}
