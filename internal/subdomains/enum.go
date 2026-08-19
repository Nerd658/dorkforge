package subdomains

import (
	"fmt"
	"strings"

	"github.com/Nerd658/dorkforge/internal/engine"
	"github.com/Nerd658/dorkforge/internal/models"
)

type SubdomainDorkSet struct {
	Target  string
	Queries []models.ResolvedDork
}

func GenerateSubdomainQueries(target string, knownSubdomains []string) SubdomainDorkSet {
	sanitized := engine.SanitizeTarget(target)
	var queries []models.ResolvedDork

	// 1. Google Base Negation Query
	var googleNegations strings.Builder
	googleNegations.WriteString(fmt.Sprintf("site:*.%s -site:www.%s -site:%s", sanitized, sanitized, sanitized))
	for _, sub := range knownSubdomains {
		subSan := strings.TrimSpace(sub)
		if subSan != "" && subSan != "www" {
			googleNegations.WriteString(fmt.Sprintf(" -site:%s.%s", subSan, sanitized))
		}
	}

	googleQuery := googleNegations.String()
	queries = append(queries, models.ResolvedDork{
		Dork: models.Dork{
			ID:          "sub-google-neg",
			Title:       "Google Subdomain Exclusion Query",
			Description: "Enumerates unmapped subdomains by excluding known domains.",
			Category:    models.CategorySubdomains,
			Severity:    models.SeverityLow,
			Engine:      models.EngineGoogle,
		},
		Target:        sanitized,
		RenderedQuery: googleQuery,
		SearchURL:     engine.GenerateSearchURL(models.EngineGoogle, googleQuery),
	})

	// 2. Bing Subdomain Discovery
	bingQuery := fmt.Sprintf("site:*.%s -site:www.%s -site:%s", sanitized, sanitized, sanitized)
	queries = append(queries, models.ResolvedDork{
		Dork: models.Dork{
			ID:          "sub-bing-neg",
			Title:       "Bing Subdomain Reconnaissance",
			Description: "Discovers indexed subdomains across Microsoft Bing engine.",
			Category:    models.CategorySubdomains,
			Severity:    models.SeverityLow,
			Engine:      models.EngineBing,
		},
		Target:        sanitized,
		RenderedQuery: bingQuery,
		SearchURL:     engine.GenerateSearchURL(models.EngineBing, bingQuery),
	})

	// 3. Shodan Hostname & SSL Cert
	shodanSSL := fmt.Sprintf("ssl.cert.subject.CN:\"%s\"", sanitized)
	queries = append(queries, models.ResolvedDork{
		Dork: models.Dork{
			ID:          "sub-shodan-ssl",
			Title:       "Shodan SSL Subject CN Search",
			Description: "Searches Shodan database for hosts presenting matching TLS certificates.",
			Category:    models.CategorySubdomains,
			Severity:    models.SeverityLow,
			Engine:      models.EngineShodan,
		},
		Target:        sanitized,
		RenderedQuery: shodanSSL,
		SearchURL:     engine.GenerateSearchURL(models.EngineShodan, shodanSSL),
	})

	shodanHost := fmt.Sprintf("hostname:\"%s\"", sanitized)
	queries = append(queries, models.ResolvedDork{
		Dork: models.Dork{
			ID:          "sub-shodan-host",
			Title:       "Shodan Hostname Wildcard",
			Description: "Discovers internet-facing servers resolving to target hostnames.",
			Category:    models.CategorySubdomains,
			Severity:    models.SeverityLow,
			Engine:      models.EngineShodan,
		},
		Target:        sanitized,
		RenderedQuery: shodanHost,
		SearchURL:     engine.GenerateSearchURL(models.EngineShodan, shodanHost),
	})

	return SubdomainDorkSet{
		Target:  sanitized,
		Queries: queries,
	}
}
