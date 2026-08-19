package engine

import (
	"fmt"
	"testing"

	"github.com/Nerd658/dorkforge/internal/dorks"
	"github.com/Nerd658/dorkforge/internal/models"
)

var (
	sinkString  string
	sinkSummary models.ScanSummary
	sinkBool    bool
)

func generateBenchmarkTargets(count int) []string {
	targets := make([]string, count)
	prefixes := []string{"https://", "http://", "ftp://", "", "  https://"}
	suffixes := []string{"/api/v1", ":8080/admin", "/path/to/resource", ":443", ""}

	for i := 0; i < count; i++ {
		prefix := prefixes[i%len(prefixes)]
		suffix := suffixes[i%len(suffixes)]
		targets[i] = fmt.Sprintf("%ssubdomain%d.service-%d.enterprise-corp.com%s", prefix, i, i%50, suffix)
	}
	return targets
}

func generateSyntheticCatalog(count int) []models.Dork {
	catalog := make([]models.Dork, count)
	categories := models.AllCategories
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
	}
	engines := models.AllEngines

	for i := 0; i < count; i++ {
		catalog[i] = models.Dork{
			ID:            fmt.Sprintf("bench-dork-%04d", i),
			Title:         fmt.Sprintf("Benchmark Dork Signature %d", i),
			Description:   fmt.Sprintf("Synthetic description for security signature pattern index %d", i),
			Category:      categories[i%len(categories)],
			Severity:      severities[i%len(severities)],
			Engine:        engines[i%len(engines)],
			QueryTemplate: fmt.Sprintf("site:{{TARGET}} inurl:/api/v%d ext:json OR \"secret_key_%d\"", i%5+1, i),
			Tags:          []string{"benchmark", "automated", fmt.Sprintf("tag-%d", i%10)},
			Remediation:   fmt.Sprintf("Remediate exposure by restricting access to endpoint #%d", i),
		}
	}
	return catalog
}

// -----------------------------------------------------------------------------
// 1. Target Sanitization Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkSanitizeTarget_Scenarios(b *testing.B) {
	scenarios := []struct {
		name  string
		input string
	}{
		{"CleanDomain", "example.com"},
		{"HTTPSWithDeepPath", "https://app.subdomain.target.org/api/v2/users/credentials?token=xyz"},
		{"HTTPWithPortAndPath", "http://admin-portal.internal.net:8443/management/console"},
		{"FTPWithSubfolder", "ftp://archive.storage.backup.corp:21/daily_dumps/sql/"},
		{"WhitespacePaddedHTTPS", "   https://production-gateway.cluster.domain.io/status   "},
	}

	b.ReportAllocs()
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			var res string
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res = SanitizeTarget(sc.input)
			}
			sinkString = res
		})
	}
}

func BenchmarkSanitizeTarget_Batch1000(b *testing.B) {
	targets := generateBenchmarkTargets(1000)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkString = SanitizeTarget(t)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "targets/sec")
}

func BenchmarkSanitizeTarget_Batch10000(b *testing.B) {
	targets := generateBenchmarkTargets(10000)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkString = SanitizeTarget(t)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "targets/sec")
}

// -----------------------------------------------------------------------------
// 2. Org Name Extraction Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkExtractOrgName(b *testing.B) {
	scenarios := []struct {
		name  string
		input string
	}{
		{"SingleDomain", "corp.com"},
		{"MultiSubdomain", "us-east-1.dev.k8s.security.acmecorp.org"},
		{"BareHostname", "internal-vault-service"},
	}

	b.ReportAllocs()
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			var res string
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res = ExtractOrgName(sc.input)
			}
			sinkString = res
		})
	}
}

// -----------------------------------------------------------------------------
// 3. Search Engine URL Generation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkGenerateSearchURL(b *testing.B) {
	query := `site:target.org (ext:env | ext:ini) "DB_PASSWORD"`
	engines := []models.Engine{
		models.EngineGoogle,
		models.EngineGitHub,
		models.EngineDuckDuckGo,
		models.EngineBing,
		models.EngineShodan,
	}

	b.ReportAllocs()
	for _, eng := range engines {
		b.Run(string(eng), func(b *testing.B) {
			var res string
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res = GenerateSearchURL(eng, query)
			}
			sinkString = res
		})
	}
}

// -----------------------------------------------------------------------------
// 4. Query Rendering Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkRenderQuery_Templates(b *testing.B) {
	templates := []struct {
		name     string
		template string
		target   string
	}{
		{
			name:     "SingleToken",
			template: "site:{{TARGET}} ext:env",
			target:   "sub.target.com",
		},
		{
			name:     "MultiToken",
			template: "site:{{TARGET}} OR site:*.{{DOMAIN}} intitle:{{ORG}} admin",
			target:   "https://eu.staging.enterprise.org:8443/auth",
		},
		{
			name:     "ComplexNegation",
			template: "site:*.{{TARGET}} -site:www.{{TARGET}} -site:{{TARGET}} intitle:\"{{ORG}} Internal\"",
			target:   "cloud.infrastructure.io",
		},
	}

	b.ReportAllocs()
	for _, tc := range templates {
		b.Run(tc.name, func(b *testing.B) {
			var res string
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res = RenderQuery(tc.template, tc.target)
			}
			sinkString = res
		})
	}
}

func BenchmarkRenderQuery_Batch1000(b *testing.B) {
	targets := generateBenchmarkTargets(1000)
	template := "site:{{TARGET}} (ext:env | ext:yml) \"{{ORG}}_SECRET_KEY\" OR inurl:{{DOMAIN}}"
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkString = RenderQuery(template, t)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "renders/sec")
}

func BenchmarkRenderQuery_Batch10000(b *testing.B) {
	targets := generateBenchmarkTargets(10000)
	template := "site:{{TARGET}} (ext:env | ext:yml) \"{{ORG}}_SECRET_KEY\" OR inurl:{{DOMAIN}}"
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkString = RenderQuery(template, t)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "renders/sec")
}

// -----------------------------------------------------------------------------
// 5. Filter Matching Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkMatchesFilter(b *testing.B) {
	dork := models.Dork{
		ID:            "cfg-001",
		Title:         "Exposed .env and Environment Files",
		Description:   "Identifies public .env files potentially exposing secrets",
		Category:      models.CategoryConfigs,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} ext:env",
		Tags:          []string{"env", "credentials", "config"},
	}

	filters := FilterOptions{
		Categories:  []models.Category{models.CategoryConfigs, models.CategorySecrets},
		MinSeverity: models.SeverityHigh,
		Engines:     []models.Engine{models.EngineGoogle, models.EngineGitHub},
		SearchQuery: "credentials",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sinkBool = MatchesFilter(dork, filters)
	}
}

// -----------------------------------------------------------------------------
// 6. Scan Summary Generation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkBuildScanSummary_SingleTarget_DefaultCatalog(b *testing.B) {
	catalog := dorks.DefaultCatalog
	filters := FilterOptions{}
	target := "https://api.staging.enterprise.org:8443/app"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sinkSummary = BuildScanSummary(target, catalog, filters)
	}
}

func BenchmarkBuildScanSummary_WithFilters(b *testing.B) {
	catalog := dorks.DefaultCatalog
	filters := FilterOptions{
		Categories:  []models.Category{models.CategoryConfigs, models.CategorySecrets, models.CategoryAdmin},
		MinSeverity: models.SeverityHigh,
		Engines:     []models.Engine{models.EngineGoogle, models.EngineGitHub},
		SearchQuery: "secret",
	}
	target := "https://api.staging.enterprise.org:8443/app"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sinkSummary = BuildScanSummary(target, catalog, filters)
	}
}

func BenchmarkBuildScanSummary_Batch100Targets(b *testing.B) {
	targets := generateBenchmarkTargets(100)
	catalog := dorks.DefaultCatalog
	filters := FilterOptions{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkSummary = BuildScanSummary(t, catalog, filters)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "targets/sec")
}

func BenchmarkBuildScanSummary_Batch1000Targets(b *testing.B) {
	targets := generateBenchmarkTargets(1000)
	catalog := dorks.DefaultCatalog
	filters := FilterOptions{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkSummary = BuildScanSummary(t, catalog, filters)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "targets/sec")
}

func BenchmarkBuildScanSummary_LargeCatalog_500Dorks(b *testing.B) {
	targets := generateBenchmarkTargets(50)
	catalog := generateSyntheticCatalog(500)
	filters := FilterOptions{
		MinSeverity: models.SeverityMedium,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, t := range targets {
			sinkSummary = BuildScanSummary(t, catalog, filters)
		}
	}
	b.ReportMetric(float64(b.N*len(targets))/b.Elapsed().Seconds(), "targets/sec")
}
