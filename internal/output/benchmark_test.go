package output

import (
	"fmt"
	"testing"

	"github.com/Nerd658/dorkforge/internal/models"
)

var (
	sinkBytes []byte
	sinkErr   error
)

func generateBenchmarkSummary(numResults int) models.ScanSummary {
	categories := models.AllCategories
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
	}
	engines := models.AllEngines

	results := make([]models.ResolvedDork, numResults)
	sevCounts := make(map[models.Severity]int)
	catCounts := make(map[models.Category]int)
	engCounts := make(map[models.Engine]int)

	for i := 0; i < numResults; i++ {
		sev := severities[i%len(severities)]
		cat := categories[i%len(categories)]
		eng := engines[i%len(engines)]

		sevCounts[sev]++
		catCounts[cat]++
		engCounts[eng]++

		dork := models.Dork{
			ID:            fmt.Sprintf("dork-%04d", i),
			Title:         fmt.Sprintf("Security Finding Signature #%d: Exposed Secrets & Configs", i),
			Description:   fmt.Sprintf("Automated vulnerability check signature #%d for external reconnaissance audits.", i),
			Category:      cat,
			Severity:      sev,
			Engine:        eng,
			QueryTemplate: fmt.Sprintf("site:target-%d.corp.internal ext:env \"SECRET_KEY_%d\"", i%100, i),
			Tags:          []string{"audit", "dork", fmt.Sprintf("tag-%d", i%10)},
			Remediation:   fmt.Sprintf("Remediation step #%d: Rotate exposed tokens and enforce IP filtering.", i),
		}

		rendered := fmt.Sprintf("site:target-%d.corp.internal ext:env \"SECRET_KEY_%d\"", i%100, i)
		results[i] = models.ResolvedDork{
			Dork:          dork,
			Target:        "enterprise-corp.com",
			RenderedQuery: rendered,
			SearchURL:     fmt.Sprintf("https://www.google.com/search?q=site%%3Atarget-%d.corp.internal+ext%%3Aenv", i%100),
		}
	}

	return models.ScanSummary{
		Target:         "enterprise-corp.com",
		GeneratedAt:    "2026-08-19T12:00:00Z",
		TotalDorks:     numResults,
		SeverityCounts: sevCounts,
		CategoryCounts: catCounts,
		EngineCounts:   engCounts,
		Results:        results,
	}
}

// -----------------------------------------------------------------------------
// 1. JSON Export Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkExportJSON(b *testing.B) {
	sizes := []int{10, 100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Results_%d", size), func(b *testing.B) {
			summary := generateBenchmarkSummary(size)
			data, _ := ExportJSON(summary)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()

			var out []byte
			var err error
			for i := 0; i < b.N; i++ {
				out, err = ExportJSON(summary)
			}
			sinkBytes = out
			sinkErr = err
		})
	}
}

// -----------------------------------------------------------------------------
// 2. Markdown Export Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkExportMarkdown(b *testing.B) {
	sizes := []int{10, 100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Results_%d", size), func(b *testing.B) {
			summary := generateBenchmarkSummary(size)
			data := ExportMarkdown(summary)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()

			var out []byte
			for i := 0; i < b.N; i++ {
				out = ExportMarkdown(summary)
			}
			sinkBytes = out
		})
	}
}

// -----------------------------------------------------------------------------
// 3. HTML Export Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkExportHTML(b *testing.B) {
	sizes := []int{10, 100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Results_%d", size), func(b *testing.B) {
			summary := generateBenchmarkSummary(size)
			data := ExportHTML(summary)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()

			var out []byte
			for i := 0; i < b.N; i++ {
				out = ExportHTML(summary)
			}
			sinkBytes = out
		})
	}
}

// -----------------------------------------------------------------------------
// 4. URL List Export Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkExportURLs(b *testing.B) {
	sizes := []int{10, 100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Results_%d", size), func(b *testing.B) {
			summary := generateBenchmarkSummary(size)
			data := ExportURLs(summary)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()

			var out []byte
			for i := 0; i < b.N; i++ {
				out = ExportURLs(summary)
			}
			sinkBytes = out
		})
	}
}

// -----------------------------------------------------------------------------
// 5. Format Comparison Benchmark (100 Results Standard Workload)
// -----------------------------------------------------------------------------

func BenchmarkExportFormats_Comparison_100Results(b *testing.B) {
	summary := generateBenchmarkSummary(100)

	b.Run("Format_JSON", func(b *testing.B) {
		data, _ := ExportJSON(summary)
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sinkBytes, sinkErr = ExportJSON(summary)
		}
	})

	b.Run("Format_Markdown", func(b *testing.B) {
		data := ExportMarkdown(summary)
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sinkBytes = ExportMarkdown(summary)
		}
	})

	b.Run("Format_HTML", func(b *testing.B) {
		data := ExportHTML(summary)
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sinkBytes = ExportHTML(summary)
		}
	})

	b.Run("Format_URLs", func(b *testing.B) {
		data := ExportURLs(summary)
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sinkBytes = ExportURLs(summary)
		}
	})
}
