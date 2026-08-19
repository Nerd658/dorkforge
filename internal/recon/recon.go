package recon

import (
	"context"
	"strings"
	"time"

	"github.com/Nerd658/dorkforge/internal/dorks"
	"github.com/Nerd658/dorkforge/internal/engine"
	"github.com/Nerd658/dorkforge/internal/fetcher"
	"github.com/Nerd658/dorkforge/internal/models"
	"github.com/Nerd658/dorkforge/internal/prober"
	"github.com/Nerd658/dorkforge/internal/scraper"
)

// ReconOptions controls which phases are enabled and their parameters.
type ReconOptions struct {
	SkipFetch    bool
	SkipLive     bool
	SkipProbe    bool
	Categories   []models.Category
	MinSeverity  models.Severity
	Engines      []models.Engine
	FetchLimit   int
	FetchTimeout time.Duration
	Concurrency  int
}

// DefaultReconOptions returns standard reconnaissance configuration.
func DefaultReconOptions() ReconOptions {
	return ReconOptions{
		FetchLimit:   100,
		FetchTimeout: 30 * time.Second,
		Concurrency:  5,
	}
}

// ReconResult consolidates output from all 3 phases.
type ReconResult struct {
	Target       string                     `json:"target"`
	StartedAt    string                     `json:"started_at"`
	CompletedAt  string                     `json:"completed_at"`
	DurationMs   int64                      `json:"duration_ms"`
	Scan         *models.ScanSummary        `json:"scan"`
	Archive      *fetcher.FetchResult       `json:"archive,omitempty"`
	LiveResults  []LiveFinding              `json:"live_results,omitempty"`
	ProbeResults []prober.ProbeResult       `json:"probe_results,omitempty"`
	RiskScore    int                        `json:"risk_score"`
	ExposedCount int                        `json:"exposed_count"`
}

// LiveFinding stores a scraper result paired with the dork that generated it.
type LiveFinding struct {
	DorkTitle     string                     `json:"dork_title"`
	RenderedQuery string                     `json:"rendered_query"`
	Items         []scraper.SearchResultItem `json:"items"`
}

// PhaseCallback is called when a phase starts/completes, for terminal progress display.
type PhaseCallback func(phase string, status string)

// RunRecon executes the full reconnaissance pipeline.
func RunRecon(ctx context.Context, target string, opts ReconOptions, onPhase PhaseCallback) (*ReconResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	target = engine.SanitizeTarget(target)

	res := &ReconResult{
		Target:    target,
		StartedAt: start.Format(time.RFC3339),
	}

	callPhase := func(phase, status string) {
		if onPhase != nil {
			onPhase(phase, status)
		}
	}

	callPhase("Scan", "started")
	filterOpts := engine.FilterOptions{
		Categories:  opts.Categories,
		MinSeverity: opts.MinSeverity,
		Engines:     opts.Engines,
	}
	scan := engine.BuildScanSummary(target, dorks.DefaultCatalog, filterOpts)
	res.Scan = &scan
	callPhase("Scan", "completed")

	crit, high, med, low := 0, 0, 0, 0
	for _, r := range scan.Results {
		sev := string(r.Dork.Severity)
		switch strings.ToLower(sev) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}

	sensitiveArchiveURLs := 0
	if !opts.SkipFetch {
		callPhase("Archive Fetch", "started")
		fOpts := fetcher.DefaultFetchOptions()
		fOpts.IncludeSubdomains = true
		fOpts.SensitiveOnly = true
		if opts.FetchLimit > 0 {
			fOpts.Limit = opts.FetchLimit
		}
		if opts.FetchTimeout > 0 {
			fOpts.Timeout = opts.FetchTimeout
		}

		fRes, err := fetcher.FetchAll(ctx, target, fOpts)
		if err == nil && fRes != nil {
			res.Archive = fRes
			sensitiveArchiveURLs = fRes.SensitiveURLs
		}
		callPhase("Archive Fetch", "completed")
	}

	if !opts.SkipLive {
		callPhase("Live Scraping", "started")
		for _, r := range scan.Results {
			eng := r.Dork.Engine
			if eng == models.EngineGoogle || eng == models.EngineDuckDuckGo {
				sOpts := scraper.DefaultScraperOptions()
				sRes, err := scraper.ScrapeDuckDuckGo(ctx, r.RenderedQuery, sOpts)
				if err == nil && sRes != nil {
					res.LiveResults = append(res.LiveResults, LiveFinding{
						DorkTitle:     r.Dork.Title,
						RenderedQuery: r.RenderedQuery,
						Items:         sRes.Items,
					})
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
		callPhase("Live Scraping", "completed")
	}

	if !opts.SkipProbe {
		callPhase("Probe", "started")
		pTargets := prober.DeriveProbeURLsFromDomain(target)
		pOpts := prober.DefaultProbeOptions()
		pRes := prober.ProbeBatch(ctx, pTargets, pOpts)
		res.ProbeResults = pRes
		for _, pr := range pRes {
			if pr.IsExposed {
				res.ExposedCount++
			}
		}
		callPhase("Probe", "completed")
	}

	res.RiskScore = (crit * 10) + (high * 5) + (med * 2) + (low * 1) + (res.ExposedCount * 15) + (sensitiveArchiveURLs * 3)
	if res.RiskScore > 100 {
		res.RiskScore = 100
	}

	end := time.Now()
	res.CompletedAt = end.Format(time.RFC3339)
	res.DurationMs = end.Sub(start).Milliseconds()

	return res, nil
}
