package scraper

import (
	"context"
	"net/http"
	"time"
)

// SearchResultItem represents an individual live result extracted from search engines.
type SearchResultItem struct {
	Title     string `json:"title"`
	TargetURL string `json:"target_url"`
	Snippet   string `json:"snippet,omitempty"`
	Engine    string `json:"engine"`
}

// ScrapeResult encapsulates all extracted live items for a dork query.
type ScrapeResult struct {
	Query      string             `json:"query"`
	Engine     string             `json:"engine"`
	TotalFound int                `json:"total_found"`
	Items      []SearchResultItem `json:"items"`
	Duration   time.Duration      `json:"duration_ms,omitempty"`
	Error      string             `json:"error,omitempty"`
}

// Config controls live search scraping behavior.
type Config struct {
	UserAgent            string        `json:"user_agent"`
	Timeout              time.Duration `json:"timeout"`
	MaxResults           int           `json:"max_results"`
	DelayBetweenRequests time.Duration `json:"delay_between_requests"`
	BaseURL              string        `json:"base_url,omitempty"`
	HTTPClient           *http.Client  `json:"-"`
}

// ScraperOptions is an alias for Config to maintain backwards compatibility.
type ScraperOptions = Config

// DefaultConfig returns standard safe scraping settings.
func DefaultConfig() Config {
	return Config{
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Timeout:              10 * time.Second,
		MaxResults:           15,
		DelayBetweenRequests: 0,
	}
}

// DefaultScraperOptions returns standard safe scraping settings.
func DefaultScraperOptions() ScraperOptions {
	return DefaultConfig()
}

// Scraper defines the interface for live search engine scrapers.
type Scraper interface {
	Search(ctx context.Context, query string) (*ScrapeResult, error)
}

// ScrapeEngine defines a generic search scraping interface with options.
type ScrapeEngine interface {
	Search(ctx context.Context, query string, opts ScraperOptions) (*ScrapeResult, error)
}
