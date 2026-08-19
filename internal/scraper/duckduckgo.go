package scraper

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultDuckDuckGoHTMLURL is the standard DuckDuckGo HTML search endpoint.
	DefaultDuckDuckGoHTMLURL = "https://html.duckduckgo.com/html/"
	// DefaultDuckDuckGoLiteURL is the lightweight fallback endpoint.
	DefaultDuckDuckGoLiteURL = "https://lite.duckduckgo.com/lite/"
)

var duckDuckGoHTMLURL = DefaultDuckDuckGoHTMLURL

var (
	// Regex matching primary title anchor tags in HTML and Lite formats
	resultAnchorRegex = regexp.MustCompile(`(?is)<a[^>]+class="[^"]*(?:result__a|result-link)[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)
	// Regex matching snippet anchor, div, or td tags
	resultSnippetRegex = regexp.MustCompile(`(?is)<(?:a|div|td)[^>]+class="[^"]*(?:result__snippet|result-snippet)[^"]*"[^>]*>(.*?)</(?:a|div|td)>`)
	// Regex matching display URL tags
	resultURLRegex = regexp.MustCompile(`(?is)<(?:a|span|td)[^>]+class="[^"]*(?:result__url|result_url|url)[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</(?:a|span|td)>`)
	// Regex matching all HTML tags for stripping
	stripTagsRegex = regexp.MustCompile(`<[^>]*>`)
)

// DuckDuckGoScraper implements the Scraper interface for DuckDuckGo live searches.
type DuckDuckGoScraper struct {
	config Config
	client *http.Client
}

// NewDuckDuckGoScraper creates a new DuckDuckGoScraper instance.
func NewDuckDuckGoScraper(cfg Config) *DuckDuckGoScraper {
	defaults := DefaultConfig()
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaults.Timeout
	}
	if cfg.MaxResults <= 0 {
		cfg.MaxResults = defaults.MaxResults
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaults.UserAgent
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = duckDuckGoHTMLURL
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	return &DuckDuckGoScraper{
		config: cfg,
		client: client,
	}
}

// Search executes a search query against DuckDuckGo.
func (s *DuckDuckGoScraper) Search(ctx context.Context, query string) (*ScrapeResult, error) {
	return scrapeDuckDuckGoWithClient(ctx, query, s.config, s.client)
}

// ExtractCleanTargetURL unescapes and normalizes DuckDuckGo redirect URLs (uddg=...).
func ExtractCleanTargetURL(rawHref string) string {
	rawHref = strings.TrimSpace(rawHref)
	if rawHref == "" {
		return ""
	}

	// Handle protocol-relative and root-relative redirect paths
	if strings.HasPrefix(rawHref, "//") {
		rawHref = "https:" + rawHref
	} else if strings.HasPrefix(rawHref, "/l/?") || strings.HasPrefix(rawHref, "l/?") {
		rawHref = "https://duckduckgo.com/" + strings.TrimPrefix(rawHref, "/")
	}

	// Extract destination from 'uddg' query parameter if present
	if strings.Contains(rawHref, "uddg=") {
		u, err := url.Parse(rawHref)
		if err == nil {
			uddgVal := u.Query().Get("uddg")
			if uddgVal != "" {
				decoded, err := url.QueryUnescape(uddgVal)
				if err == nil {
					decoded = strings.TrimSpace(decoded)
					if strings.HasPrefix(decoded, "http://") || strings.HasPrefix(decoded, "https://") {
						return decoded
					}
				}
			}
		}
	}

	// Handle direct HTTP/HTTPS URLs
	if strings.HasPrefix(rawHref, "http://") || strings.HasPrefix(rawHref, "https://") {
		// Filter out internal DuckDuckGo search or navigation links
		if strings.Contains(rawHref, "duckduckgo.com/l/") ||
			strings.Contains(rawHref, "duckduckgo.com/?q=") ||
			strings.Contains(rawHref, "duckduckgo.com/html/?q=") {
			return ""
		}
		return rawHref
	}

	return ""
}

// StripHTML removes HTML markup tags, unescapes HTML entities, and normalizes whitespace.
func StripHTML(htmlStr string) string {
	if htmlStr == "" {
		return ""
	}
	cleaned := stripTagsRegex.ReplaceAllString(htmlStr, " ")
	cleaned = html.UnescapeString(cleaned)
	cleaned = strings.ReplaceAll(cleaned, "\u00a0", " ")
	fields := strings.Fields(cleaned)
	return strings.Join(fields, " ")
}

// ParseSearchResults extracts structured search result items from raw DuckDuckGo HTML content.
func ParseSearchResults(body string, maxResults int) []SearchResultItem {
	if maxResults <= 0 {
		maxResults = 15
	}

	var items []SearchResultItem
	seen := make(map[string]bool)

	// Match primary title anchor positions
	locs := resultAnchorRegex.FindAllStringSubmatchIndex(body, -1)
	for i, loc := range locs {
		if len(loc) >= 6 {
			rawHref := body[loc[2]:loc[3]]
			rawTitle := body[loc[4]:loc[5]]

			cleanURL := ExtractCleanTargetURL(rawHref)
			title := StripHTML(rawTitle)

			// Substring bounded between end of current anchor and start of next anchor
			searchEnd := len(body)
			if i+1 < len(locs) {
				searchEnd = locs[i+1][0]
			}
			searchSlice := body[loc[1]:searchEnd]

			// Extract snippet associated with this result block
			var snippet string
			if snipMatches := resultSnippetRegex.FindStringSubmatch(searchSlice); len(snipMatches) > 1 {
				snippet = StripHTML(snipMatches[1])
			}

			// Fallback URL extraction if title anchor did not have full target
			if cleanURL == "" {
				if urlMatches := resultURLRegex.FindStringSubmatch(searchSlice); len(urlMatches) > 1 {
					cleanURL = ExtractCleanTargetURL(urlMatches[1])
				}
			}

			if cleanURL != "" && !seen[cleanURL] {
				seen[cleanURL] = true
				if title == "" {
					title = cleanURL
				}
				items = append(items, SearchResultItem{
					Title:     title,
					TargetURL: cleanURL,
					Snippet:   snippet,
					Engine:    "duckduckgo",
				})

				if len(items) >= maxResults {
					return items
				}
			}
		}
	}

	// Fallback when no primary anchor matches were found: scan standalone result URLs
	if len(items) == 0 {
		urlMatches := resultURLRegex.FindAllStringSubmatch(body, -1)
		for _, m := range urlMatches {
			if len(m) > 1 {
				cleanURL := ExtractCleanTargetURL(m[1])
				if cleanURL != "" && !seen[cleanURL] {
					seen[cleanURL] = true
					title := ""
					if len(m) > 2 {
						title = StripHTML(m[2])
					}
					if title == "" {
						title = cleanURL
					}
					items = append(items, SearchResultItem{
						Title:     title,
						TargetURL: cleanURL,
						Engine:    "duckduckgo",
					})
					if len(items) >= maxResults {
						break
					}
				}
			}
		}
	}

	return items
}

// ScrapeDuckDuckGo sends a query to DuckDuckGo HTML endpoint and extracts real result URLs.
func ScrapeDuckDuckGo(ctx context.Context, query string, opts Config) (*ScrapeResult, error) {
	scraper := NewDuckDuckGoScraper(opts)
	return scraper.Search(ctx, query)
}

func scrapeDuckDuckGoWithClient(ctx context.Context, query string, opts Config, client *http.Client) (*ScrapeResult, error) {
	start := time.Now()

	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxResults <= 0 {
		opts.MaxResults = 15
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultConfig().UserAgent
	}
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = duckDuckGoHTMLURL
	}

	if opts.DelayBetweenRequests > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(opts.DelayBetweenRequests):
		}
	}

	subCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	formData := url.Values{}
	formData.Set("q", query)
	formData.Set("b", "")
	formData.Set("kl", "us-en")

	req, err := http.NewRequestWithContext(subCtx, "POST", baseURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("duckduckgo search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("duckduckgo rate limit reached (HTTP 429)")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("duckduckgo request forbidden / bot detected (HTTP 403)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("duckduckgo search returned unexpected status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	body := string(bodyBytes)

	items := ParseSearchResults(body, opts.MaxResults)

	return &ScrapeResult{
		Query:      query,
		Engine:     "duckduckgo",
		TotalFound: len(items),
		Items:      items,
		Duration:   time.Since(start),
	}, nil
}
