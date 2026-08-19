package fetcher

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Nerd658/dorkforge/internal/engine"
	"github.com/Nerd658/dorkforge/internal/models"
)

// ArchiveItem represents a single discovered historical URL.
type ArchiveItem struct {
	URL         string          `json:"url"`
	Source      string          `json:"source"` // "wayback" or "alienvault"
	MimeType    string          `json:"mimetype,omitempty"`
	StatusCode  int             `json:"status_code,omitempty"`
	Timestamp   string          `json:"timestamp,omitempty"`
	IsSensitive bool            `json:"is_sensitive"`
	Category    models.Category `json:"category,omitempty"`
}

// FetchResult stores the aggregated output of archive lookups.
type FetchResult struct {
	Target        string        `json:"target"`
	FetchedAt     string        `json:"fetched_at"`
	TotalURLs     int           `json:"total_urls"`
	SensitiveURLs int           `json:"sensitive_urls"`
	Items         []ArchiveItem `json:"items"`
}

// FetchOptions configures the archive lookup queries.
type FetchOptions struct {
	IncludeSubdomains bool
	SensitiveOnly     bool
	Timeout           time.Duration
	Limit             int
}

// DefaultFetchOptions returns standard fetcher parameters.
func DefaultFetchOptions() FetchOptions {
	return FetchOptions{
		IncludeSubdomains: true,
		SensitiveOnly:     false,
		Timeout:           15 * time.Second,
		Limit:             1000,
	}
}

var (
	sensitiveExtRegex  = regexp.MustCompile(`(?i)\.(env|sql|bak|dump|tar\.gz|zip|db|sqlite|sqlite3|tfstate|tfvars|log|pem|key|crt|conf|config|yml|yaml|json|xml|pdf|doc|docx|xls|xlsx|action|do|jsp|asp|aspx|php)$`)
	sensitivePathRegex = regexp.MustCompile(`(?i)(admin|api|v1|v2|actuator|swagger|graphql|wp-config|login|\.git|\.env|backup|secret|token|password|config|internal)`)
	ignoredExtRegex    = regexp.MustCompile(`(?i)\.(css|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|mp4|webm|avi|mp3|wav|ogg)$`)
)

// SensitiveExtensions lists all prioritized sensitive file extensions.
var SensitiveExtensions = []string{
	".env", ".sql", ".bak", ".zip", ".tar.gz", ".dump", ".json", ".log",
	".xml", ".yaml", ".yml", ".pdf", ".docx", ".xlsx", ".pem", ".key",
	".php", ".asp", ".aspx", ".action", ".do",
}

// SensitiveKeywords lists high-value sensitive substrings and parameter keys.
var SensitiveKeywords = []string{
	"password", "token", "secret", "admin", "backup", "config", "api", "v1", "v2", "internal",
}

// MatchesSensitiveExtension tests whether a URL ends with or contains a sensitive file extension.
func MatchesSensitiveExtension(rawURL string) (bool, string) {
	u, err := url.Parse(rawURL)
	var path string
	if err != nil {
		path = rawURL
	} else {
		path = u.Path
	}

	pathLower := strings.ToLower(path)
	if idx := strings.Index(pathLower, "?"); idx != -1 {
		pathLower = pathLower[:idx]
	}
	if idx := strings.Index(pathLower, "#"); idx != -1 {
		pathLower = pathLower[:idx]
	}
	pathLower = strings.TrimRight(pathLower, "/")

	for _, ext := range SensitiveExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return true, ext
		}
		if ext == ".env" && (strings.Contains(pathLower, "/.env") || strings.HasPrefix(pathLower, ".env")) {
			return true, ".env"
		}
	}

	return false, ""
}

// MatchesSensitiveKeyword checks if any sensitive keyword exists in the URL path or query.
func MatchesSensitiveKeyword(rawURL string) (bool, string) {
	rawLower := strings.ToLower(rawURL)
	unescaped, err := url.QueryUnescape(rawLower)
	if err != nil {
		unescaped = rawLower
	}

	for _, kw := range SensitiveKeywords {
		if strings.Contains(rawLower, kw) || strings.Contains(unescaped, kw) {
			return true, kw
		}
	}

	return false, ""
}

// FilterSensitiveURLs returns only ArchiveItems that match sensitive assets.
func FilterSensitiveURLs(items []ArchiveItem) []ArchiveItem {
	var filtered []ArchiveItem
	for _, item := range items {
		if item.IsSensitive {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// FilterSubdomains filters items based on target domain and subdomain inclusion preference.
func FilterSubdomains(items []ArchiveItem, domain string, includeSubs bool) []ArchiveItem {
	cleanTarget := strings.ToLower(engine.SanitizeTarget(domain))
	if cleanTarget == "" {
		cleanTarget = strings.ToLower(domain)
	}

	var filtered []ArchiveItem
	for _, item := range items {
		u, err := url.Parse(item.URL)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if !includeSubs {
			if host == cleanTarget || host == "www."+cleanTarget {
				filtered = append(filtered, item)
			}
		} else {
			if host == cleanTarget || host == "www."+cleanTarget || strings.HasSuffix(host, "."+cleanTarget) {
				filtered = append(filtered, item)
			}
		}
	}
	return filtered
}

// ClassifyURL determines whether an archived URL points to sensitive assets and assigns a Category.
func ClassifyURL(rawURL string) (bool, models.Category) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, ""
	}

	path := strings.ToLower(u.Path)
	full := strings.ToLower(rawURL)

	if ignoredExtRegex.MatchString(path) {
		return false, ""
	}

	if strings.Contains(path, ".env") || strings.Contains(path, "tfstate") || strings.Contains(path, "wp-config") {
		return true, models.CategoryConfigs
	}
	if strings.Contains(path, ".sql") || strings.Contains(path, ".dump") || strings.Contains(path, ".bak") || strings.Contains(path, "backup") {
		return true, models.CategoryBackups
	}
	if strings.Contains(path, "/actuator/") || strings.Contains(path, "/admin") || strings.Contains(path, "/phpmyadmin") || strings.Contains(full, "admin") {
		return true, models.CategoryAdmin
	}
	if strings.Contains(path, "/swagger") || strings.Contains(path, "/graphql") || strings.Contains(path, "/api") || strings.Contains(full, "/api/") || strings.Contains(full, "/v1/") || strings.Contains(full, "/v2/") {
		return true, models.CategoryAPIEndpoints
	}
	if strings.Contains(path, ".git") || strings.Contains(path, ".svn") || strings.Contains(path, ".php") || strings.Contains(path, ".asp") || strings.Contains(path, ".aspx") || strings.Contains(path, ".action") || strings.Contains(path, ".do") {
		return true, models.CategorySourceCode
	}
	if strings.Contains(path, ".pdf") || strings.Contains(path, ".xlsx") || strings.Contains(path, ".docx") {
		return true, models.CategoryDocs
	}
	if strings.Contains(path, ".pem") || strings.Contains(path, ".key") || strings.Contains(full, "password") || strings.Contains(full, "token") || strings.Contains(full, "secret") || strings.Contains(full, "internal") {
		return true, models.CategorySecrets
	}

	if sensitiveExtRegex.MatchString(path) || sensitivePathRegex.MatchString(full) {
		return true, models.CategorySecrets
	}

	return false, ""
}

// FetchAll queries Wayback Machine and AlienVault concurrently, deduplicating findings.
func FetchAll(ctx context.Context, domain string, opts FetchOptions) (*FetchResult, error) {
	targetDomain := strings.ToLower(engine.SanitizeTarget(domain))
	if targetDomain == "" {
		targetDomain = strings.ToLower(domain)
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}

	subCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex

	seen := make(map[string]bool)
	var allItems []ArchiveItem

	addItem := func(item ArchiveItem) {
		cleanURL := strings.TrimSpace(item.URL)
		if cleanURL == "" {
			return
		}

		u, err := url.Parse(cleanURL)
		if err != nil || u.Host == "" {
			return
		}

		host := strings.ToLower(u.Hostname())
		if !opts.IncludeSubdomains {
			if host != targetDomain && host != "www."+targetDomain {
				return
			}
		} else {
			if host != targetDomain && host != "www."+targetDomain && !strings.HasSuffix(host, "."+targetDomain) {
				return
			}
		}

		// Filter noise
		if ignoredExtRegex.MatchString(u.Path) {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if seen[cleanURL] {
			return
		}
		seen[cleanURL] = true

		isSens, cat := ClassifyURL(cleanURL)
		item.IsSensitive = isSens
		item.Category = cat

		if opts.SensitiveOnly && !isSens {
			return
		}

		if opts.Limit > 0 && len(allItems) >= opts.Limit {
			return
		}

		allItems = append(allItems, item)
	}

	// 1. Wayback CDX API
	wg.Add(1)
	go func() {
		defer wg.Done()
		items, err := QueryWaybackCDX(subCtx, targetDomain, opts.IncludeSubdomains)
		if err == nil {
			for _, it := range items {
				addItem(it)
			}
		}
	}()

	// 2. AlienVault OTX API
	wg.Add(1)
	go func() {
		defer wg.Done()
		items, err := QueryAlienVaultOTX(subCtx, targetDomain)
		if err == nil {
			for _, it := range items {
				addItem(it)
			}
		}
	}()

	wg.Wait()

	sensCount := 0
	for _, it := range allItems {
		if it.IsSensitive {
			sensCount++
		}
	}

	return &FetchResult{
		Target:        targetDomain,
		FetchedAt:     time.Now().UTC().Format(time.RFC3339),
		TotalURLs:     len(allItems),
		SensitiveURLs: sensCount,
		Items:         allItems,
	}, nil
}
