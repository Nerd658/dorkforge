package prober

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Nerd658/dorkforge/internal/engine"
	"github.com/Nerd658/dorkforge/internal/models"
)

// ProbeTarget represents a URL target to probe with associated metadata.
type ProbeTarget struct {
	URL         string          `json:"url"`
	Category    models.Category `json:"category"`
	Severity    models.Severity `json:"severity"`
	Title       string          `json:"title"`
	DorkID      string          `json:"dork_id,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
}

// ProbeResult stores the result of an HTTP probe request.
type ProbeResult struct {
	URL            string          `json:"url"`
	StatusCode     int             `json:"status_code"`
	StatusText     string          `json:"status_text"`
	ContentLength  int64           `json:"content_length"`
	ContentType    string          `json:"content_type"`
	HTMLTitle      string          `json:"html_title,omitempty"`
	ResponseTimeMs int64           `json:"response_time_ms"`
	RedirectURL    string          `json:"redirect_url,omitempty"`
	Category       models.Category `json:"category"`
	Severity       models.Severity `json:"severity"`
	DorkTitle      string          `json:"dork_title"`
	IsExposed      bool            `json:"is_exposed"`
	Error          string          `json:"error,omitempty"`
}

// ProbeOptions controls the behavior of concurrent probing.
type ProbeOptions struct {
	Concurrency     int
	Timeout         time.Duration
	FollowRedirects bool
	UserAgent       string
	FilterStatuses  []int // e.g. [200, 403, 401]
	InsecureSkipTLS bool
}

// DefaultProbeOptions returns standard safe probing parameters.
func DefaultProbeOptions() ProbeOptions {
	return ProbeOptions{
		Concurrency:     15,
		Timeout:         5 * time.Second,
		FollowRedirects: false,
		UserAgent:       "Mozilla/5.0 (compatible; DorkForge/1.0; +https://github.com/Nerd658/dorkforge)",
		FilterStatuses:  nil,
		InsecureSkipTLS: false,
	}
}

var (
	titleRegex   = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	envSensitive = regexp.MustCompile(`(?i)(DB_PASSWORD|AWS_SECRET|APP_KEY|SECRET_KEY|DATABASE_URL)`)
)

// ProbeSingle executes a single HTTP request and analyzes the response.
func ProbeSingle(ctx context.Context, client *http.Client, target ProbeTarget, userAgent string) ProbeResult {
	start := time.Now()
	res := ProbeResult{
		URL:       target.URL,
		Category:  target.Category,
		Severity:  target.Severity,
		DorkTitle: target.Title,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		res.Error = err.Error()
		res.ResponseTimeMs = time.Since(start).Milliseconds()
		return res
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	res.ResponseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.StatusText = http.StatusText(resp.StatusCode)
	res.ContentType = resp.Header.Get("Content-Type")
	res.ContentLength = resp.ContentLength

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		res.RedirectURL = resp.Header.Get("Location")
	}

	// Read first 8KB of body for heuristic classification
	lr := io.LimitReader(resp.Body, 8192)
	bodyBytes, _ := io.ReadAll(lr)
	bodyStr := string(bodyBytes)

	if len(bodyBytes) > 0 && res.ContentLength <= 0 {
		res.ContentLength = int64(len(bodyBytes))
	}

	// Extract HTML title if HTML
	if strings.Contains(strings.ToLower(res.ContentType), "html") {
		matches := titleRegex.FindStringSubmatch(bodyStr)
		if len(matches) > 1 {
			res.HTMLTitle = strings.TrimSpace(matches[1])
		}
	}

	// Determine if asset is exposed
	if resp.StatusCode == http.StatusOK {
		res.IsExposed = true
		// Filter out custom 404 pages returning 200 OK
		if strings.Contains(strings.ToLower(bodyStr), "page not found") || strings.Contains(strings.ToLower(bodyStr), "404 not found") {
			res.IsExposed = false
		}
		// Confirm .env files
		if strings.Contains(target.URL, ".env") && !envSensitive.MatchString(bodyStr) && !strings.Contains(bodyStr, "=") {
			res.IsExposed = false
		}
	} else if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		res.IsExposed = false
	}

	return res
}

// ProbeBatch executes concurrent probes across multiple targets using a worker pool.
func ProbeBatch(ctx context.Context, targets []ProbeTarget, opts ProbeOptions) []ProbeResult {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 15
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipTLS,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	results := make([]ProbeResult, 0, len(targets))
	var mu sync.Mutex

	jobs := make(chan ProbeTarget, len(targets))
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := opts.Concurrency
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers <= 0 {
		workers = 1
	}

	allowedStatusMap := make(map[int]bool)
	for _, s := range opts.FilterStatuses {
		allowedStatusMap[s] = true
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := ProbeSingle(ctx, client, target, opts.UserAgent)
					if len(allowedStatusMap) > 0 && !allowedStatusMap[res.StatusCode] {
						continue
					}
					mu.Lock()
					results = append(results, res)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return results
}

// DeriveProbeURLsFromDomain generates standard high-value endpoints to probe for a domain.
func DeriveProbeURLsFromDomain(domain string) []ProbeTarget {
	cleanDomain := engine.SanitizeTarget(domain)
	if cleanDomain == "" {
		cleanDomain = domain
	}

	scheme := "https://"

	type PathSpec struct {
		Path        string
		Category    models.Category
		Severity    models.Severity
		Title       string
		Remediation string
	}

	paths := []PathSpec{
		{"/.env", models.CategoryConfigs, models.SeverityCritical, "Exposed Root .env File", "Deny web access to dotfiles in Nginx/Apache."},
		{"/.env.local", models.CategoryConfigs, models.SeverityCritical, "Exposed Next.js/Nuxt .env.local", "Block .env.local in web server configuration."},
		{"/.env.production", models.CategoryConfigs, models.SeverityCritical, "Exposed Production .env File", "Remove .env from public web tree."},
		{"/.git/HEAD", models.CategorySourceCode, models.SeverityCritical, "Exposed .git Repository", "Deny access to /.git/ directory on web server."},
		{"/actuator/env", models.CategoryConfigs, models.SeverityCritical, "Spring Boot Actuator Env Endpoint", "Exclude actuator/env in application properties."},
		{"/actuator/heapdump", models.CategoryBackups, models.SeverityCritical, "Spring Boot Heapdump", "Disable heapdump actuator endpoint in production."},
		{"/actuator/health", models.CategoryAdmin, models.SeverityLow, "Spring Boot Actuator Health", "Restrict actuator metrics to internal network."},
		{"/swagger.json", models.CategoryAPIEndpoints, models.SeverityHigh, "Exposed Swagger/OpenAPI Spec", "Restrict Swagger UI and JSON specs to authenticated users."},
		{"/openapi.json", models.CategoryAPIEndpoints, models.SeverityHigh, "Exposed OpenAPI Specification", "Require auth for API definition endpoints."},
		{"/api/v1", models.CategoryAPIEndpoints, models.SeverityLow, "API v1 Entrypoint", "Ensure API requires token/session authentication."},
		{"/graphql", models.CategoryAPIEndpoints, models.SeverityMedium, "GraphQL Endpoint", "Disable GraphQL introspection in production."},
		{"/wp-config.php.bak", models.CategoryConfigs, models.SeverityCritical, "WordPress wp-config Backup", "Delete backup files from web directory."},
		{"/phpinfo.php", models.CategoryErrors, models.SeverityMedium, "PHP Info Diagnostic Page", "Remove phpinfo() scripts from production servers."},
		{"/server-status", models.CategoryErrors, models.SeverityHigh, "Apache mod_status Console", "Restrict /server-status to 127.0.0.1."},
		{"/server-info", models.CategoryErrors, models.SeverityHigh, "Apache mod_info Console", "Restrict /server-info to localhost."},
		{"/admin", models.CategoryAdmin, models.SeverityHigh, "Admin Management Portal", "Place admin portal behind MFA and VPN."},
		{"/admin/login", models.CategoryAdmin, models.SeverityHigh, "Admin Login Page", "Enforce rate limiting and MFA."},
		{"/phpmyadmin/", models.CategoryAdmin, models.SeverityCritical, "phpMyAdmin Web Interface", "Remove phpMyAdmin or restrict access to internal VPN."},
		{"/robots.txt", models.CategoryDocs, models.SeverityLow, "Robots.txt Crawl Policy", "Review disallowed paths for sensitive exposure."},
		{"/sitemap.xml", models.CategoryDocs, models.SeverityLow, "Sitemap XML", "Verify public sitemap does not expose internal endpoints."},
		{"/backup.sql", models.CategoryBackups, models.SeverityCritical, "Exposed SQL Database Dump", "Delete SQL dump files immediately."},
		{"/dump.sql", models.CategoryBackups, models.SeverityCritical, "Exposed Database Dump", "Delete SQL dump files from public directory."},
		{"/db.sqlite3", models.CategoryBackups, models.SeverityCritical, "Exposed SQLite Database", "Store SQLite databases outside web root."},
		{"/terraform.tfstate", models.CategoryConfigs, models.SeverityCritical, "Exposed Terraform State File", "Store Terraform state in encrypted S3/GCS backend."},
	}

	targets := make([]ProbeTarget, 0, len(paths))
	for _, p := range paths {
		targetURL := scheme + cleanDomain + p.Path
		if _, err := url.Parse(targetURL); err == nil {
			targets = append(targets, ProbeTarget{
				URL:         targetURL,
				Category:    p.Category,
				Severity:    p.Severity,
				Title:       p.Title,
				Remediation: p.Remediation,
			})
		}
	}

	return targets
}
