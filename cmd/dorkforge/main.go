package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Nerd658/dorkforge/internal/browser"
	"github.com/Nerd658/dorkforge/internal/completion"
	"github.com/Nerd658/dorkforge/internal/dorks"
	"github.com/Nerd658/dorkforge/internal/engine"
	"github.com/Nerd658/dorkforge/internal/fetcher"
	"github.com/Nerd658/dorkforge/internal/models"
	"github.com/Nerd658/dorkforge/internal/output"
	"github.com/Nerd658/dorkforge/internal/prober"
	"github.com/Nerd658/dorkforge/internal/recon"
	"github.com/Nerd658/dorkforge/internal/scraper"
	"github.com/Nerd658/dorkforge/internal/subdomains"
)

const (
	Version   = "1.0.0"
	AppBanner = `
     _            _     __                     
  __| | ___  _ __| | __/ _| ___  _ __ __ _  ___ 
 / _` + "`" + ` |/ _ \| '__| |/ / |_ / _ \| '__/ _` + "`" + ` |/ _ \
| (_| | (_) | |  |   <|  _| (_) | | | (_| |  __/
 \__,_|\___/|_|  |_|\_\_|  \___/|_|  \__, |\___|
                                     |___/      
 Advanced Search Dorking & Passive Reconnaissance Engine`
)

const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cRed     = "\033[1;31m"
	cGreen   = "\033[1;32m"
	cYellow  = "\033[1;33m"
	cBlue    = "\033[1;34m"
	cMagenta = "\033[1;35m"
	cCyan    = "\033[1;36m"
	cGray    = "\033[0;90m"
)

func printUsage() {
	noColor := output.ShouldDisableColor()
	cyan, green, yellow, bold, dim, reset := "", "", "", "", "", ""
	red, magenta := "", ""
	if !noColor {
		cyan = cCyan
		green = cGreen
		yellow = cYellow
		bold = cBold
		dim = cDim
		reset = cReset
		red = cRed
		magenta = cMagenta
	}

	fmt.Printf("%s%s%s\n", cyan, AppBanner, reset)
	fmt.Printf(" %sVersion:%s %sv%s%s  %s|%s  %sLicense:%s %sMIT%s  %s|%s  %sRepository:%s %sgithub.com/Nerd658/dorkforge%s\n\n",
		dim, reset, bold, Version, reset, dim, reset, dim, reset, green, reset, dim, reset, dim, reset, cyan, reset)

	fmt.Printf("%s%sABOUT%s\n", bold, yellow, reset)
	fmt.Printf("  DorkForge is an advanced passive reconnaissance and search engine dorking CLI tool.\n")
	fmt.Printf("  It synthesizes targeted, high-precision audit queries across 5 search engines inspired by\n")
	fmt.Printf("  Exploit-DB's Google Hacking Database (GHDB) and modern DevSecOps cloud security benchmarks.\n\n")

	fmt.Printf("%s%sUSAGE%s\n", bold, yellow, reset)
	fmt.Printf("  dorkforge %s<command>%s [flags]\n\n", green, reset)

	fmt.Printf("%s%sAVAILABLE COMMANDS%s\n", bold, yellow, reset)
	fmt.Printf("  %s%-14s%s %sExecute passive dorking reconnaissance on single or multiple targets%s\n", green, "scan", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sExtract historical URLs from Wayback Machine CDX & AlienVault OTX%s\n", green, "fetch", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sActively probe high-value exposed endpoints (HTTP status verification)%s\n", green, "probe", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sFull automated reconnaissance pipeline (scan + fetch + live + probe)%s\n", green, "recon", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sGenerate negative exclusion search chains for subdomain discovery%s\n", green, "subdomains", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sInspect built-in signatures catalog with category and keyword filters%s\n", green, "list", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sList all 12 audit categories, risk severities, and descriptions%s\n", green, "categories", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sGenerate shell autocompletion scripts (bash, zsh, fish)%s\n", green, "completion", reset, dim, reset)
	fmt.Printf("  %s%-14s%s %sDisplay version and build information%s\n", green, "version", reset, dim, reset)

	fmt.Printf("\n%s%sSUPPORTED SEARCH ENGINES (-e, --engine)%s\n", bold, yellow, reset)
	fmt.Printf("  %s%-12s%s Google Search (GHDB operators: site, inurl, intitle, ext, filetype)\n", cyan, "google", reset)
	fmt.Printf("  %s%-12s%s GitHub Code Search (API tokens, repo secrets, commit disclosures)\n", cyan, "github", reset)
	fmt.Printf("  %s%-12s%s DuckDuckGo (Non-personalized index & unranked parameter listings)\n", cyan, "duckduckgo", reset)
	fmt.Printf("  %s%-12s%s Bing (Subdomain discovery, IP hosting, unlinked document indexing)\n", cyan, "bing", reset)
	fmt.Printf("  %s%-12s%s Shodan (Internet-facing host fingerprints & SSL certificate SANs)\n", cyan, "shodan", reset)

	fmt.Printf("\n%s%sSUPPORTED EXPORT FORMATS (-f, --format)%s\n", bold, yellow, reset)
	fmt.Printf("  %s%-12s%s Formatted Markdown audit deliverable with remediation tables (default)\n", magenta, "markdown", reset)
	fmt.Printf("  %s%-12s%s Interactive HTML web dashboard with live search, filters & quick launch\n", magenta, "html", reset)
	fmt.Printf("  %s%-12s%s Structured JSON report for CI/CD integration and automated ingestion\n", magenta, "json", reset)
	fmt.Printf("  %s%-12s%s Plaintext newline-delimited list of encoded search URLs\n", magenta, "urls", reset)

	fmt.Printf("\n%s%sPRACTICAL WORKFLOW EXAMPLES%s\n", bold, yellow, reset)
	fmt.Printf("  %s# 1. Quick triage: Audit critical configs and credentials%s\n", dim, reset)
	fmt.Printf("  dorkforge scan -d %sexample.com%s -c %sconfigs,secrets%s -s %shigh%s\n\n", cyan, reset, green, reset, red, reset)

	fmt.Printf("  %s# 2. Live search scraping (DuckDuckGo real results extraction)%s\n", dim, reset)
	fmt.Printf("  dorkforge scan -d %sexample.com%s -c %sconfigs,secrets%s --live\n\n", cyan, reset, green, reset)

	fmt.Printf("  %s# 3. Mine historical web archive URLs (Wayback + AlienVault OTX)%s\n", dim, reset)
	fmt.Printf("  dorkforge fetch -d %sexample.com%s --subs --sensitive-only -o %surls.txt%s\n\n", cyan, reset, yellow, reset)

	fmt.Printf("  %s# 4. Actively probe endpoints on target host (HTTP 200/403 verification)%s\n", dim, reset)
	fmt.Printf("  dorkforge probe -d %sexample.com%s -c %sconfigs,admin%s -t %s20%s -o %sprobe_report.html%s -f %shtml%s\n\n",
		cyan, reset, green, reset, cyan, reset, yellow, reset, magenta, reset)

	fmt.Printf("  %s# 5. Passive subdomain expansion excluding known hosts%s\n", dim, reset)
	fmt.Printf("  dorkforge subdomains -d %sexample.com%s --exclude %smail,blog,vpn,api,dev%s\n\n", cyan, reset, yellow, reset)

	fmt.Printf("%s%sENVIRONMENT VARIABLES%s\n", bold, yellow, reset)
	fmt.Printf("  %sNO_COLOR=1%s              Disable ANSI color codes in terminal output\n", green, reset)
	fmt.Printf("  %sDORKFORGE_NO_COLOR=1%s    Alternative flag to force monochrome terminal display\n\n", green, reset)

	fmt.Printf("%sRun 'dorkforge <command> -h' for command-specific flags and parameters.%s\n\n", dim, reset)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "scan":
		handleScan(os.Args[2:])
	case "fetch":
		handleFetch(os.Args[2:])
	case "probe":
		handleProbe(os.Args[2:])
	case "recon":
		handleRecon(os.Args[2:])
	case "subdomains":
		handleSubdomains(os.Args[2:])
	case "list":
		handleList(os.Args[2:])
	case "categories":
		handleCategories()
	case "completion":
		handleCompletion(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("dorkforge v%s (go1.22+ linux/amd64)\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func parseCategoryList(val string) []models.Category {
	if strings.TrimSpace(val) == "" || strings.ToLower(val) == "all" {
		return nil
	}
	parts := strings.Split(val, ",")
	var cats []models.Category
	for _, p := range parts {
		norm := strings.ToLower(strings.TrimSpace(p))
		if models.IsValidCategory(norm) {
			cats = append(cats, models.Category(norm))
		}
	}
	return cats
}

func parseEngineList(val string) []models.Engine {
	if strings.TrimSpace(val) == "" || strings.ToLower(val) == "all" {
		return nil
	}
	parts := strings.Split(val, ",")
	var engines []models.Engine
	for _, p := range parts {
		norm := strings.ToLower(strings.TrimSpace(p))
		if models.IsValidEngine(norm) {
			engines = append(engines, models.Engine(norm))
		}
	}
	return engines
}

func handleScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	var (
		domainFlag      string
		listFlag        string
		categoryFlag    string
		minSeverityFlag string
		engineFlag      string
		searchFlag      string
		outputFlag      string
		formatFlag      string
		customFlag      string
		openBrowser     bool
		liveFlag        bool
		probeFlag       bool
		batchSize       int
		delayMs         int
		noColor         bool
	)

	fs.StringVar(&domainFlag, "d", "", "Target domain (e.g. example.com)")
	fs.StringVar(&domainFlag, "domain", "", "Target domain (e.g. example.com)")
	fs.StringVar(&listFlag, "l", "", "Path to file containing domain targets (one per line)")
	fs.StringVar(&listFlag, "list", "", "Path to file containing domain targets (one per line)")
	fs.StringVar(&categoryFlag, "c", "all", "Comma-separated categories or 'all'")
	fs.StringVar(&categoryFlag, "category", "all", "Comma-separated categories or 'all'")
	fs.StringVar(&minSeverityFlag, "s", "", "Minimum severity filter: low, medium, high, critical")
	fs.StringVar(&minSeverityFlag, "min-severity", "", "Minimum severity filter: low, medium, high, critical")
	fs.StringVar(&engineFlag, "e", "all", "Engines to use: google, github, duckduckgo, bing, shodan, or all")
	fs.StringVar(&engineFlag, "engine", "all", "Engines to use: google, github, duckduckgo, bing, shodan, or all")
	fs.StringVar(&searchFlag, "q", "", "Keyword search within dork descriptions or templates")
	fs.StringVar(&searchFlag, "search", "", "Keyword search within dork descriptions or templates")
	fs.StringVar(&outputFlag, "o", "", "Output file path (e.g. report.md, results.json, report.html)")
	fs.StringVar(&outputFlag, "output", "", "Output file path (e.g. report.md, results.json, report.html)")
	fs.StringVar(&formatFlag, "f", "markdown", "Export format: markdown, json, html, urls")
	fs.StringVar(&formatFlag, "format", "markdown", "Export format: markdown, json, html, urls")
	fs.StringVar(&customFlag, "custom", "", "Path to custom JSON dorks file")
	fs.BoolVar(&openBrowser, "open", false, "Open generated queries in default web browser")
	fs.BoolVar(&liveFlag, "live", false, "Scrape DuckDuckGo search results in real-time")
	fs.BoolVar(&probeFlag, "probe", false, "Actively probe target host for exposed files")
	fs.IntVar(&batchSize, "batch-size", 5, "Number of search tabs to open per batch")
	fs.IntVar(&delayMs, "delay", 2000, "Delay in milliseconds between browser batches")
	fs.BoolVar(&noColor, "no-color", false, "Disable colorized terminal output")

	fs.Usage = func() {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s%sSCAN COMMAND USAGE%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge scan %s-d <domain>%s [flags]\n", cyan, reset)
		fmt.Printf("  dorkforge scan %s-l <targets.txt>%s [flags]\n\n", cyan, reset)

		fmt.Printf("%s%sTARGET OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-d, --domain%s %s<string>%s         Target root domain (e.g. example.com)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-l, --list%s   %s<file>%s           Path to file containing domain targets (one per line)\n\n", green, reset, cyan, reset)

		fmt.Printf("%s%sFILTER OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-c, --category%s %s<list>%s         Categories (configs, secrets, admin, backups, cloud, etc.) [default: all]\n", green, reset, cyan, reset)
		fmt.Printf("  %s-s, --min-severity%s %s<level>%s    Minimum risk severity (low, medium, high, critical)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-e, --engine%s %s<list>%s           Search engines (google, github, duckduckgo, bing, shodan) [default: all]\n", green, reset, cyan, reset)
		fmt.Printf("  %s-q, --search%s %s<keyword>%s        Filter dorks by search keyword\n", green, reset, cyan, reset)
		fmt.Printf("  %s--custom%s %s<path.json>%s          Path to custom JSON dorks catalog\n\n", green, reset, cyan, reset)

		fmt.Printf("%s%sEXECUTION MODES%s\n", bold, yellow, reset)
		fmt.Printf("  %s--live%s                          Scrape live search engine results (DuckDuckGo HTML)\n", green, reset)
		fmt.Printf("  %s--probe%s                         Actively test HTTP status codes of sensitive endpoints\n", green, reset)
		fmt.Printf("  %s--open%s                          Open generated search queries in default web browser\n", green, reset)
		fmt.Printf("  %s--batch-size%s %s<int>%s            Number of browser tabs to open per batch [default: 5]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--delay%s %s<ms>%s                  Delay in milliseconds between browser batches [default: 2000]\n\n", green, reset, cyan, reset)

		fmt.Printf("%s%sEXPORT & REPORT OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-o, --output%s %s<file>%s           Output report destination path (report.md, dashboard.html, data.json)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-f, --format%s %s<fmt>%s            Export format: markdown, html, json, urls [default: markdown]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--no-color%s                      Disable colorized terminal output\n\n", green, reset)
		fmt.Printf("%s%s%s\n", dim, "Run 'dorkforge -h' for global options.", reset)
	}

	_ = fs.Parse(args)

	if domainFlag == "" && listFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: must specify a target with -d <domain> or a target list with -l <file>\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if output.ShouldDisableColor() {
		noColor = true
	}

	// Prepare catalog
	catalog := make([]models.Dork, len(dorks.DefaultCatalog))
	copy(catalog, dorks.DefaultCatalog)

	if customFlag != "" {
		customList, err := dorks.LoadCustomDorks(customFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading custom dorks: %v\n", err)
			os.Exit(1)
		}
		catalog = append(catalog, customList...)
	}

	var minSev models.Severity
	if minSeverityFlag != "" {
		parsedSev, err := models.ParseSeverity(minSeverityFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		minSev = parsedSev
	}

	filters := engine.FilterOptions{
		Categories:  parseCategoryList(categoryFlag),
		MinSeverity: minSev,
		Engines:     parseEngineList(engineFlag),
		SearchQuery: searchFlag,
	}

	var targets []string
	if domainFlag != "" {
		targets = append(targets, domainFlag)
	}
	if listFlag != "" {
		file, err := os.Open(listFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading target list file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	for _, target := range targets {
		summary := engine.BuildScanSummary(target, catalog, filters)
		output.PrintScanResults(os.Stdout, summary, noColor)

		if liveFlag && len(summary.Results) > 0 {
			fmt.Printf("\n--- [LIVE SEARCH RESULTS EXTRACTION (DuckDuckGo)] ---\n\n")
			scraperOpts := scraper.DefaultScraperOptions()
			ctx := context.Background()

			for i, r := range summary.Results {
				if r.Dork.Engine == models.EngineGoogle || r.Dork.Engine == models.EngineDuckDuckGo {
					fmt.Printf("[%02d] Querying: %s\n", i+1, r.RenderedQuery)
					res, err := scraper.ScrapeDuckDuckGo(ctx, r.RenderedQuery, scraperOpts)
					if err == nil && res.TotalFound > 0 {
						for _, it := range res.Items {
							fmt.Printf("     -> Found: %s (%s)\n", it.TargetURL, it.Title)
						}
					} else {
						fmt.Printf("     -> (No public results index found)\n")
					}
					time.Sleep(500 * time.Millisecond) // Polite search delay
				}
			}
			fmt.Println()
		}

		if probeFlag {
			fmt.Printf("\n--- [ACTIVE HTTP ENDPOINT PROBING] ---\n\n")
			probeTargets := prober.DeriveProbeURLsFromDomain(target)
			probeOpts := prober.DefaultProbeOptions()
			results := prober.ProbeBatch(context.Background(), probeTargets, probeOpts)

			for _, p := range results {
				col, rst := output.StatusCodeColor(p.StatusCode, noColor)
				expTag := ""
				if p.IsExposed {
					expTag = " [EXPOSED VULNERABILITY!]"
				}
				fmt.Printf("  [%s%d%s] %-30s -> %s%s\n", col, p.StatusCode, rst, p.DorkTitle, p.URL, expTag)
			}
			fmt.Println()
		}

		if outputFlag != "" {
			var outFormat output.ExportFormat
			switch strings.ToLower(formatFlag) {
			case "json":
				outFormat = output.FormatJSON
			case "html":
				outFormat = output.FormatHTML
			case "urls":
				outFormat = output.FormatURLs
			default:
				outFormat = output.FormatMarkdown
			}

			if err := output.WriteOutput(outputFlag, outFormat, summary); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing report to %s: %v\n", outputFlag, err)
			} else {
				fmt.Printf("Report successfully exported to %s (format: %s)\n\n", outputFlag, outFormat)
			}
		}

		if openBrowser && len(summary.Results) > 0 {
			var urls []string
			for _, r := range summary.Results {
				urls = append(urls, r.SearchURL)
			}
			delayDuration := time.Duration(delayMs) * time.Millisecond
			if err := browser.OpenBatch(urls, batchSize, delayDuration); err != nil {
				fmt.Fprintf(os.Stderr, "Browser batch error: %v\n", err)
			}
		}
	}
}

func handleSubdomains(args []string) {
	fs := flag.NewFlagSet("subdomains", flag.ExitOnError)
	var (
		domainFlag  string
		excludeFlag string
		outputFlag  string
		formatFlag  string
		openBrowser bool
		noColor     bool
	)

	fs.StringVar(&domainFlag, "d", "", "Target domain (e.g. example.com)")
	fs.StringVar(&domainFlag, "domain", "", "Target domain (e.g. example.com)")
	fs.StringVar(&excludeFlag, "exclude", "", "Comma-separated subdomains to exclude (e.g. mail,blog,app)")
	fs.StringVar(&outputFlag, "o", "", "Output file path")
	fs.StringVar(&formatFlag, "f", "markdown", "Export format: markdown, json, html, urls")
	fs.BoolVar(&openBrowser, "open", false, "Open subdomain dorks in default browser")
	fs.BoolVar(&noColor, "no-color", false, "Disable color output")

	fs.Usage = func() {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s%sSUBDOMAINS COMMAND USAGE%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge subdomains %s-d <domain>%s [flags]\n\n", cyan, reset)

		fmt.Printf("%s%sOPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-d, --domain%s  %s<string>%s        Target domain (e.g. example.com)\n", green, reset, cyan, reset)
		fmt.Printf("  %s--exclude%s     %s<list>%s          Known subdomains to exclude (e.g. mail,blog,app)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-o, --output%s  %s<file>%s          Output file destination path\n", green, reset, cyan, reset)
		fmt.Printf("  %s-f, --format%s  %s<fmt>%s           Export format: markdown, html, json, urls [default: markdown]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--open%s                          Open generated queries in default web browser\n", green, reset)
		fmt.Printf("  %s--no-color%s                      Disable color output\n\n", green, reset)
		fmt.Printf("%s%s%s\n", dim, "Run 'dorkforge -h' for global options.", reset)
	}

	_ = fs.Parse(args)

	if domainFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: must specify target domain with -d <domain>\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if output.ShouldDisableColor() {
		noColor = true
	}

	var known []string
	if excludeFlag != "" {
		for _, s := range strings.Split(excludeFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				known = append(known, trimmed)
			}
		}
	}

	dorkSet := subdomains.GenerateSubdomainQueries(domainFlag, known)
	summary := models.ScanSummary{
		Target:      dorkSet.Target,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		TotalDorks:  len(dorkSet.Queries),
		SeverityCounts: map[models.Severity]int{
			models.SeverityLow: len(dorkSet.Queries),
		},
		Results: dorkSet.Queries,
	}

	output.PrintScanResults(os.Stdout, summary, noColor)

	if outputFlag != "" {
		var outFormat output.ExportFormat
		switch strings.ToLower(formatFlag) {
		case "json":
			outFormat = output.FormatJSON
		case "html":
			outFormat = output.FormatHTML
		case "urls":
			outFormat = output.FormatURLs
		default:
			outFormat = output.FormatMarkdown
		}

		if err := output.WriteOutput(outputFlag, outFormat, summary); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output to %s: %v\n", outputFlag, err)
		} else {
			fmt.Printf("Subdomain queries exported to %s\n\n", outputFlag)
		}
	}

	if openBrowser {
		var urls []string
		for _, q := range dorkSet.Queries {
			urls = append(urls, q.SearchURL)
		}
		_ = browser.OpenBatch(urls, 5, 1500*time.Millisecond)
	}
}

func handleList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var (
		categoryFlag string
		customFlag   string
		noColor      bool
	)

	fs.StringVar(&categoryFlag, "c", "", "Filter list by category")
	fs.StringVar(&customFlag, "custom", "", "Include custom dorks JSON file")
	fs.BoolVar(&noColor, "no-color", false, "Disable color output")

	fs.Usage = func() {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s%sLIST COMMAND USAGE%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge list [flags]\n\n")

		fmt.Printf("%s%sOPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-c%s        %s<category>%s          Filter catalog by category name\n", green, reset, cyan, reset)
		fmt.Printf("  %s--custom%s  %s<path.json>%s         Include custom JSON signatures catalog\n", green, reset, cyan, reset)
		fmt.Printf("  %s--no-color%s                      Disable color output\n\n", green, reset)
		fmt.Printf("%s%s%s\n", dim, "Run 'dorkforge -h' for global options.", reset)
	}

	_ = fs.Parse(args)

	if output.ShouldDisableColor() {
		noColor = true
	}

	catalog := make([]models.Dork, len(dorks.DefaultCatalog))
	copy(catalog, dorks.DefaultCatalog)

	if customFlag != "" {
		customList, err := dorks.LoadCustomDorks(customFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading custom dorks: %v\n", err)
			os.Exit(1)
		}
		catalog = append(catalog, customList...)
	}

	if categoryFlag != "" {
		var filtered []models.Dork
		norm := strings.ToLower(categoryFlag)
		for _, d := range catalog {
			if string(d.Category) == norm {
				filtered = append(filtered, d)
			}
		}
		catalog = filtered
	}

	output.PrintCatalog(os.Stdout, catalog, noColor)
}

func handleCategories() {
	noCol := output.ShouldDisableColor()
	cyan, bold, dim, reset := "", "", "", ""
	if !noCol {
		cyan = cCyan
		bold = cBold
		dim = cDim
		reset = cReset
	}

	fmt.Printf("\n%s================================================================================%s\n", dim, reset)
	fmt.Printf(" %s%sDORKFORGE SUPPORTED CATEGORIES (12 CATEGORIES)%s\n", bold, cyan, reset)
	fmt.Printf("%s================================================================================%s\n\n", dim, reset)

	categoriesInfo := []struct {
		Name        string
		Severity    string
		SevColor    string
		Description string
	}{
		{"configs", "CRITICAL", cRed, "Exposed .env files, server configurations (nginx, apache), docker-compose"},
		{"secrets", "CRITICAL", cRed, "AWS access keys, SSH/RSA private keys, GitHub tokens, database passwords"},
		{"admin", "HIGH", cYellow, "Administrative login portals, phpMyAdmin, Jenkins, Grafana, Kibana"},
		{"backups", "HIGH", cYellow, "Database dumps (.sql, .dump), compressed source archives (.tar.gz, .zip)"},
		{"cloud", "HIGH/MED", cYellow, "Public Amazon S3 buckets, Azure Blob containers, Google Cloud Storage"},
		{"source-code", "HIGH", cYellow, "Exposed .git folders, code leaks on GitHub / GitLab"},
		{"errors", "MEDIUM", cBlue, "PHP info diagnostics, framework stack traces, application error logs"},
		{"docs", "MED/LOW", cBlue, "Confidential PDF documents, payroll spreadsheets, internal organigrams"},
		{"api-endpoints", "HIGH", cYellow, "Exposed Swagger/OpenAPI specs, GraphQL consoles, Postman collections"},
		{"subdomains", "LOW", cCyan, "Search engine exclusion chains and Shodan SSL certificate recon"},
		{"network-iot", "HIGH", cYellow, "Router/firewall interfaces (pfSense, FortiGate), web terminals"},
		{"employees-osint", "LOW", cCyan, "LinkedIn profiles, employee directories, email footprinting"},
	}

	for _, c := range categoriesInfo {
		sevColor := ""
		if !noCol {
			sevColor = c.SevColor
		}
		fmt.Printf("  %s%-18s%s %s[%-8s]%s : %s%s%s\n",
			cyan, c.Name, reset,
			sevColor, c.Severity, reset,
			dim, c.Description, reset,
		)
	}
	fmt.Println()
}

func handleCompletion(args []string) {
	if len(args) < 1 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s================================================================================%s\n", dim, reset)
		fmt.Printf(" %s%sDORKFORGE SHELL AUTOCOMPLETION GENERATOR%s\n", bold, cyan, reset)
		fmt.Printf("%s================================================================================%s\n\n", dim, reset)
		fmt.Printf("%sGenerate fast autocompletion scripts for your interactive shell.%s\n\n", dim, reset)

		fmt.Printf("%s%sUSAGE%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge completion %s<shell>%s\n\n", green, reset)

		fmt.Printf("%s%sSUPPORTED SHELLS%s\n", bold, yellow, reset)
		fmt.Printf("  %s%-12s%s %sGenerate autocompletion script for Bash%s\n", green, "bash", reset, dim, reset)
		fmt.Printf("  %s%-12s%s %sGenerate autocompletion script for Zsh%s\n", green, "zsh", reset, dim, reset)
		fmt.Printf("  %s%-12s%s %sGenerate autocompletion script for Fish%s\n\n", green, "fish", reset, dim, reset)

		fmt.Printf("%s%sINSTALLATION EXAMPLES%s\n", bold, yellow, reset)
		fmt.Printf("  %s# Bash (temporary or current session):%s\n", dim, reset)
		fmt.Printf("  source <(dorkforge completion %sbash%s)\n\n", green, reset)
		fmt.Printf("  %s# Bash (persistent):%s\n", dim, reset)
		fmt.Printf("  dorkforge completion %sbash%s > ~/.local/share/bash-completion/completions/dorkforge\n\n", green, reset)
		fmt.Printf("  %s# Zsh:%s\n", dim, reset)
		fmt.Printf("  dorkforge completion %szsh%s > \"${fpath[1]}/_dorkforge\"\n\n", green, reset)
		fmt.Printf("  %s# Fish:%s\n", dim, reset)
		fmt.Printf("  dorkforge completion %sfish%s > ~/.config/fish/completions/dorkforge.fish\n\n", green, reset)

		if len(args) >= 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			return
		}
		os.Exit(1)
	}

	shell := args[0]
	script, err := completion.Generate(shell)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(script)
}

func handleFetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	var (
		domainFlag    string
		subsFlag      bool
		sensitiveOnly bool
		outputFlag    string
		formatFlag    string
		limitFlag     int
		timeoutFlag   int
		noColor       bool
	)

	fs.StringVar(&domainFlag, "d", "", "Target domain (e.g. example.com)")
	fs.StringVar(&domainFlag, "domain", "", "Target domain (e.g. example.com)")
	fs.BoolVar(&subsFlag, "subs", true, "Include subdomains in archive lookup")
	fs.BoolVar(&sensitiveOnly, "sensitive-only", false, "Filter output to sensitive extensions and endpoints only")
	fs.StringVar(&outputFlag, "o", "", "Output file path (e.g. urls.txt, archive.json, report.md)")
	fs.StringVar(&outputFlag, "output", "", "Output file path (e.g. urls.txt, archive.json, report.md)")
	fs.StringVar(&formatFlag, "f", "urls", "Export format: urls, json, markdown")
	fs.StringVar(&formatFlag, "format", "urls", "Export format: urls, json, markdown")
	fs.IntVar(&limitFlag, "limit", 1000, "Maximum number of archive URLs to retrieve")
	fs.IntVar(&timeoutFlag, "timeout", 15, "Network timeout in seconds for archive queries")
	fs.BoolVar(&noColor, "no-color", false, "Disable colorized terminal output")

	fs.Usage = func() {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s%sFETCH COMMAND USAGE (Historical Web Archive Mining)%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge fetch %s-d <domain>%s [flags]\n\n", cyan, reset)

		fmt.Printf("%s%sOPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-d, --domain%s        %s<string>%s   Target root domain (e.g. example.com)\n", green, reset, cyan, reset)
		fmt.Printf("  %s--subs%s                            Include subdomains in lookup [default: true]\n", green, reset)
		fmt.Printf("  %s--sensitive-only%s                  Filter to sensitive endpoints (.env, .sql, /admin, etc.)\n", green, reset)
		fmt.Printf("  %s-o, --output%s        %s<file>%s     Output destination path\n", green, reset, cyan, reset)
		fmt.Printf("  %s-f, --format%s        %s<fmt>%s      Export format: urls, json, markdown [default: urls]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--limit%s             %s<int>%s      Maximum URLs to extract [default: 1000]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--timeout%s           %s<sec>%s      Timeout in seconds [default: 15]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--no-color%s                        Disable color output\n\n", green, reset)
		fmt.Printf("%s%s%s\n", dim, "Run 'dorkforge -h' for global options.", reset)
	}

	_ = fs.Parse(args)

	if domainFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: must specify target domain with -d <domain>\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if output.ShouldDisableColor() {
		noColor = true
	}

	fmt.Printf("\n[+] Mining historical URLs for %s (Wayback Machine + AlienVault OTX)...\n", domainFlag)
	opts := fetcher.DefaultFetchOptions()
	opts.IncludeSubdomains = subsFlag
	opts.SensitiveOnly = sensitiveOnly
	opts.Limit = limitFlag
	opts.Timeout = time.Duration(timeoutFlag) * time.Second

	res, err := fetcher.FetchAll(context.Background(), domainFlag, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching archive URLs: %v\n", err)
		os.Exit(1)
	}

	b, r, cyan, green, yellow, dim := "", "", "", "", "", ""
	if !noColor {
		b = cBold
		r = cReset
		cyan = cCyan
		green = cGreen
		yellow = cYellow
		dim = cDim
	}

	fmt.Printf("\n%s================================================================================%s\n", dim, r)
	fmt.Printf(" %sDORKFORGE ARCHIVE URL EXTRACTION RESULTS%s\n", b, r)
	fmt.Printf(" Target         : %s%s%s\n", cyan, res.Target, r)
	fmt.Printf(" Total URLs     : %s%d%s\n", green, res.TotalURLs, r)
	fmt.Printf(" Sensitive URLs : %s%d%s\n", yellow, res.SensitiveURLs, r)
	fmt.Printf("%s================================================================================%s\n\n", dim, r)

	for i, item := range res.Items {
		sensTag := ""
		if item.IsSensitive {
			sensTag = fmt.Sprintf(" [%s%s%s]", cRed, "SENSITIVE", r)
		}
		fmt.Printf("%03d. [%s] %s%s\n", i+1, item.Source, item.URL, sensTag)
	}
	fmt.Println()

	if outputFlag != "" {
		var data []byte
		switch strings.ToLower(formatFlag) {
		case "json":
			data, _ = json.MarshalIndent(res, "", "  ")
		case "markdown":
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("# Historical Archive URLs - %s\n\n", res.Target))
			sb.WriteString(fmt.Sprintf("Total URLs: %d | Sensitive Assets: %d\n\n", res.TotalURLs, res.SensitiveURLs))
			sb.WriteString("| # | Source | Sensitive | Category | URL |\n|---|---|---|---|---|\n")
			for i, it := range res.Items {
				sb.WriteString(fmt.Sprintf("| %d | %s | %v | %s | `%s` |\n", i+1, it.Source, it.IsSensitive, it.Category, it.URL))
			}
			data = []byte(sb.String())
		default:
			var sb strings.Builder
			for _, it := range res.Items {
				sb.WriteString(it.URL + "\n")
			}
			data = []byte(sb.String())
		}

		if err := os.WriteFile(outputFlag, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output to %s: %v\n", outputFlag, err)
		} else {
			fmt.Printf("Archive URLs successfully exported to %s (format: %s)\n\n", outputFlag, formatFlag)
		}
	}
}

func handleProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	var (
		domainFlag      string
		listFlag        string
		concurrencyFlag int
		timeoutFlag     int
		outputFlag      string
		formatFlag      string
		noColor         bool
	)

	fs.StringVar(&domainFlag, "d", "", "Target domain (e.g. example.com)")
	fs.StringVar(&domainFlag, "domain", "", "Target domain (e.g. example.com)")
	fs.StringVar(&listFlag, "l", "", "Path to file containing domain targets (one per line)")
	fs.StringVar(&listFlag, "list", "", "Path to file containing domain targets (one per line)")
	fs.IntVar(&concurrencyFlag, "t", 15, "Concurrency / worker count")
	fs.IntVar(&concurrencyFlag, "concurrency", 15, "Concurrency / worker count")
	fs.IntVar(&timeoutFlag, "timeout", 5, "HTTP request timeout in seconds")
	fs.StringVar(&outputFlag, "o", "", "Output file path (e.g. report.html, probe.json, probe.md)")
	fs.StringVar(&outputFlag, "output", "", "Output file path (e.g. report.html, probe.json, probe.md)")
	fs.StringVar(&formatFlag, "f", "markdown", "Export format: markdown, html, json, urls")
	fs.StringVar(&formatFlag, "format", "markdown", "Export format: markdown, json, html, urls")
	fs.BoolVar(&noColor, "no-color", false, "Disable colorized terminal output")

	fs.Usage = func() {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s%sPROBE COMMAND USAGE (Active HTTP Endpoint Probing)%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge probe %s-d <domain>%s [flags]\n", cyan, reset)
		fmt.Printf("  dorkforge probe %s-l <targets.txt>%s [flags]\n\n", cyan, reset)

		fmt.Printf("%s%sOPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-d, --domain%s        %s<string>%s   Target root domain (e.g. example.com)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-l, --list%s          %s<file>%s     Path to file with target domains\n", green, reset, cyan, reset)
		fmt.Printf("  %s-t, --concurrency%s   %s<int>%s      Worker count [default: 15]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--timeout%s           %s<sec>%s      Timeout in seconds [default: 5]\n", green, reset, cyan, reset)
		fmt.Printf("  %s-o, --output%s        %s<file>%s     Output file path\n", green, reset, cyan, reset)
		fmt.Printf("  %s-f, --format%s        %s<fmt>%s      Export format: markdown, html, json, urls [default: markdown]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--no-color%s                        Disable color output\n\n", green, reset)
		fmt.Printf("%s%s%s\n", dim, "Run 'dorkforge -h' for global options.", reset)
	}

	_ = fs.Parse(args)

	if domainFlag == "" && listFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: must specify target domain with -d <domain> or -l <file>\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if output.ShouldDisableColor() {
		noColor = true
	}

	var targets []string
	if domainFlag != "" {
		targets = append(targets, domainFlag)
	}
	if listFlag != "" {
		file, err := os.Open(listFlag)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		}
	}

	probeOpts := prober.DefaultProbeOptions()
	probeOpts.Concurrency = concurrencyFlag
	probeOpts.Timeout = time.Duration(timeoutFlag) * time.Second

	for _, target := range targets {
		probeTargets := prober.DeriveProbeURLsFromDomain(target)
		fmt.Printf("\n[+] Actively probing %d sensitive endpoints on %s...\n", len(probeTargets), target)
		results := prober.ProbeBatch(context.Background(), probeTargets, probeOpts)

		b, r, cyan, dim := "", "", "", ""
		if !noColor {
			b = cBold
			r = cReset
			cyan = cCyan
			dim = cDim
		}

		fmt.Printf("\n%s================================================================================%s\n", dim, r)
		fmt.Printf(" %sDORKFORGE ACTIVE PROBE AUDIT RESULTS%s\n", b, r)
		fmt.Printf(" Target : %s%s%s\n", cyan, target, r)
		fmt.Printf(" Probed : %d endpoints\n", len(results))
		fmt.Printf("%s================================================================================%s\n\n", dim, r)

		exposedCount := 0
		for _, p := range results {
			col, rst := output.StatusCodeColor(p.StatusCode, noColor)
			expTag := ""
			if p.IsExposed {
				exposedCount++
				expTag = fmt.Sprintf(" %s[EXPOSED VULNERABILITY!]%s", cRed, rst)
			}
			fmt.Printf("  [%s%03d%s] %-32s -> %s%s\n", col, p.StatusCode, rst, p.DorkTitle, p.URL, expTag)
		}
		fmt.Printf("\nSummary: %d endpoints exposed with HTTP 200 OK.\n\n", exposedCount)

		if outputFlag != "" {
			var data []byte
			switch strings.ToLower(formatFlag) {
			case "json":
				data, _ = json.MarshalIndent(results, "", "  ")
			case "html":
				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("<!DOCTYPE html><html><head><title>Probe Report - %s</title>", target))
				sb.WriteString("<style>body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border:1px solid #30363d;text-align:left;}th{background:#161b22;}.s200{color:#3fb950;font-weight:bold;}.s403{color:#d29922;}.exp{color:#f85149;font-weight:bold;}</style></head><body>")
				sb.WriteString(fmt.Sprintf("<h1>Active Endpoint Probe Report: %s</h1>", target))
				sb.WriteString("<table><tr><th>Status</th><th>Endpoint Title</th><th>URL</th><th>Category</th><th>Severity</th><th>Exposed</th></tr>")
				for _, p := range results {
					cls := "sother"
					if p.StatusCode >= 200 && p.StatusCode < 300 {
						cls = "s200"
					} else if p.StatusCode == 403 || p.StatusCode == 401 {
						cls = "s403"
					}
					expStr := "No"
					if p.IsExposed {
						expStr = "<span class='exp'>YES</span>"
					}
					sb.WriteString(fmt.Sprintf("<tr><td class='%s'>%d</td><td>%s</td><td><a style='color:#58a6ff;' href='%s' target='_blank'>%s</a></td><td>%s</td><td>%s</td><td>%s</td></tr>",
						cls, p.StatusCode, p.DorkTitle, p.URL, p.URL, p.Category, p.Severity, expStr))
				}
				sb.WriteString("</table></body></html>")
				data = []byte(sb.String())
			default:
				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("# Active Endpoint Probe Report - `%s`\n\n", target))
				sb.WriteString("| Status | Title | URL | Category | Severity | Exposed |\n|---|---|---|---|---|---|\n")
				for _, p := range results {
					sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %v |\n", p.StatusCode, p.DorkTitle, p.URL, p.Category, p.Severity, p.IsExposed))
				}
				data = []byte(sb.String())
			}

			if err := os.WriteFile(outputFlag, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing probe output: %v\n", err)
			} else {
				fmt.Printf("Probe results successfully exported to %s (format: %s)\n\n", outputFlag, formatFlag)
			}
		}
	}
}

func handleRecon(args []string) {
	fs := flag.NewFlagSet("recon", flag.ExitOnError)
	var (
		domainFlag      string
		listFlag        string
		categoryFlag    string
		minSeverityFlag string
		engineFlag      string
		outputFlag      string
		formatFlag      string
		noFetch         bool
		noLive          bool
		noProbe         bool
		fetchLimit      int
		fetchTimeout    int
		concurrency     int
		noColor         bool
	)

	fs.StringVar(&domainFlag, "d", "", "Target domain (e.g. example.com)")
	fs.StringVar(&domainFlag, "domain", "", "Target domain (e.g. example.com)")
	fs.StringVar(&listFlag, "l", "", "Path to file containing domain targets (one per line)")
	fs.StringVar(&listFlag, "list", "", "Path to file containing domain targets (one per line)")
	fs.StringVar(&categoryFlag, "c", "all", "Comma-separated categories or 'all'")
	fs.StringVar(&categoryFlag, "category", "all", "Comma-separated categories or 'all'")
	fs.StringVar(&minSeverityFlag, "s", "", "Minimum severity filter: low, medium, high, critical")
	fs.StringVar(&minSeverityFlag, "min-severity", "", "Minimum severity filter: low, medium, high, critical")
	fs.StringVar(&engineFlag, "e", "all", "Engines to use: google, github, duckduckgo, bing, shodan, or all")
	fs.StringVar(&engineFlag, "engine", "all", "Engines to use: google, github, duckduckgo, bing, shodan, or all")
	fs.StringVar(&outputFlag, "o", "", "Output report destination path")
	fs.StringVar(&outputFlag, "output", "", "Output report destination path")
	fs.StringVar(&formatFlag, "f", "html", "Export format: html, markdown, json")
	fs.StringVar(&formatFlag, "format", "html", "Export format: html, markdown, json")
	fs.BoolVar(&noFetch, "no-fetch", false, "Skip historical archive URL mining")
	fs.BoolVar(&noLive, "no-live", false, "Skip live DuckDuckGo search scraping")
	fs.BoolVar(&noProbe, "no-probe", false, "Skip active HTTP endpoint probing")
	fs.IntVar(&fetchLimit, "fetch-limit", 200, "Maximum archive URLs to retrieve")
	fs.IntVar(&fetchTimeout, "fetch-timeout", 15, "Archive query timeout in seconds")
	fs.IntVar(&concurrency, "t", 15, "Probe concurrency / worker count")
	fs.IntVar(&concurrency, "concurrency", 15, "Probe concurrency / worker count")
	fs.BoolVar(&noColor, "no-color", false, "Disable colorized terminal output")

	fs.Usage = func() {
		noCol := output.ShouldDisableColor()
		yellow, green, cyan, bold, dim, reset := "", "", "", "", "", ""
		if !noCol {
			yellow = cYellow
			green = cGreen
			cyan = cCyan
			bold = cBold
			dim = cDim
			reset = cReset
		}

		fmt.Printf("\n%s%sRECON COMMAND USAGE (Full Automated Reconnaissance Pipeline)%s\n", bold, yellow, reset)
		fmt.Printf("  dorkforge recon %s-d <domain>%s [flags]\n", cyan, reset)
		fmt.Printf("  dorkforge recon %s-l <targets.txt>%s [flags]\n\n", cyan, reset)

		fmt.Printf("%s%sTARGET OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-d, --domain%s %s<string>%s         Target root domain (e.g. example.com)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-l, --list%s   %s<file>%s           Path to file containing domain targets (one per line)\n\n", green, reset, cyan, reset)

		fmt.Printf("%s%sFILTER OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-c, --category%s %s<list>%s         Categories filter [default: all]\n", green, reset, cyan, reset)
		fmt.Printf("  %s-s, --min-severity%s %s<level>%s    Minimum risk severity\n", green, reset, cyan, reset)
		fmt.Printf("  %s-e, --engine%s %s<list>%s           Search engines filter [default: all]\n\n", green, reset, cyan, reset)

		fmt.Printf("%s%sPHASE CONTROL%s\n", bold, yellow, reset)
		fmt.Printf("  %s--no-fetch%s                       Skip historical archive mining (Wayback + AlienVault)\n", green, reset)
		fmt.Printf("  %s--no-live%s                        Skip live DuckDuckGo search scraping\n", green, reset)
		fmt.Printf("  %s--no-probe%s                       Skip active HTTP endpoint probing\n", green, reset)
		fmt.Printf("  %s--fetch-limit%s %s<int>%s           Maximum archive URLs [default: 200]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--fetch-timeout%s %s<sec>%s         Archive query timeout [default: 15]\n", green, reset, cyan, reset)
		fmt.Printf("  %s-t, --concurrency%s %s<int>%s       Probe worker count [default: 15]\n\n", green, reset, cyan, reset)

		fmt.Printf("%s%sEXPORT & REPORT OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-o, --output%s %s<file>%s           Output report destination path\n", green, reset, cyan, reset)
		fmt.Printf("  %s-f, --format%s %s<fmt>%s            Export format: html, markdown, json [default: html]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--no-color%s                       Disable colorized terminal output\n\n", green, reset)
		fmt.Printf("%s%s%s\n", dim, "Run 'dorkforge -h' for global options.", reset)
	}

	_ = fs.Parse(args)

	if domainFlag == "" && listFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: must specify a target with -d <domain> or a target list with -l <file>\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if output.ShouldDisableColor() {
		noColor = true
	}

	var minSev models.Severity
	if minSeverityFlag != "" {
		parsedSev, err := models.ParseSeverity(minSeverityFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		minSev = parsedSev
	}

	reconOpts := recon.ReconOptions{
		SkipFetch:    noFetch,
		SkipLive:     noLive,
		SkipProbe:    noProbe,
		Categories:   parseCategoryList(categoryFlag),
		MinSeverity:  minSev,
		Engines:      parseEngineList(engineFlag),
		FetchLimit:   fetchLimit,
		FetchTimeout: time.Duration(fetchTimeout) * time.Second,
		Concurrency:  concurrency,
	}

	var targets []string
	if domainFlag != "" {
		targets = append(targets, domainFlag)
	}
	if listFlag != "" {
		file, err := os.Open(listFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading target list file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	b, r, cyan, green, yellow, dim, red := "", "", "", "", "", "", ""
	if !noColor {
		b = cBold
		r = cReset
		cyan = cCyan
		green = cGreen
		yellow = cYellow
		dim = cDim
		red = cRed
	}

	onPhase := func(phase string, status string) {
		if status == "started" {
			fmt.Printf("\n%s[PHASE]%s %s%s%s %s...\n", yellow, r, b, phase, r, dim)
		} else {
			fmt.Printf("%s[DONE]%s  %s%s%s\n", green, r, b, phase, r)
		}
	}

	ctx := context.Background()
	for _, target := range targets {
		fmt.Printf("\n%s=================================================================================%s\n", dim, r)
		fmt.Printf(" %s%sDORKFORGE FULL RECONNAISSANCE PIPELINE%s\n", b, cyan, r)
		fmt.Printf(" Target : %s%s%s\n", cyan, target, r)
		fmt.Printf("%s=================================================================================%s\n", dim, r)

		result, err := recon.RunRecon(ctx, target, reconOpts, onPhase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during reconnaissance: %v\n", err)
			continue
		}

		fmt.Printf("\n%s=================================================================================%s\n", dim, r)
		fmt.Printf(" %s%sRECONNAISSANCE SUMMARY%s\n", b, cyan, r)
		fmt.Printf("%s=================================================================================%s\n", dim, r)
		fmt.Printf("  Target          : %s%s%s\n", cyan, result.Target, r)
		fmt.Printf("  Duration        : %s%dms%s\n", green, result.DurationMs, r)

		riskColor := green
		if result.RiskScore >= 70 {
			riskColor = red
		} else if result.RiskScore >= 40 {
			riskColor = yellow
		}
		fmt.Printf("  Risk Score      : %s%d/100%s\n", riskColor, result.RiskScore, r)

		if result.Scan != nil {
			fmt.Printf("  Total Dorks     : %s%d%s\n", green, result.Scan.TotalDorks, r)
		}
		if result.Archive != nil {
			fmt.Printf("  Archive URLs    : %s%d%s (sensitive: %s%d%s)\n",
				green, result.Archive.TotalURLs, r, yellow, result.Archive.SensitiveURLs, r)
		}

		liveCount := 0
		for _, lf := range result.LiveResults {
			liveCount += len(lf.Items)
		}
		if liveCount > 0 {
			fmt.Printf("  Live Findings   : %s%d%s URLs extracted from search engines\n", green, liveCount, r)
		}
		if len(result.ProbeResults) > 0 {
			fmt.Printf("  Probed          : %s%d%s endpoints\n", green, len(result.ProbeResults), r)
			if result.ExposedCount > 0 {
				fmt.Printf("  Exposed         : %s%d%s endpoints confirmed accessible\n", red, result.ExposedCount, r)
			}
		}
		fmt.Println()

		if outputFlag != "" {
			if err := recon.WriteReconReport(outputFlag, formatFlag, result); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing report to %s: %v\n", outputFlag, err)
			} else {
				fmt.Printf("Report successfully exported to %s%s%s (format: %s)\n\n", cyan, outputFlag, r, formatFlag)
			}
		}
	}
}
