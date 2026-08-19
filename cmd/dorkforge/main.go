package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Nerd658/dorkforge/internal/browser"
	"github.com/Nerd658/dorkforge/internal/completion"
	"github.com/Nerd658/dorkforge/internal/dorks"
	"github.com/Nerd658/dorkforge/internal/engine"
	"github.com/Nerd658/dorkforge/internal/models"
	"github.com/Nerd658/dorkforge/internal/output"
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
	red, blue, magenta := "", "", ""
	if !noColor {
		cyan = cCyan
		green = cGreen
		yellow = cYellow
		bold = cBold
		dim = cDim
		reset = cReset
		red = cRed
		blue = cBlue
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

	fmt.Printf("  %s# 2. Comprehensive cloud audit: Firebase, S3, Azure Blob, Notion, Drive%s\n", dim, reset)
	fmt.Printf("  dorkforge scan -d %sexample.com%s -c %scloud,backups,source-code%s\n\n", cyan, reset, green, reset)

	fmt.Printf("  %s# 3. Export interactive HTML dashboard + Markdown report%s\n", dim, reset)
	fmt.Printf("  dorkforge scan -d %sexample.com%s -o %sdashboard.html%s -f %shtml%s\n", cyan, reset, yellow, reset, magenta, reset)
	fmt.Printf("  dorkforge scan -d %sexample.com%s -o %saudit-report.md%s -f %smarkdown%s\n\n", cyan, reset, yellow, reset, magenta, reset)

	fmt.Printf("  %s# 4. Multi-target batch reconnaissance with custom dorks%s\n", dim, reset)
	fmt.Printf("  dorkforge scan -l %stargets.txt%s -s %smedium%s --custom %s./my-rules.json%s -o %srecon.json%s -f %sjson%s\n\n",
		cyan, reset, blue, reset, green, reset, yellow, reset, magenta, reset)

	fmt.Printf("  %s# 5. Passive subdomain expansion excluding known hosts%s\n", dim, reset)
	fmt.Printf("  dorkforge subdomains -d %sexample.com%s --exclude %smail,blog,vpn,api,dev%s\n\n", cyan, reset, yellow, reset)

	fmt.Printf("  %s# 6. Rate-limited browser opening (avoids anti-bot CAPTCHAs)%s\n", dim, reset)
	fmt.Printf("  dorkforge scan -d %sexample.com%s -c %sadmin,api-endpoints%s --open --batch-size %s3%s --delay %s2500%s\n\n",
		cyan, reset, green, reset, cyan, reset, cyan, reset)

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

		fmt.Printf("%s%sEXPORT & REPORT OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s-o, --output%s %s<file>%s           Output report destination path (report.md, dashboard.html, data.json)\n", green, reset, cyan, reset)
		fmt.Printf("  %s-f, --format%s %s<fmt>%s            Export format: markdown, html, json, urls [default: markdown]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--no-color%s                      Disable colorized terminal output\n\n", green, reset)

		fmt.Printf("%s%sBROWSER OPTIONS%s\n", bold, yellow, reset)
		fmt.Printf("  %s--open%s                          Open generated search queries in default web browser\n", green, reset)
		fmt.Printf("  %s--batch-size%s %s<int>%s            Number of browser tabs to open per batch [default: 5]\n", green, reset, cyan, reset)
		fmt.Printf("  %s--delay%s %s<ms>%s                  Delay in milliseconds between browser batches [default: 2000]\n\n", green, reset, cyan, reset)
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
