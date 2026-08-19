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
 Advanced Search Dorking & Passive Reconnaissance Engine
`
)

func printUsage() {
	fmt.Print(AppBanner)
	fmt.Printf("Version: %s | Repository: github.com/Nerd658/dorkforge\n\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  dorkforge <command> [arguments]")
	fmt.Println("\nAvailable Commands:")
	fmt.Println("  scan         Execute a dorking reconnaissance audit against a target domain")
	fmt.Println("  subdomains   Generate negative exclusion dorks for subdomain discovery")
	fmt.Println("  list         Display the complete catalog of built-in search signatures")
	fmt.Println("  categories   List all 12 supported dorking categories and descriptions")
	fmt.Println("  completion   Generate shell autocompletion scripts (bash, zsh, fish)")
	fmt.Println("  version      Show the current version and build information")
	fmt.Println("\nRun 'dorkforge <command> -h' for command-specific flags and examples.")
	fmt.Println()
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
	fmt.Printf("\n================================================================================\n")
	fmt.Println(" DORKFORGE SUPPORTED CATEGORIES (12 CATEGORIES)")
	fmt.Printf("================================================================================\n\n")

	categoriesInfo := []struct {
		Name        string
		Severity    string
		Description string
	}{
		{"configs", "CRITICAL", "Exposed .env files, server configurations (nginx, apache), docker-compose"},
		{"secrets", "CRITICAL", "AWS access keys, SSH/RSA private keys, GitHub tokens, database passwords"},
		{"admin", "HIGH", "Administrative login portals, phpMyAdmin, Jenkins, Grafana, Kibana"},
		{"backups", "HIGH", "Database dumps (.sql, .dump), compressed source archives (.tar.gz, .zip)"},
		{"cloud", "HIGH/MED", "Public Amazon S3 buckets, Azure Blob containers, Google Cloud Storage"},
		{"source-code", "HIGH", "Exposed .git folders, code leaks on GitHub / GitLab"},
		{"errors", "MEDIUM", "PHP info diagnostics, framework stack traces, application error logs"},
		{"docs", "MED/LOW", "Confidential PDF documents, payroll spreadsheets, internal organigrams"},
		{"api-endpoints", "HIGH", "Exposed Swagger/OpenAPI specs, GraphQL consoles, Postman collections"},
		{"subdomains", "LOW", "Search engine exclusion chains and Shodan SSL certificate recon"},
		{"network-iot", "HIGH", "Router/firewall interfaces (pfSense, FortiGate), web terminals"},
		{"employees-osint", "LOW", "LinkedIn profiles, employee directories, email footprinting"},
	}

	for _, c := range categoriesInfo {
		fmt.Printf("- %-18s [%-8s] : %s\n", c.Name, c.Severity, c.Description)
	}
	fmt.Println()
}

func handleCompletion(args []string) {
	if len(args) < 1 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Printf("\n================================================================================\n")
		fmt.Println(" DORKFORGE SHELL AUTOCOMPLETION GENERATOR")
		fmt.Printf("================================================================================\n\n")
		fmt.Println("Generate autocompletion scripts for Bash, Zsh, or Fish.")
		fmt.Println("\nUsage:")
		fmt.Println("  dorkforge completion <shell>")
		fmt.Println("\nSupported Shells:")
		fmt.Println("  bash         Generate autocompletion script for Bash")
		fmt.Println("  zsh          Generate autocompletion script for Zsh")
		fmt.Println("  fish         Generate autocompletion script for Fish")
		fmt.Println("\nInstallation Examples:")
		fmt.Println("  # Bash:")
		fmt.Println("  dorkforge completion bash > /etc/bash_completion.d/dorkforge")
		fmt.Println("  # or in ~/.bashrc:")
		fmt.Println("  source <(dorkforge completion bash)")
		fmt.Println("\n  # Zsh:")
		fmt.Println("  dorkforge completion zsh > \"${fpath[1]}/_dorkforge\"")
		fmt.Println("\n  # Fish:")
		fmt.Println("  dorkforge completion fish > ~/.config/fish/completions/dorkforge.fish")
		fmt.Println()
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
