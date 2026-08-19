package models

import (
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

func (s Severity) Rank() int {
	switch strings.ToLower(string(s)) {
	case string(SeverityCritical):
		return 4
	case string(SeverityHigh):
		return 3
	case string(SeverityMedium):
		return 2
	case string(SeverityLow):
		return 1
	default:
		return 0
	}
}

func ParseSeverity(val string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "critical", "crit":
		return SeverityCritical, nil
	case "high", "hi":
		return SeverityHigh, nil
	case "medium", "med":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	default:
		return "", fmt.Errorf("invalid severity level: %s (expected: critical, high, medium, low)", val)
	}
}

type Category string

const (
	CategoryConfigs        Category = "configs"
	CategorySecrets        Category = "secrets"
	CategoryAdmin          Category = "admin"
	CategoryBackups        Category = "backups"
	CategoryCloud          Category = "cloud"
	CategorySourceCode     Category = "source-code"
	CategoryErrors         Category = "errors"
	CategoryDocs           Category = "docs"
	CategoryAPIEndpoints   Category = "api-endpoints"
	CategorySubdomains     Category = "subdomains"
	CategoryNetworkIoT     Category = "network-iot"
	CategoryEmployeesOSINT Category = "employees-osint"
)

var AllCategories = []Category{
	CategoryConfigs,
	CategorySecrets,
	CategoryAdmin,
	CategoryBackups,
	CategoryCloud,
	CategorySourceCode,
	CategoryErrors,
	CategoryDocs,
	CategoryAPIEndpoints,
	CategorySubdomains,
	CategoryNetworkIoT,
	CategoryEmployeesOSINT,
}

func IsValidCategory(cat string) bool {
	norm := strings.ToLower(strings.TrimSpace(cat))
	for _, c := range AllCategories {
		if string(c) == norm {
			return true
		}
	}
	return false
}

type Engine string

const (
	EngineGoogle     Engine = "google"
	EngineGitHub     Engine = "github"
	EngineDuckDuckGo Engine = "duckduckgo"
	EngineBing       Engine = "bing"
	EngineShodan     Engine = "shodan"
)

var AllEngines = []Engine{
	EngineGoogle,
	EngineGitHub,
	EngineDuckDuckGo,
	EngineBing,
	EngineShodan,
}

func IsValidEngine(eng string) bool {
	norm := strings.ToLower(strings.TrimSpace(eng))
	for _, e := range AllEngines {
		if string(e) == norm {
			return true
		}
	}
	return false
}

type Dork struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Category      Category `json:"category"`
	Severity      Severity `json:"severity"`
	Engine        Engine   `json:"engine"`
	QueryTemplate string   `json:"query_template"`
	Tags          []string `json:"tags,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
}

type ResolvedDork struct {
	Dork          Dork   `json:"dork"`
	Target        string `json:"target"`
	RenderedQuery string `json:"rendered_query"`
	SearchURL     string `json:"search_url"`
}

type ScanSummary struct {
	Target         string           `json:"target"`
	GeneratedAt    string           `json:"generated_at"`
	TotalDorks     int              `json:"total_dorks"`
	SeverityCounts map[Severity]int `json:"severity_counts"`
	CategoryCounts map[Category]int `json:"category_counts"`
	EngineCounts   map[Engine]int   `json:"engine_counts"`
	Results        []ResolvedDork   `json:"results"`
}
