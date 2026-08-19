package output

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"

	"github.com/Nerd658/dorkforge/internal/models"
)

type ExportFormat string

const (
	FormatJSON     ExportFormat = "json"
	FormatMarkdown ExportFormat = "markdown"
	FormatHTML     ExportFormat = "html"
	FormatURLs     ExportFormat = "urls"
)

func ExportJSON(summary models.ScanSummary) ([]byte, error) {
	return json.MarshalIndent(summary, "", "  ")
}

func ExportURLs(summary models.ScanSummary) []byte {
	var sb strings.Builder
	for _, res := range summary.Results {
		sb.WriteString(res.SearchURL)
		sb.WriteString("\n")
	}
	return []byte(sb.String())
}

func ExportMarkdown(summary models.ScanSummary) []byte {
	var sb strings.Builder

	sb.WriteString("# Security Dorking & Passive Reconnaissance Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Target Domain**: `%s`\n", summary.Target))
	sb.WriteString(fmt.Sprintf("- **Generated At**: `%s`\n", summary.GeneratedAt))
	sb.WriteString(fmt.Sprintf("- **Total Signatures**: `%d`\n", summary.TotalDorks))
	sb.WriteString(fmt.Sprintf("- **Severity Summary**: Critical: %d | High: %d | Medium: %d | Low: %d\n\n",
		summary.SeverityCounts[models.SeverityCritical],
		summary.SeverityCounts[models.SeverityHigh],
		summary.SeverityCounts[models.SeverityMedium],
		summary.SeverityCounts[models.SeverityLow],
	))

	sb.WriteString("## Findings Breakdown\n\n")
	sb.WriteString("| # | Severity | Category | Engine | Title | Query | Direct Search Link |\n")
	sb.WriteString("|---|---|---|---|---|---|---|\n")

	for i, res := range summary.Results {
		escapedQuery := strings.ReplaceAll(res.RenderedQuery, "|", "\\|")
		sb.WriteString(fmt.Sprintf("| %d | **%s** | `%s` | `%s` | %s | `%s` | [Launch Search](%s) |\n",
			i+1,
			strings.ToUpper(string(res.Dork.Severity)),
			res.Dork.Category,
			res.Dork.Engine,
			res.Dork.Title,
			escapedQuery,
			res.SearchURL,
		))
	}

	sb.WriteString("\n## Remediation Recommendations\n\n")
	seenRemediations := make(map[string]bool)
	for _, res := range summary.Results {
		if res.Dork.Remediation != "" && !seenRemediations[res.Dork.Remediation] {
			seenRemediations[res.Dork.Remediation] = true
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", res.Dork.Title, res.Dork.Remediation))
		}
	}

	return []byte(sb.String())
}

func ExportHTML(summary models.ScanSummary) []byte {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dorkforge Audit Report - ` + html.EscapeString(summary.Target) + `</title>
    <style>
        :root {
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #f0f6fc;
            --accent: #58a6ff;
            --crit: #f85149;
            --high: #d29922;
            --med: #58a6ff;
            --low: #8b949e;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2 { color: var(--heading); }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 25px 0; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 15px; }
        .card h3 { margin: 0 0 10px 0; font-size: 14px; color: var(--low); text-transform: uppercase; }
        .card .count { font-size: 28px; font-weight: bold; }
        .crit-text { color: var(--crit); }
        .high-text { color: var(--high); }
        .med-text { color: var(--med); }
        .low-text { color: var(--low); }
        .search-bar { width: 100%; padding: 12px; font-size: 15px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; color: #fff; margin-bottom: 20px; box-sizing: border-box; }
        table { width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: #21262d; color: var(--heading); font-size: 13px; text-transform: uppercase; }
        tr:hover { background: #1f242c; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .badge-crit { background: rgba(248,81,73,0.15); color: var(--crit); border: 1px solid var(--crit); }
        .badge-high { background: rgba(210,153,34,0.15); color: var(--high); border: 1px solid var(--high); }
        .badge-med { background: rgba(88,166,255,0.15); color: var(--med); border: 1px solid var(--med); }
        .badge-low { background: rgba(139,148,158,0.15); color: var(--low); border: 1px solid var(--low); }
        .btn { display: inline-block; padding: 6px 12px; background: #238636; color: #fff; text-decoration: none; border-radius: 6px; font-size: 13px; font-weight: 500; }
        .btn:hover { background: #2ea043; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b0e14; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
    </style>
</head>
<body>
<div class="container">
    <h1>Dorkforge Security Reconnaissance</h1>
    <p>Target: <code>` + html.EscapeString(summary.Target) + `</code> | Generated: <code>` + html.EscapeString(summary.GeneratedAt) + `</code></p>
    
    <div class="summary-cards">
        <div class="card"><h3>Total Dorks</h3><div class="count">` + fmt.Sprintf("%d", summary.TotalDorks) + `</div></div>
        <div class="card"><h3>Critical</h3><div class="count crit-text">` + fmt.Sprintf("%d", summary.SeverityCounts[models.SeverityCritical]) + `</div></div>
        <div class="card"><h3>High</h3><div class="count high-text">` + fmt.Sprintf("%d", summary.SeverityCounts[models.SeverityHigh]) + `</div></div>
        <div class="card"><h3>Medium</h3><div class="count med-text">` + fmt.Sprintf("%d", summary.SeverityCounts[models.SeverityMedium]) + `</div></div>
    </div>

    <input type="text" id="searchInput" class="search-bar" placeholder="Filter by keyword, category, or query..." onkeyup="filterTable()">

    <table id="dorksTable">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Engine</th>
                <th>Title & Description</th>
                <th>Query</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>`)

	for _, res := range summary.Results {
		badgeClass := "badge-low"
		switch res.Dork.Severity {
		case models.SeverityCritical:
			badgeClass = "badge-crit"
		case models.SeverityHigh:
			badgeClass = "badge-high"
		case models.SeverityMedium:
			badgeClass = "badge-med"
		}

		sb.WriteString(`<tr>
            <td><span class="badge ` + badgeClass + `">` + html.EscapeString(string(res.Dork.Severity)) + `</span></td>
            <td><code>` + html.EscapeString(string(res.Dork.Category)) + `</code></td>
            <td><code>` + html.EscapeString(string(res.Dork.Engine)) + `</code></td>
            <td><strong>` + html.EscapeString(res.Dork.Title) + `</strong><br><small style="color:var(--low)">` + html.EscapeString(res.Dork.Description) + `</small></td>
            <td><code>` + html.EscapeString(res.RenderedQuery) + `</code></td>
            <td><a href="` + html.EscapeString(res.SearchURL) + `" target="_blank" rel="noopener noreferrer" class="btn">Launch</a></td>
        </tr>`)
	}

	sb.WriteString(`
        </tbody>
    </table>
</div>
<script>
function filterTable() {
    var input = document.getElementById("searchInput");
    var filter = input.value.toLowerCase();
    var tr = document.getElementById("dorksTable").getElementsByTagName("tr");
    for (var i = 1; i < tr.length; i++) {
        var text = tr[i].textContent || tr[i].innerText;
        if (text.toLowerCase().indexOf(filter) > -1) {
            tr[i].style.display = "";
        } else {
            tr[i].style.display = "none";
        }
    }
}
</script>
</body>
</html>`)

	return []byte(sb.String())
}

func WriteOutput(targetFile string, format ExportFormat, summary models.ScanSummary) error {
	var content []byte
	var err error

	switch format {
	case FormatJSON:
		content, err = ExportJSON(summary)
	case FormatMarkdown:
		content = ExportMarkdown(summary)
	case FormatHTML:
		content = ExportHTML(summary)
	case FormatURLs:
		content = ExportURLs(summary)
	default:
		content = ExportMarkdown(summary)
	}

	if err != nil {
		return fmt.Errorf("failed to encode output: %w", err)
	}

	if err := os.WriteFile(targetFile, content, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
