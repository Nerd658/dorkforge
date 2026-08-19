package recon

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"

	"github.com/Nerd658/dorkforge/internal/models"
)

// ExportReconJSON generates a structured JSON report.
func ExportReconJSON(result *ReconResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// WriteReconReport writes the report to disk in the specified format.
func WriteReconReport(path string, format string, result *ReconResult) error {
	var data []byte
	var err error

	switch strings.ToLower(format) {
	case "html":
		data = ExportReconHTML(result)
	case "md", "markdown":
		data = ExportReconMarkdown(result)
	case "json":
		data, err = ExportReconJSON(result)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return os.WriteFile(path, data, 0644)
}

// ExportReconMarkdown generates a unified Markdown audit report.
func ExportReconMarkdown(result *ReconResult) []byte {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Recon Report: %s\n\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Risk Score:** %d | **Exposed Endpoints:** %d\n", result.RiskScore, result.ExposedCount))
	sb.WriteString(fmt.Sprintf("**Started At:** %s | **Completed At:** %s | **Duration:** %d ms\n\n", result.StartedAt, result.CompletedAt, result.DurationMs))

	if result.Scan != nil {
		sb.WriteString("## Dork Signatures\n\n")
		sb.WriteString("| Severity | Category | Engine | Title | Query |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, r := range result.Scan.Results {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | `%s` |\n",
				r.Dork.Severity, r.Dork.Category, r.Dork.Engine, r.Dork.Title, r.RenderedQuery))
		}
		sb.WriteString("\n")
	}

	if len(result.LiveResults) > 0 {
		sb.WriteString("## Live Findings\n\n")
		for _, lr := range result.LiveResults {
			sb.WriteString(fmt.Sprintf("### %s\n", lr.DorkTitle))
			sb.WriteString(fmt.Sprintf("**Query:** `%s`\n\n", lr.RenderedQuery))
			for _, item := range lr.Items {
				sb.WriteString(fmt.Sprintf("- **[%s](%s)**\n", item.Title, item.TargetURL))
				if item.Snippet != "" {
					sb.WriteString(fmt.Sprintf("  > %s\n", strings.ReplaceAll(item.Snippet, "\n", " ")))
				}
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("## Live Findings\n\nNo live findings.\n\n")
	}

	if len(result.ProbeResults) > 0 {
		sb.WriteString("## Probe Results\n\n")
		sb.WriteString("| URL | Status | Content Type | Title | Dork |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, pr := range result.ProbeResults {
			sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s |\n",
				pr.URL, pr.StatusCode, pr.ContentType, pr.HTMLTitle, pr.DorkTitle))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("## Probe Results\n\nNo probe results.\n\n")
	}

	return []byte(sb.String())
}

func getSeverityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "#f85149"
	case models.SeverityHigh:
		return "#ff7b72"
	case models.SeverityMedium:
		return "#d2a8ff"
	case models.SeverityLow:
		return "#7ee787"
	default:
		return "#8b949e"
	}
}

// ExportReconHTML generates a unified interactive HTML dashboard with 4 tabs.
func ExportReconHTML(result *ReconResult) []byte {
	var sb strings.Builder

	critical := 0
	high := 0
	medium := 0
	low := 0
	if result.Scan != nil {
		critical = result.Scan.SeverityCounts[models.SeverityCritical]
		high = result.Scan.SeverityCounts[models.SeverityHigh]
		medium = result.Scan.SeverityCounts[models.SeverityMedium]
		low = result.Scan.SeverityCounts[models.SeverityLow]
	}

	archiveUrls := 0
	sensitiveArchives := 0
	if result.Archive != nil {
		archiveUrls = result.Archive.TotalURLs
		sensitiveArchives = result.Archive.SensitiveURLs
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report - ` + html.EscapeString(result.Target) + `</title>
<style>
	:root {
		--bg-color: #0d1117;
		--card-bg: #161b22;
		--border-color: #30363d;
		--text-color: #c9d1d9;
		--muted-text: #8b949e;
		--accent-color: #58a6ff;
		--critical: #f85149;
		--high: #ff7b72;
		--medium: #d2a8ff;
		--low: #7ee787;
		--success: #2ea043;
		--warning: #d29922;
	}
	body {
		font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
		background-color: var(--bg-color);
		color: var(--text-color);
		margin: 0;
		padding: 20px;
		line-height: 1.5;
	}
	.header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 20px;
		border-bottom: 1px solid var(--border-color);
		padding-bottom: 10px;
	}
	.header h1 {
		margin: 0;
		font-size: 24px;
	}
	.header-meta {
		color: var(--muted-text);
		font-size: 14px;
	}
	.tabs {
		display: flex;
		border-bottom: 1px solid var(--border-color);
		margin-bottom: 20px;
	}
	.tab {
		padding: 10px 20px;
		cursor: pointer;
		border-bottom: 2px solid transparent;
		color: var(--muted-text);
	}
	.tab:hover {
		color: var(--text-color);
	}
	.tab.active {
		color: var(--text-color);
		border-bottom: 2px solid var(--accent-color);
		font-weight: 600;
	}
	.tab-content {
		display: none;
	}
	.tab-content.active {
		display: block;
	}
	.card-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 15px;
		margin-bottom: 20px;
	}
	.card {
		background-color: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 6px;
		padding: 15px;
		text-align: center;
	}
	.card h3 {
		margin: 0 0 10px 0;
		font-size: 14px;
		color: var(--muted-text);
	}
	.card .value {
		font-size: 24px;
		font-weight: 600;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		background-color: var(--card-bg);
		border-radius: 6px;
		overflow: hidden;
		border: 1px solid var(--border-color);
	}
	th, td {
		padding: 10px 15px;
		text-align: left;
		border-bottom: 1px solid var(--border-color);
	}
	th {
		background-color: var(--card-bg);
		font-weight: 600;
		color: var(--muted-text);
	}
	tr:last-child td {
		border-bottom: none;
	}
	.badge {
		padding: 2px 8px;
		border-radius: 12px;
		font-size: 12px;
		font-weight: 600;
		display: inline-block;
	}
	.badge-outline {
		border: 1px solid var(--border-color);
		color: var(--muted-text);
	}
	.code-block {
		background-color: #0d1117;
		padding: 2px 6px;
		border-radius: 4px;
		font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
		font-size: 12px;
		border: 1px solid var(--border-color);
	}
	a {
		color: var(--accent-color);
		text-decoration: none;
	}
	a:hover {
		text-decoration: underline;
	}
	.filter-input {
		width: 100%;
		padding: 8px 12px;
		margin-bottom: 15px;
		background-color: #0d1117;
		border: 1px solid var(--border-color);
		border-radius: 4px;
		color: var(--text-color);
		box-sizing: border-box;
	}
	.filter-input:focus {
		outline: none;
		border-color: var(--accent-color);
	}
	.btn {
		background-color: #21262d;
		color: #c9d1d9;
		border: 1px solid rgba(240, 246, 252, 0.1);
		padding: 4px 10px;
		border-radius: 6px;
		font-size: 12px;
		cursor: pointer;
		text-decoration: none;
		display: inline-block;
	}
	.btn:hover {
		background-color: #30363d;
		border-color: #8b949e;
		text-decoration: none;
	}
	.gauge {
		width: 100px;
		height: 100px;
		margin: 0 auto 10px;
	}
	.live-finding {
		margin-bottom: 20px;
		background-color: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 6px;
		padding: 15px;
	}
	.live-finding h4 {
		margin-top: 0;
		margin-bottom: 10px;
	}
	.live-finding-items {
		margin: 0;
		padding-left: 20px;
	}
	.live-finding-items li {
		margin-bottom: 10px;
	}
	.snippet {
		color: var(--muted-text);
		font-size: 13px;
		margin-top: 4px;
	}
	.status-200 { color: var(--success); }
	.status-403, .status-401 { color: var(--warning); }
	.status-error { color: var(--muted-text); }
</style>
</head>
<body>

<div class="header">
	<div>
		<h1>Recon Report: ` + html.EscapeString(result.Target) + `</h1>
	</div>
	<div class="header-meta">
		<div>Started: ` + html.EscapeString(result.StartedAt) + `</div>
		<div>Duration: ` + fmt.Sprintf("%d", result.DurationMs) + `ms</div>
	</div>
</div>

<div class="tabs">
	<div class="tab active" onclick="switchTab(event, 'overview')">Overview</div>
	<div class="tab" onclick="switchTab(event, 'dorks')">Dork Signatures</div>
	<div class="tab" onclick="switchTab(event, 'live')">Live Findings</div>
	<div class="tab" onclick="switchTab(event, 'probes')">Probe Results</div>` + func() string {
		if len(result.ShodanMatches) > 0 || len(result.GitHubItems) > 0 {
			return `<div class="tab" onclick="switchTab(event, 'api-results')">API Intelligence</div>`
		}
		return ""
	}() + `
</div>

<div id="overview" class="tab-content active">
	<div class="card-grid">
		<div class="card" style="grid-column: span 2; display: flex; flex-direction: column; align-items: center; justify-content: center;">
			<h3>Risk Score</h3>
			<svg class="gauge" viewBox="0 0 36 36">
				<path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--border-color)" stroke-width="3" />
				<path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--critical)" stroke-width="3" stroke-dasharray="` + fmt.Sprintf("%d", result.RiskScore) + `, 100" />
				<text x="18" y="20.35" font-size="8" fill="var(--text-color)" text-anchor="middle">` + fmt.Sprintf("%d", result.RiskScore) + `</text>
			</svg>
		</div>
		<div class="card">
			<h3>Critical / High</h3>
			<div class="value"><span style="color:var(--critical)">` + fmt.Sprintf("%d", critical) + `</span> / <span style="color:var(--high)">` + fmt.Sprintf("%d", high) + `</span></div>
		</div>
		<div class="card">
			<h3>Medium / Low</h3>
			<div class="value"><span style="color:var(--medium)">` + fmt.Sprintf("%d", medium) + `</span> / <span style="color:var(--low)">` + fmt.Sprintf("%d", low) + `</span></div>
		</div>
		<div class="card">
			<h3>Exposed Endpoints</h3>
			<div class="value" style="color:var(--warning)">` + fmt.Sprintf("%d", result.ExposedCount) + `</div>
		</div>
		<div class="card">
			<h3>Archive URLs</h3>
			<div class="value">` + fmt.Sprintf("%d", archiveUrls) + `</div>
		</div>
		<div class="card">
			<h3>Sensitive Archives</h3>
			<div class="value" style="color:var(--critical)">` + fmt.Sprintf("%d", sensitiveArchives) + `</div>
		</div>
	</div>
</div>

<div id="dorks" class="tab-content">
	<div style="display:flex; gap:10px; margin-bottom: 15px;">
		<input type="text" class="filter-input" id="dorks-filter" style="margin-bottom:0;" placeholder="Filter signatures..." onkeyup="filterTable('dorks-table', 'dorks-filter')">
		<button onclick="launchAllDorks()" class="btn" style="background:#1f6beb; padding:0 20px; white-space:nowrap; cursor:pointer;">🚀 Launch All Dorks</button>
	</div>
	<table id="dorks-table">
		<thead>
			<tr>
				<th>Severity</th>
				<th>Category</th>
				<th>Engine</th>
				<th>Title</th>
				<th>Query</th>
				<th>Action</th>
			</tr>
		</thead>
		<tbody>`)

	if result.Scan != nil {
		for _, r := range result.Scan.Results {
			color := getSeverityColor(r.Dork.Severity)
			sb.WriteString(fmt.Sprintf(`
			<tr>
				<td><span class="badge" style="color: %s; border: 1px solid %s">%s</span></td>
				<td><span class="badge badge-outline">%s</span></td>
				<td>%s</td>
				<td>%s</td>
				<td><span class="code-block">%s</span></td>
				<td><a href="%s" target="_blank" class="btn">Launch</a></td>
			</tr>`, color, color, html.EscapeString(string(r.Dork.Severity)), html.EscapeString(string(r.Dork.Category)), html.EscapeString(string(r.Dork.Engine)), html.EscapeString(r.Dork.Title), html.EscapeString(r.RenderedQuery), html.EscapeString(r.SearchURL)))
		}
	} else {
		sb.WriteString(`<tr><td colspan="6" style="text-align: center; color: var(--muted-text);">No dorks found.</td></tr>`)
	}

	sb.WriteString(`
		</tbody>
	</table>
</div>

<div id="live" class="tab-content">
	<input type="text" class="filter-input" id="live-filter" placeholder="Filter findings..." onkeyup="filterDivs('live-findings-container', 'live-filter')">
	<div id="live-findings-container">`)

	if len(result.LiveResults) > 0 {
		for _, lr := range result.LiveResults {
			sb.WriteString(fmt.Sprintf(`
		<div class="live-finding filterable-item">
			<h4>%s</h4>
			<div style="margin-bottom: 10px;"><span class="code-block">%s</span></div>
			<ul class="live-finding-items">`, html.EscapeString(lr.DorkTitle), html.EscapeString(lr.RenderedQuery)))
			for _, item := range lr.Items {
				sb.WriteString(fmt.Sprintf(`
				<li>
					<a href="%s" target="_blank"><strong>%s</strong></a>
					<div class="snippet">%s</div>
				</li>`, html.EscapeString(item.TargetURL), html.EscapeString(item.Title), html.EscapeString(item.Snippet)))
			}
			sb.WriteString(`
			</ul>
		</div>`)
		}
	} else {
		sb.WriteString(`<div style="padding: 20px; text-align: center; color: var(--muted-text); background-color: var(--card-bg); border-radius: 6px; border: 1px solid var(--border-color);">No live findings.</div>`)
	}

	sb.WriteString(`
	</div>
</div>

<div id="probes" class="tab-content">
	<input type="text" class="filter-input" id="probes-filter" placeholder="Filter probe results..." onkeyup="filterTable('probes-table', 'probes-filter')">
	<table id="probes-table">
		<thead>
			<tr>
				<th>URL</th>
				<th>Status</th>
				<th>Content Type</th>
				<th>Title</th>
				<th>Exposed</th>
				<th>Dork</th>
			</tr>
		</thead>
		<tbody>`)

	if len(result.ProbeResults) > 0 {
		for _, pr := range result.ProbeResults {
			statusClass := "status-error"
			if pr.StatusCode == 200 {
				statusClass = "status-200"
			} else if pr.StatusCode == 403 || pr.StatusCode == 401 {
				statusClass = "status-403"
			}
			exposedBadge := ""
			if pr.IsExposed {
				exposedBadge = `<span class="badge" style="color: var(--critical); border: 1px solid var(--critical);">Exposed</span>`
			}
			sb.WriteString(fmt.Sprintf(`
			<tr>
				<td><a href="%s" target="_blank">%s</a></td>
				<td class="%s">%d %s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
			</tr>`, html.EscapeString(pr.URL), html.EscapeString(pr.URL), statusClass, pr.StatusCode, html.EscapeString(pr.StatusText), html.EscapeString(pr.ContentType), html.EscapeString(pr.HTMLTitle), exposedBadge, html.EscapeString(pr.DorkTitle)))
		}
	} else {
		sb.WriteString(`<tr><td colspan="6" style="text-align: center; color: var(--muted-text);">No probe results.</td></tr>`)
	}

	sb.WriteString(`
		</tbody>
	</table>
</div>`)

	if len(result.ShodanMatches) > 0 || len(result.GitHubItems) > 0 {
		sb.WriteString(`
<div id="api-results" class="tab-content">`)
		if len(result.ShodanMatches) > 0 {
			sb.WriteString(fmt.Sprintf(`<h3>Shodan Direct Host Matches (%d)</h3>`, len(result.ShodanMatches)))
			sb.WriteString(`<table><thead><tr><th>IP Address</th><th>Port</th><th>Hostnames</th><th>Organization</th><th>Country</th></tr></thead><tbody>`)
			for _, m := range result.ShodanMatches {
				hosts := strings.Join(m.Hostnames, ", ")
				if hosts == "" {
					hosts = "-"
				}
				sb.WriteString(fmt.Sprintf(`<tr><td><code>%s</code></td><td><code>%d</code></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(m.IPStr), m.Port, html.EscapeString(hosts), html.EscapeString(m.Org), html.EscapeString(m.Location.CountryCode)))
			}
			sb.WriteString(`</tbody></table><br>`)
		}
		if len(result.GitHubItems) > 0 {
			sb.WriteString(fmt.Sprintf(`<h3>GitHub Code Leaks (%d)</h3>`, len(result.GitHubItems)))
			sb.WriteString(`<table><thead><tr><th>File Path</th><th>Repository</th><th>Action</th></tr></thead><tbody>`)
			for _, g := range result.GitHubItems {
				sb.WriteString(fmt.Sprintf(`<tr><td><code>%s</code></td><td>%s</td><td><a href="%s" target="_blank" class="btn">View Code</a></td></tr>`,
					html.EscapeString(g.Path), html.EscapeString(g.Repository.FullName), html.EscapeString(g.HTMLURL)))
			}
			sb.WriteString(`</tbody></table>`)
		}
		sb.WriteString(`</div>`)
	}

	sb.WriteString(`
<script>
function switchTab(evt, tabId) {
	document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
	document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
	document.getElementById(tabId).classList.add('active');
	if (evt && evt.currentTarget) {
		evt.currentTarget.classList.add('active');
	}
}

function filterTable(tableId, inputId) {
	const input = document.getElementById(inputId);
	const filter = input.value.toLowerCase();
	const table = document.getElementById(tableId);
	const tr = table.getElementsByTagName("tr");
	for (let i = 1; i < tr.length; i++) {
		tr[i].style.display = "none";
		const td = tr[i].getElementsByTagName("td");
		for (let j = 0; j < td.length; j++) {
			if (td[j]) {
				if (td[j].textContent.toLowerCase().indexOf(filter) > -1) {
					tr[i].style.display = "";
					break;
				}
			}
		}
	}
}

function filterDivs(containerId, inputId) {
	const input = document.getElementById(inputId);
	const filter = input.value.toLowerCase();
	const container = document.getElementById(containerId);
	const items = container.getElementsByClassName("filterable-item");
	for (let i = 0; i < items.length; i++) {
		if (items[i].textContent.toLowerCase().indexOf(filter) > -1) {
			items[i].style.display = "";
		} else {
			items[i].style.display = "none";
		}
	}
}

function launchAllDorks() {
	const table = document.getElementById("dorks-table");
	const tr = table.getElementsByTagName("tr");
	const links = [];
	for (let i = 1; i < tr.length; i++) {
		if (tr[i].style.display !== "none") {
			const a = tr[i].querySelector("a.btn");
			if (a && a.href) {
				links.push(a.href);
			}
		}
	}
	if (links.length === 0) return;
	if (confirm("Open " + links.length + " search queries in browser tabs?")) {
		links.forEach((url, idx) => {
			setTimeout(() => {
				window.open(url, "_blank");
			}, idx * 300);
		});
	}
}
</script>
</body>
</html>`)

	return []byte(sb.String())
}
