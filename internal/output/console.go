package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Nerd658/dorkforge/internal/models"
)

const (
	colorReset    = "\033[0m"
	colorBold     = "\033[1m"
	colorDim      = "\033[2m"
	colorRed      = "\033[1;31m"
	colorYellow   = "\033[1;33m"
	colorBlue     = "\033[1;34m"
	colorMagenta  = "\033[1;35m"
	colorCyan     = "\033[1;36m"
	colorGray     = "\033[0;90m"
	colorGreen    = "\033[1;32m"
)

func severityColor(sev models.Severity, noColor bool) (string, string) {
	if noColor {
		return "", ""
	}
	switch sev {
	case models.SeverityCritical:
		return colorRed, colorReset
	case models.SeverityHigh:
		return colorYellow, colorReset
	case models.SeverityMedium:
		return colorBlue, colorReset
	case models.SeverityLow:
		return colorCyan, colorReset
	default:
		return colorGray, colorReset
	}
}

func PrintScanResults(w io.Writer, summary models.ScanSummary, noColor bool) {
	b, r := "", ""
	dim, cyan, green := "", "", ""
	if !noColor {
		b = colorBold
		r = colorReset
		dim = colorDim
		cyan = colorCyan
		green = colorGreen
	}

	fmt.Fprintf(w, "\n%s================================================================================%s\n", dim, r)
	fmt.Fprintf(w, "%s DORKFORGE RECONNAISSANCE AUDIT%s\n", b, r)
	fmt.Fprintf(w, "%s Target       : %s%s%s\n", dim, cyan, summary.Target, r)
	fmt.Fprintf(w, "%s Generated At : %s%s\n", dim, summary.GeneratedAt, r)
	fmt.Fprintf(w, "%s Total Dorks  : %s%d%s\n", dim, green, summary.TotalDorks, r)
	fmt.Fprintf(w, "%s Severity     : [CRIT: %d] [HIGH: %d] [MED: %d] [LOW: %d]%s\n",
		dim,
		summary.SeverityCounts[models.SeverityCritical],
		summary.SeverityCounts[models.SeverityHigh],
		summary.SeverityCounts[models.SeverityMedium],
		summary.SeverityCounts[models.SeverityLow],
		r,
	)
	fmt.Fprintf(w, "%s================================================================================%s\n\n", dim, r)

	if len(summary.Results) == 0 {
		fmt.Fprintf(w, "No dorks matched the provided filters.\n\n")
		return
	}

	for i, res := range summary.Results {
		sColor, sReset := severityColor(res.Dork.Severity, noColor)
		sevTag := fmt.Sprintf("[%s]", strings.ToUpper(string(res.Dork.Severity)))

		fmt.Fprintf(w, "%s%02d. %s%-10s%s %s%s%s (%s / %s)\n",
			dim, i+1, sColor, sevTag, sReset, b, res.Dork.Title, r, res.Dork.Category, res.Dork.Engine)
		fmt.Fprintf(w, "    %sDescription :%s %s\n", dim, r, res.Dork.Description)
		fmt.Fprintf(w, "    %sQuery       :%s %s\n", dim, r, res.RenderedQuery)
		fmt.Fprintf(w, "    %sSearch URL  :%s %s\n", dim, r, res.SearchURL)
		if res.Dork.Remediation != "" {
			fmt.Fprintf(w, "    %sRemediation :%s %s\n", dim, r, res.Dork.Remediation)
		}
		fmt.Fprintln(w)
	}
}

func PrintCatalog(w io.Writer, catalog []models.Dork, noColor bool) {
	b, r, dim := "", "", ""
	if !noColor {
		b = colorBold
		r = colorReset
		dim = colorDim
	}

	fmt.Fprintf(w, "\n%s================================================================================%s\n", dim, r)
	fmt.Fprintf(w, "%s DORKFORGE BUILT-IN DORK CATALOG (%d Signatures)%s\n", b, len(catalog), r)
	fmt.Fprintf(w, "%s================================================================================%s\n\n", dim, r)

	fmt.Fprintf(w, "%-10s %-16s %-10s %-10s %s\n", "ID", "CATEGORY", "SEVERITY", "ENGINE", "TITLE")
	fmt.Fprintf(w, "%-10s %-16s %-10s %-10s %s\n", "----------", "----------------", "----------", "----------", "------------------------------")

	for _, d := range catalog {
		sColor, sReset := severityColor(d.Severity, noColor)
		fmt.Fprintf(w, "%-10s %-16s %s%-10s%s %-10s %s\n",
			d.ID,
			d.Category,
			sColor, strings.ToUpper(string(d.Severity)), sReset,
			d.Engine,
			d.Title,
		)
	}
	fmt.Fprintln(w)
}

func ShouldDisableColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return true
	}
	return false
}
