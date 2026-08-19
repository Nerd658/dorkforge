package subdomains

import (
	"strings"
	"testing"
)

func TestGenerateSubdomainQueries(t *testing.T) {
	target := "https://corp-example.com/api"
	known := []string{"vpn", "mail", "api"}

	dorkSet := GenerateSubdomainQueries(target, known)
	if dorkSet.Target != "corp-example.com" {
		t.Errorf("expected target 'corp-example.com', got %q", dorkSet.Target)
	}

	if len(dorkSet.Queries) < 4 {
		t.Errorf("expected at least 4 queries, got %d", len(dorkSet.Queries))
	}

	googleQuery := dorkSet.Queries[0].RenderedQuery
	if !strings.Contains(googleQuery, "site:*.corp-example.com") ||
		!strings.Contains(googleQuery, "-site:vpn.corp-example.com") ||
		!strings.Contains(googleQuery, "-site:mail.corp-example.com") {
		t.Errorf("unexpected Google exclusion query: %s", googleQuery)
	}
}
