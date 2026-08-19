package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var waybackCDXURL = "https://web.archive.org/cdx/search/cdx"

// QueryWaybackCDX queries the Wayback Machine CDX API.
func QueryWaybackCDX(ctx context.Context, domain string, includeSubs bool) ([]ArchiveItem, error) {
	searchTarget := domain
	if includeSubs {
		searchTarget = "*." + domain
	}

	apiURL := fmt.Sprintf("%s?url=%s/*&output=json&fl=original,mimetype,statuscode,timestamp&collapse=urlkey&limit=2000",
		waybackCDXURL, url.QueryEscape(searchTarget))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DorkForge-Archive-Fetcher/1.0 (+https://github.com/Nerd658/dorkforge)")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback CDX returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rawRows [][]string
	if err := json.Unmarshal(body, &rawRows); err != nil {
		return nil, err
	}

	if len(rawRows) <= 1 {
		return nil, nil // Header row only
	}

	var results []ArchiveItem
	// Parse header row to map column indices dynamically
	origIdx, mimeIdx, statusIdx, tsIdx := 0, 1, 2, 3
	header := rawRows[0]
	for idx, col := range header {
		switch strings.ToLower(strings.TrimSpace(col)) {
		case "original":
			origIdx = idx
		case "mimetype":
			mimeIdx = idx
		case "statuscode":
			statusIdx = idx
		case "timestamp":
			tsIdx = idx
		}
	}

	maxIdx := origIdx
	if mimeIdx > maxIdx {
		maxIdx = mimeIdx
	}
	if statusIdx > maxIdx {
		maxIdx = statusIdx
	}
	if tsIdx > maxIdx {
		maxIdx = tsIdx
	}

	for i := 1; i < len(rawRows); i++ {
		row := rawRows[i]
		if len(row) <= maxIdx {
			continue
		}

		rawURL := row[origIdx]
		mime := row[mimeIdx]
		statusStr := row[statusIdx]
		ts := row[tsIdx]

		status, _ := strconv.Atoi(statusStr)

		results = append(results, ArchiveItem{
			URL:        rawURL,
			Source:     "wayback",
			MimeType:   mime,
			StatusCode: status,
			Timestamp:  ts,
		})
	}

	return results, nil
}
