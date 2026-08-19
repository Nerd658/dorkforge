package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

var alienVaultOTXURL = "https://otx.alienvault.com/api/v1/indicators/domain"

type otxURLListResponse struct {
	URLList []struct {
		URL        string `json:"url"`
		Date       string `json:"date"`
		HTTPCode   int    `json:"httpcode"`
		Result     struct {
			URLWorker struct {
				Mime string `json:"mime"`
			} `json:"urlworker"`
		} `json:"result"`
	} `json:"url_list"`
}

// QueryAlienVaultOTX queries the AlienVault OTX URL database for historical indicators.
func QueryAlienVaultOTX(ctx context.Context, domain string) ([]ArchiveItem, error) {
	apiURL := fmt.Sprintf("%s/%s/url_list?limit=500", alienVaultOTXURL, url.PathEscape(domain))

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
		return nil, fmt.Errorf("alienvault OTX returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var otxResp otxURLListResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		return nil, err
	}

	var results []ArchiveItem
	for _, entry := range otxResp.URLList {
		results = append(results, ArchiveItem{
			URL:        entry.URL,
			Source:     "alienvault",
			MimeType:   entry.Result.URLWorker.Mime,
			StatusCode: entry.HTTPCode,
			Timestamp:  entry.Date,
		})
	}

	return results, nil
}
