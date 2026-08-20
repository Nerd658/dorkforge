package origin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type AlienVaultOTXResponse struct {
	URLList []struct {
		URL string `json:"url"`
		IP  string `json:"ip,omitempty"`
	} `json:"url_list"`
}

func MineHistoricalIPs(ctx context.Context, targetDomain string, subdomains []string) map[string][]string {
	ipToDomainMap := make(map[string][]string)

	domainSet := make(map[string]bool)
	domainSet[targetDomain] = true
	for _, sub := range subdomains {
		domainSet[sub] = true
	}

	client := &http.Client{Timeout: 8 * time.Second}

	for dom := range domainSet {
		addrs, err := net.LookupHost(dom)
		if err == nil {
			for _, ip := range addrs {
				ipToDomainMap[ip] = appendIfMissing(ipToDomainMap[ip], dom)
			}
		}

		otxURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=100", dom)
		req, err := http.NewRequestWithContext(ctx, "GET", otxURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "DorkForge-CertIntel/1.1")
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				var otxRes AlienVaultOTXResponse
				if json.NewDecoder(resp.Body).Decode(&otxRes) == nil {
					for _, item := range otxRes.URLList {
						if item.IP != "" && net.ParseIP(item.IP) != nil {
							ipToDomainMap[item.IP] = appendIfMissing(ipToDomainMap[item.IP], dom)
						}
					}
				}
				resp.Body.Close()
			}
		}
	}

	return ipToDomainMap
}

func appendIfMissing(slice []string, item string) []string {
	for _, ele := range slice {
		if ele == item {
			return slice
		}
	}
	return append(slice, item)
}
