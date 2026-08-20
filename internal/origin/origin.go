package origin

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/Nerd658/dorkforge/internal/engine"
)

type OriginOptions struct {
	Timeout     time.Duration
	Concurrency int
}

func DefaultOriginOptions() OriginOptions {
	return OriginOptions{
		Timeout:     15 * time.Second,
		Concurrency: 10,
	}
}

type OriginReport struct {
	Target             string            `json:"target"`
	GeneratedAt        string            `json:"generated_at"`
	DurationMs         int64             `json:"duration_ms"`
	CurrentPublicIPs   []string          `json:"current_public_ips"`
	CDNEdgeDetected    bool              `json:"cdn_edge_detected"`
	CDNProvider        string            `json:"cdn_provider,omitempty"`
	SubdomainsDiscovered []string        `json:"subdomains_discovered"`
	CandidatesTested   int               `json:"candidates_tested"`
	OriginBypassCount  int               `json:"origin_bypass_count"`
	Candidates         []CandidateResult `json:"candidates"`
}

func RunOriginDiscovery(ctx context.Context, rawTarget string, opts OriginOptions) (*OriginReport, error) {
	startTime := time.Now()
	target := engine.SanitizeTarget(rawTarget)

	report := &OriginReport{
		Target:      target,
		GeneratedAt: startTime.Format(time.RFC3339),
	}

	dnsIPs, err := net.LookupHost(target)
	if err == nil {
		report.CurrentPublicIPs = dnsIPs
		for _, ip := range dnsIPs {
			if isCDN, provider := IsCDNIP(ip); isCDN {
				report.CDNEdgeDetected = true
				report.CDNProvider = provider
				break
			}
		}
	}

	_, subdomains, _ := QueryCRTLog(ctx, target, "")
	report.SubdomainsDiscovered = subdomains

	ipToDomainMap := MineHistoricalIPs(ctx, target, subdomains)

	var candidatesToTest []struct {
		IP   string
		Host string
	}

	seenIPs := make(map[string]bool)
	for ip, hostList := range ipToDomainMap {
		if !seenIPs[ip] {
			seenIPs[ip] = true
			assocHost := target
			if len(hostList) > 0 {
				assocHost = hostList[0]
			}
			candidatesToTest = append(candidatesToTest, struct {
				IP   string
				Host string
			}{IP: ip, Host: assocHost})
		}
	}

	report.CandidatesTested = len(candidatesToTest)

	resultsChan := make(chan CandidateResult, len(candidatesToTest)*2)
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, item := range candidatesToTest {
		wg.Add(1)
		go func(ipStr, assocHost string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res443 := VerifyOriginCandidate(ctx, ipStr, 443, target, assocHost)
			resultsChan <- res443
		}(item.IP, item.Host)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		if res.IsOriginBypass {
			report.OriginBypassCount++
		}
		report.Candidates = append(report.Candidates, res)
	}

	report.DurationMs = time.Since(startTime).Milliseconds()
	return report, nil
}
