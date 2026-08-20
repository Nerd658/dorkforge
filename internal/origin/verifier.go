package origin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type ConfidenceLevel string

const (
	ConfidenceLow      ConfidenceLevel = "LOW"
	ConfidenceMedium   ConfidenceLevel = "MEDIUM"
	ConfidenceHigh     ConfidenceLevel = "HIGH"
	ConfidenceVeryHigh ConfidenceLevel = "VERY_HIGH"
)

type CandidateResult struct {
	IP               string          `json:"ip"`
	Port             int             `json:"port"`
	IsCDN            bool            `json:"is_cdn"`
	CDNProvider      string          `json:"cdn_provider,omitempty"`
	TLSHandshake     bool            `json:"tls_handshake"`
	CertCN           string          `json:"cert_cn,omitempty"`
	CertSANs         []string        `json:"cert_sans,omitempty"`
	CertIssuer       string          `json:"cert_issuer,omitempty"`
	MatchedDomain    string          `json:"matched_domain,omitempty"`
	HTTPStatus       int             `json:"http_status,omitempty"`
	HTTPServerHeader string          `json:"http_server_header,omitempty"`
	HTTPTitle        string          `json:"http_title,omitempty"`
	IsOriginBypass   bool            `json:"is_origin_bypass"`
	ConfidenceScore  int             `json:"confidence_score"`
	ConfidenceLevel  ConfidenceLevel `json:"confidence_level"`
	AssociatedHost   string          `json:"associated_host,omitempty"`
}

func VerifyOriginCandidate(ctx context.Context, ipStr string, port int, targetDomain string, associatedHost string) CandidateResult {
	res := CandidateResult{
		IP:             ipStr,
		Port:           port,
		AssociatedHost: associatedHost,
	}

	isCDN, provider := IsCDNIP(ipStr)
	res.IsCDN = isCDN
	res.CDNProvider = provider

	if isCDN {
		res.ConfidenceLevel = ConfidenceLow
		res.ConfidenceScore = 10
		return res
	}

	score := 25
	res.ConfidenceLevel = ConfidenceLow

	dialer := &net.Dialer{Timeout: 4 * time.Second}
	targetAddr := fmt.Sprintf("%s:%d", ipStr, port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         targetDomain,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		res.ConfidenceScore = score
		return res
	}
	defer rawConn.Close()

	if port == 443 {
		tlsConn := tls.Client(rawConn, tlsConfig)
		_ = tlsConn.SetDeadline(time.Now().Add(4 * time.Second))
		err = tlsConn.Handshake()
		if err == nil {
			res.TLSHandshake = true
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				res.CertCN = cert.Subject.CommonName
				res.CertSANs = cert.DNSNames
				if cert.Issuer.Organization != nil && len(cert.Issuer.Organization) > 0 {
					res.CertIssuer = cert.Issuer.Organization[0]
				} else {
					res.CertIssuer = cert.Issuer.CommonName
				}

				if matchesDomain(cert.Subject.CommonName, targetDomain) || matchesAnySAN(cert.DNSNames, targetDomain) {
					res.MatchedDomain = targetDomain
					score += 35 // Now score = 60
					res.ConfidenceLevel = ConfidenceMedium
				}
			}
		}
	}

	reqURL := fmt.Sprintf("http://%s:%d/", ipStr, port)
	if port == 443 {
		reqURL = fmt.Sprintf("https://%s:%d/", ipStr, port)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err == nil {
		httpReq.Host = targetDomain
		httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DorkForge-CertIntel/1.1")

		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
		httpClient := &http.Client{
			Transport: tr,
			Timeout:   5 * time.Second,
		}

		resp, err := httpClient.Do(httpReq)
		if err == nil {
			res.HTTPStatus = resp.StatusCode
			res.HTTPServerHeader = resp.Header.Get("Server")

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			res.HTTPTitle = extractTitle(string(bodyBytes))

			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				score += 20 // Now score = 80
				res.ConfidenceLevel = ConfidenceHigh
			}

			if !res.IsCDN && (res.TLSHandshake || resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 401) && res.MatchedDomain != "" {
				score += 15 // Now score = 95
				res.IsOriginBypass = true
				res.ConfidenceLevel = ConfidenceVeryHigh
			}
		}
	}

	if score > 100 {
		score = 100
	}
	res.ConfidenceScore = score

	return res
}

func matchesDomain(name, target string) bool {
	normName := strings.ToLower(strings.TrimSpace(name))
	normTarget := strings.ToLower(strings.TrimSpace(target))
	if normName == normTarget || strings.HasSuffix(normName, "."+normTarget) {
		return true
	}
	if strings.HasPrefix(normName, "*.") {
		base := normName[2:]
		if normTarget == base || strings.HasSuffix(normTarget, "."+base) {
			return true
		}
	}
	return false
}

func matchesAnySAN(sans []string, target string) bool {
	for _, s := range sans {
		if matchesDomain(s, target) {
			return true
		}
	}
	return false
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	startIdx := strings.Index(lower, "<title>")
	if startIdx == -1 {
		return ""
	}
	startIdx += 7
	endIdx := strings.Index(lower[startIdx:], "</title>")
	if endIdx == -1 {
		return ""
	}
	return strings.TrimSpace(body[startIdx : startIdx+endIdx])
}
