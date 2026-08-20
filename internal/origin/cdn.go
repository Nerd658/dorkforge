package origin

import (
	"net"
	"strings"
)

var cdnSubnets = []struct {
	Name string
	CIDR string
}{
	// Cloudflare IPv4
	{"Cloudflare", "103.21.244.0/22"},
	{"Cloudflare", "103.22.200.0/22"},
	{"Cloudflare", "103.31.4.0/22"},
	{"Cloudflare", "104.16.0.0/13"},
	{"Cloudflare", "104.24.0.0/14"},
	{"Cloudflare", "104.28.0.0/14"},
	{"Cloudflare", "108.162.192.0/18"},
	{"Cloudflare", "131.0.72.0/22"},
	{"Cloudflare", "141.101.64.0/18"},
	{"Cloudflare", "162.158.0.0/15"},
	{"Cloudflare", "172.64.0.0/13"},
	{"Cloudflare", "173.245.48.0/20"},
	{"Cloudflare", "188.114.96.0/20"},
	{"Cloudflare", "190.93.240.0/20"},
	{"Cloudflare", "197.234.240.0/22"},
	{"Cloudflare", "198.41.128.0/17"},

	// Fastly
	{"Fastly", "151.101.0.0/16"},
	{"Fastly", "199.27.128.0/21"},
	{"Fastly", "140.248.0.0/16"},

	// Akamai
	{"Akamai", "23.32.0.0/11"},
	{"Akamai", "184.24.0.0/13"},
	{"Akamai", "2.16.0.0/13"},
	{"Akamai", "104.64.0.0/10"},

	// AWS CloudFront
	{"CloudFront", "13.32.0.0/15"},
	{"CloudFront", "13.35.0.0/16"},
	{"CloudFront", "13.224.0.0/14"},
	{"CloudFront", "13.249.0.0/16"},
	{"CloudFront", "52.84.0.0/15"},
	{"CloudFront", "54.192.0.0/16"},
	{"CloudFront", "54.230.0.0/16"},
	{"CloudFront", "54.239.128.0/18"},
	{"CloudFront", "54.240.128.0/18"},
	{"CloudFront", "205.251.192.0/19"},
	{"CloudFront", "204.246.164.0/22"},
}

var parsedSubnets []*net.IPNet
var subnetNames []string

func init() {
	for _, entry := range cdnSubnets {
		_, ipNet, err := net.ParseCIDR(entry.CIDR)
		if err == nil {
			parsedSubnets = append(parsedSubnets, ipNet)
			subnetNames = append(subnetNames, entry.Name)
		}
	}
}

// IsCDNIP checks whether an IP address belongs to a known CDN network range.
func IsCDNIP(ipStr string) (bool, string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false, ""
	}

	for i, sub := range parsedSubnets {
		if sub.Contains(ip) {
			return true, subnetNames[i]
		}
	}

	return false, ""
}
