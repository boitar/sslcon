package vpnc

import (
	"net"
	"net/netip"
	"strings"
)

var privateDNSNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC 6598
}

// isPrivateDNSIPv4 reports whether ipStr is a valid IPv4 address in RFC1918 or RFC6598 ranges.
func isPrivateDNSIPv4(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.Is4() {
		return false
	}
	for _, pfx := range privateDNSNetworks {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// parseSplitNetwork parses either "IP/Netmask" (e.g. "10.0.0.0/255.0.0.0") or CIDR ("10.0.0.0/8").
func parseSplitNetwork(entry string) (netip.Prefix, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return netip.Prefix{}, false
	}
	if pfx, err := netip.ParsePrefix(entry); err == nil {
		if !pfx.Addr().Is4() {
			return netip.Prefix{}, false
		}
		return pfx.Masked(), true
	}
	parts := strings.Split(entry, "/")
	if len(parts) != 2 {
		return netip.Prefix{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	maskIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if maskIP == nil {
		return netip.Prefix{}, false
	}
	ones, bits := net.IPMask(maskIP).Size()
	if bits != 32 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}

// isIPCoveredBySplitInclude reports whether ipStr falls inside any IPv4 network in splitInclude.
func isIPCoveredBySplitInclude(ipStr string, splitInclude []string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.Is4() {
		return false
	}
	for _, entry := range splitInclude {
		pfx, ok := parseSplitNetwork(entry)
		if ok && pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// privateDNSRoutesToAdd returns deduplicated private IPv4 DNS addresses that are not already covered by splitInclude.
func privateDNSRoutesToAdd(dnsList []string, splitInclude []string) []string {
	var routes []string
	seen := make(map[string]struct{})
	for _, raw := range dnsList {
		ip := strings.TrimSpace(raw)
		if !isPrivateDNSIPv4(ip) {
			continue
		}
		if isIPCoveredBySplitInclude(ip, splitInclude) {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		routes = append(routes, ip)
	}
	return routes
}

func isRouteExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") ||
		strings.HasSuffix(msg, "exists") ||
		strings.HasSuffix(msg, "exists.")
}
