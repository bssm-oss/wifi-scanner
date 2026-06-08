package target

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type Options struct {
	AllowPublic bool
	MaxHosts    int
}

func Expand(spec string, opts Options) ([]net.IP, error) {
	var targets []net.IP
	var err error
	if strings.TrimSpace(spec) == "" {
		spec, err = AutoPrivateSpec()
		if err != nil {
			return nil, err
		}
	}

	seen := make(map[string]struct{})
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		ips, err := expandToken(token, opts)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			if !isAllowed(ip, opts.AllowPublic) {
				return nil, fmt.Errorf("target %s is not private, loopback, or link-local; use --allow-public only for authorized scans", ip)
			}
			seen[key] = struct{}{}
			targets = append(targets, append(net.IP(nil), ip...))
			if opts.MaxHosts > 0 && len(targets) > opts.MaxHosts {
				return nil, fmt.Errorf("expanded target set exceeds --max-hosts=%d", opts.MaxHosts)
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		return ipToUint32(targets[i]) < ipToUint32(targets[j])
	})
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets resolved")
	}
	return targets, nil
}

func AutoPrivateSpec() (string, error) {
	var specs []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ipnet, ok := parseAddr(addr)
			if !ok || ip.To4() == nil || !isAllowed(ip, false) {
				continue
			}
			ipnet.IP = ip.Mask(ipnet.Mask)
			specs = append(specs, ipnet.String())
		}
	}
	if len(specs) == 0 {
		return "", fmt.Errorf("no active private IPv4 interface found; pass --targets explicitly")
	}
	sort.Strings(specs)
	return strings.Join(specs, ","), nil
}

func expandToken(token string, opts Options) ([]net.IP, error) {
	if strings.Contains(token, "/") {
		return expandCIDR(token, opts.MaxHosts)
	}
	if strings.Contains(token, "-") {
		return expandRange(token)
	}
	ip := parseIPv4(token)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 target %q", token)
	}
	return []net.IP{ip}, nil
}

func expandCIDR(token string, maxHosts int) ([]net.IP, error) {
	base, ipnet, err := net.ParseCIDR(token)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", token, err)
	}
	if base.To4() == nil {
		return nil, fmt.Errorf("only IPv4 targets are supported: %q", token)
	}
	start := base.Mask(ipnet.Mask).To4()
	var out []net.IP
	for ip := append(net.IP(nil), start...); ipnet.Contains(ip); inc(ip) {
		out = append(out, append(net.IP(nil), ip...))
		if maxHosts > 0 && len(out) > maxHosts {
			return nil, fmt.Errorf("CIDR %s exceeds --max-hosts=%d", token, maxHosts)
		}
	}
	if len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

func expandRange(token string) ([]net.IP, error) {
	parts := strings.SplitN(token, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range %q", token)
	}
	start := parseIPv4(strings.TrimSpace(parts[0]))
	if start == nil {
		return nil, fmt.Errorf("invalid range start %q", parts[0])
	}
	endText := strings.TrimSpace(parts[1])
	end := parseIPv4(endText)
	if end == nil && !strings.Contains(endText, ".") {
		prefix := strings.Split(start.String(), ".")
		last, err := strconv.Atoi(endText)
		if err != nil || last < 0 || last > 255 {
			return nil, fmt.Errorf("invalid range end %q", parts[1])
		}
		prefix[3] = strconv.Itoa(last)
		end = parseIPv4(strings.Join(prefix, "."))
	}
	if end == nil {
		return nil, fmt.Errorf("invalid range end %q", parts[1])
	}
	startN := ipToUint32(start)
	endN := ipToUint32(end)
	if startN > endN {
		return nil, fmt.Errorf("invalid descending IP range %q", token)
	}
	out := make([]net.IP, 0, int(endN-startN)+1)
	for n := startN; n <= endN; n++ {
		out = append(out, uint32ToIP(n))
	}
	return out, nil
}

func parseAddr(addr net.Addr) (net.IP, *net.IPNet, bool) {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP, v, true
	case *net.IPAddr:
		return v.IP, &net.IPNet{IP: v.IP, Mask: net.CIDRMask(32, 32)}, true
	default:
		return nil, nil, false
	}
}

func parseIPv4(text string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(text))
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func isAllowed(ip net.IP, allowPublic bool) bool {
	if allowPublic {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
