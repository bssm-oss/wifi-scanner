package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Targets        []net.IP
	TCPPorts       []int
	UDPPorts       []int
	Timeout        time.Duration
	Concurrency    int
	Retries        int
	Banner         bool
	LocalDiscovery bool
}

type Result struct {
	IP        string `json:"ip"`
	Port      int    `json:"port,omitempty"`
	URL       string `json:"url,omitempty"`
	Protocol  string `json:"protocol"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Banner    string `json:"banner,omitempty"`
}

func Scan(ctx context.Context, cfg Config) ([]Result, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 300 * time.Millisecond
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 512
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}

	var results []Result
	if len(cfg.TCPPorts) > 0 && len(cfg.Targets) > 0 {
		tcpResults, err := scanTCP(ctx, cfg)
		if err != nil {
			return nil, err
		}
		results = append(results, tcpResults...)
	}
	if len(cfg.UDPPorts) > 0 && len(cfg.Targets) > 0 {
		udpResults, err := scanUDP(ctx, cfg)
		if err != nil {
			return nil, err
		}
		results = append(results, udpResults...)
	}
	if cfg.LocalDiscovery {
		results = append(results, DiscoverARP(ctx)...)
		results = append(results, DiscoverSSDP(ctx, cfg.Timeout)...)
	}

	sortResults(results)
	return dedupe(results), nil
}

type job struct {
	ip   net.IP
	port int
}

func scanTCP(ctx context.Context, cfg Config) ([]Result, error) {
	jobs := make(chan job)
	out := make(chan Result)
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if result, ok := scanTCPPort(ctx, j.ip, j.port, cfg); ok {
					out <- result
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range cfg.Targets {
			for _, port := range cfg.TCPPorts {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{ip: ip, port: port}:
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	var results []Result
	for result := range out {
		results = append(results, result)
	}
	return results, ctx.Err()
}

func scanTCPPort(ctx context.Context, ip net.IP, port int, cfg Config) (Result, bool) {
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	var lastLatency time.Duration
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		start := time.Now()
		dialer := net.Dialer{Timeout: cfg.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		lastLatency = time.Since(start)
		if err != nil {
			continue
		}
		defer conn.Close()
		banner := ""
		if cfg.Banner {
			banner = readBanner(conn, port, cfg.Timeout)
		}
		return Result{
			IP:        ip.String(),
			Port:      port,
			URL:       HTTPSURL(ip.String(), port),
			Protocol:  "tcp",
			Status:    "open",
			Source:    "connect",
			LatencyMS: lastLatency.Milliseconds(),
			Banner:    banner,
		}, true
	}
	return Result{}, false
}

func scanUDP(ctx context.Context, cfg Config) ([]Result, error) {
	jobs := make(chan job)
	out := make(chan Result)
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if result, ok := probeUDP(ctx, j.ip, j.port, cfg.Timeout); ok {
					out <- result
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range cfg.Targets {
			for _, port := range cfg.UDPPorts {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{ip: ip, port: port}:
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	var results []Result
	for result := range out {
		results = append(results, result)
	}
	return results, ctx.Err()
}

func probeUDP(ctx context.Context, ip net.IP, port int, timeout time.Duration) (Result, bool) {
	dialer := net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return Result{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write(udpPayload(port))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return Result{}, false
	}
	return Result{
		IP:        ip.String(),
		Port:      port,
		URL:       HTTPSURL(ip.String(), port),
		Protocol:  "udp",
		Status:    "responsive",
		Source:    "udp-probe",
		LatencyMS: time.Since(start).Milliseconds(),
		Banner:    cleanBanner(string(buf[:n])),
	}, true
}

func readBanner(conn net.Conn, port int, timeout time.Duration) string {
	if timeout > 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if isHTTPPort(port) {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nUser-Agent: wifi-scanner\r\n\r\n"))
	}
	reader := bufio.NewReader(conn)
	buf := make([]byte, 512)
	n, err := reader.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return cleanBanner(string(buf[:n]))
}

func udpPayload(port int) []byte {
	switch port {
	case 53:
		return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 137:
		return []byte{
			0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
			0x00, 0x01,
		}
	default:
		return []byte{0}
	}
}

func DiscoverARP(ctx context.Context) []Result {
	cmd := exec.CommandContext(ctx, "arp", "-an")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	return ParseARPTable(string(output))
}

func ParseARPTable(output string) []Result {
	re := regexp.MustCompile(`\((\d{1,3}(?:\.\d{1,3}){3})\)`)
	matches := re.FindAllStringSubmatch(output, -1)
	seen := make(map[string]struct{})
	var results []Result
	for _, match := range matches {
		ip := net.ParseIP(match[1])
		if ip == nil || ip.To4() == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, Result{
			IP:       key,
			Protocol: "host",
			Status:   "seen",
			Source:   "arp",
		})
	}
	return results
}

func DiscoverSSDP(ctx context.Context, timeout time.Duration) []Result {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return nil
	}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil
	}
	defer conn.Close()
	message := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`,
		"MX: 1",
		"ST: ssdp:all",
		"", "",
	}, "\r\n")
	_, _ = conn.WriteTo([]byte(message), addr)

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	seen := make(map[string]struct{})
	var results []Result
	for {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		buf := make([]byte, 2048)
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			return results
		}
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil {
			host = remote.String()
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, Result{
			IP:       key,
			Port:     1900,
			URL:      HTTPSURL(key, 1900),
			Protocol: "udp",
			Status:   "responsive",
			Source:   "ssdp",
			Banner:   summarizeSSDP(string(buf[:n])),
		})
	}
}

func summarizeSSDP(raw string) string {
	var parts []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "SERVER:") || strings.HasPrefix(upper, "LOCATION:") || strings.HasPrefix(upper, "USN:") {
			parts = append(parts, line)
		}
		if len(parts) == 2 {
			break
		}
	}
	return cleanBanner(strings.Join(parts, " "))
}

func sortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].IP != results[j].IP {
			return ipLess(results[i].IP, results[j].IP)
		}
		if results[i].Protocol != results[j].Protocol {
			return results[i].Protocol < results[j].Protocol
		}
		return results[i].Port < results[j].Port
	})
}

func dedupe(results []Result) []Result {
	seen := make(map[string]struct{})
	out := results[:0]
	for _, r := range results {
		key := fmt.Sprintf("%s/%s/%d/%s", r.IP, r.Protocol, r.Port, r.Source)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func ipLess(a, b string) bool {
	ipa := net.ParseIP(a).To4()
	ipb := net.ParseIP(b).To4()
	if ipa == nil || ipb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ipa[i] != ipb[i] {
			return ipa[i] < ipb[i]
		}
	}
	return false
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 8000, 8008, 8080, 8081, 8888:
		return true
	default:
		return false
	}
}

func HTTPSURL(ip string, port int) string {
	if ip == "" || port <= 0 {
		return ""
	}
	return fmt.Sprintf("https://%s:%d", ip, port)
}

func cleanBanner(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
