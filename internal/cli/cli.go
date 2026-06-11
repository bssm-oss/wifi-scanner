package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/bssm-oss/wifi-scanner/internal/output"
	"github.com/bssm-oss/wifi-scanner/internal/ports"
	"github.com/bssm-oss/wifi-scanner/internal/scanner"
	"github.com/bssm-oss/wifi-scanner/internal/target"
)

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

func Run(args []string, stdout, stderr io.Writer, version VersionInfo) int {
	if len(args) > 0 {
		switch args[0] {
		case "completion":
			return runCompletion(args[1:], stdout, stderr)
		case "help":
			writeHelp(stdout, version)
			return 0
		}
	}
	if wantsHelp(args) {
		writeHelp(stdout, version)
		return 0
	}

	cfg, err := parseFlags(args, stderr, version)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	if cfg.showVersion {
		fmt.Fprintf(stdout, "wifi-scanner %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return 0
	}
	siteStatus, err := parseStatusRanges(cfg.siteCodes)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets, err := target.Expand(cfg.targets, target.Options{
		AllowPublic: cfg.allowPublic,
		MaxHosts:    cfg.maxHosts,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	tcpPorts, err := ports.ParseTCP(cfg.tcpPorts, cfg.deep)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	udpPorts, err := ports.ParseUDP(cfg.udpPorts)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if cfg.deep && cfg.udpPorts == "" {
		udpPorts = append([]int(nil), ports.DefaultUDP...)
	}

	localDiscovery := cfg.deep && !cfg.noLocalDiscovery && cfg.mode != "sites"
	banner := cfg.banner || cfg.deep
	fmt.Fprintf(stderr, "Scanning %d hosts, %d TCP ports", len(targets), len(tcpPorts))
	if len(udpPorts) > 0 {
		fmt.Fprintf(stderr, ", %d UDP probes", len(udpPorts))
	}
	if localDiscovery {
		fmt.Fprint(stderr, ", local discovery")
	}
	if cfg.mode == "sites" || cfg.mode == "all" {
		fmt.Fprintf(stderr, ", site checks (%s)", cfg.siteCodes)
	}
	fmt.Fprintln(stderr, "...")

	results, err := scanner.Scan(ctx, scanner.Config{
		Targets:        targets,
		TCPPorts:       tcpPorts,
		UDPPorts:       udpPorts,
		Timeout:        cfg.timeout,
		Concurrency:    cfg.concurrency,
		Retries:        cfg.retries,
		Banner:         banner,
		LocalDiscovery: localDiscovery,
		ProbeSites:     cfg.mode == "sites" || cfg.mode == "all",
		SitesOnly:      cfg.mode == "sites",
		SiteTimeout:    cfg.siteTimeout,
		SiteStatus:     siteStatus,
	})
	if err != nil && err != context.Canceled {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := output.Write(stdout, cfg.format, results); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch cfg.mode {
	case "sites":
		fmt.Fprintf(stderr, "Found %d browser-openable sites.\n", len(results))
	default:
		fmt.Fprintf(stderr, "Found %d responsive services or hosts.\n", len(results))
	}
	return 0
}

type config struct {
	targets          string
	tcpPorts         string
	udpPorts         string
	mode             string
	siteCodes        string
	format           string
	timeout          time.Duration
	siteTimeout      time.Duration
	concurrency      int
	retries          int
	maxHosts         int
	deep             bool
	banner           bool
	sitesOnly        bool
	portsOnly        bool
	noLocalDiscovery bool
	allowPublic      bool
	showVersion      bool
}

func parseFlags(args []string, stderr io.Writer, version VersionInfo) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("wifi-scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		writeHelp(fs.Output(), version)
	}

	var shortTargets, shortPorts string
	fs.StringVar(&cfg.targets, "targets", "", "CIDR, IP, or range list to scan. Defaults to active private IPv4 interfaces.")
	fs.StringVar(&shortTargets, "t", "", "Short form of --targets.")
	fs.StringVar(&cfg.tcpPorts, "ports", "", "TCP ports: default, all, or comma/range list like 22,80,8000-9000.")
	fs.StringVar(&shortPorts, "p", "", "Short form of --ports.")
	fs.StringVar(&cfg.udpPorts, "udp-ports", "", "UDP probes: default, none, all, or comma/range list. Deep mode uses default when omitted.")
	fs.StringVar(&cfg.mode, "mode", "ports", "Scan mode: ports, sites, or all. ports=open ports only, sites=browser-openable HTTP/S only, all=open ports plus site checks.")
	fs.StringVar(&cfg.siteCodes, "site-codes", "200-399", "HTTP status codes accepted by sites mode, like 200-399 or 200-399,401.")
	fs.StringVar(&cfg.format, "format", "table", "Output format: table, json, or csv.")
	fs.DurationVar(&cfg.timeout, "timeout", 300*time.Millisecond, "Per-port timeout.")
	fs.DurationVar(&cfg.siteTimeout, "site-timeout", 1200*time.Millisecond, "Per-site HTTP/S probe timeout.")
	fs.IntVar(&cfg.concurrency, "concurrency", 512, "Maximum concurrent probes.")
	fs.IntVar(&cfg.retries, "retries", 0, "Retry count for failed TCP connects.")
	fs.IntVar(&cfg.maxHosts, "max-hosts", 65536, "Maximum expanded hosts. Use 0 for no limit.")
	fs.BoolVar(&cfg.deep, "deep", false, "Use exhaustive TCP ports, default UDP probes, local discovery, banners, and retries-friendly behavior.")
	fs.BoolVar(&cfg.banner, "banner", false, "Try to collect lightweight service banners for open TCP ports.")
	fs.BoolVar(&cfg.sitesOnly, "sites-only", false, "Shortcut for --mode sites: only show browser-openable HTTP/S sites.")
	fs.BoolVar(&cfg.portsOnly, "ports-only", false, "Shortcut for --mode ports: only show responsive ports/services.")
	fs.BoolVar(&cfg.noLocalDiscovery, "no-local-discovery", false, "Disable ARP/SSDP local discovery in --deep mode.")
	fs.BoolVar(&cfg.allowPublic, "allow-public", false, "Allow non-private targets. Use only for networks you are authorized to scan.")
	fs.BoolVar(&cfg.showVersion, "version", false, "Print version and exit.")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if shortTargets != "" {
		if cfg.targets != "" {
			return config{}, fmt.Errorf("use either --targets or -t, not both")
		}
		cfg.targets = shortTargets
	}
	if shortPorts != "" {
		if cfg.tcpPorts != "" {
			return config{}, fmt.Errorf("use either --ports or -p, not both")
		}
		cfg.tcpPorts = shortPorts
	}
	cfg.format = strings.ToLower(strings.TrimSpace(cfg.format))
	cfg.mode = strings.ToLower(strings.TrimSpace(cfg.mode))
	if cfg.sitesOnly && cfg.portsOnly {
		return config{}, fmt.Errorf("use either --sites-only or --ports-only, not both")
	}
	if cfg.sitesOnly {
		cfg.mode = "sites"
	}
	if cfg.portsOnly {
		cfg.mode = "ports"
	}
	switch cfg.mode {
	case "ports", "sites", "all":
	default:
		return config{}, fmt.Errorf("--mode must be ports, sites, or all")
	}
	if cfg.concurrency < 1 {
		return config{}, fmt.Errorf("--concurrency must be at least 1")
	}
	if cfg.timeout <= 0 {
		return config{}, fmt.Errorf("--timeout must be positive")
	}
	if cfg.siteTimeout <= 0 {
		return config{}, fmt.Errorf("--site-timeout must be positive")
	}
	if cfg.retries < 0 {
		return config{}, fmt.Errorf("--retries cannot be negative")
	}
	if cfg.maxHosts < 0 {
		return config{}, fmt.Errorf("--max-hosts cannot be negative")
	}
	return cfg, nil
}

func wantsHelp(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "-h", "-help", "--help":
			return true
		}
	}
	return false
}

func writeHelp(w io.Writer, version VersionInfo) {
	fmt.Fprintf(w, `wifi-scanner %s

내부망에서 열린 포트와 실제 접속 가능한 사이트를 빠르게 찾는 도구입니다.

사용법:
  wifi-scanner
      현재 연결된 내부망을 기본 포트로 빠르게 스캔합니다.

  wifi-scanner --targets 192.168.1.0/24 --ports-only
      열린 포트만 찾습니다.

  wifi-scanner --targets 192.168.1.0/24 --sites-only
      브라우저로 실제 들어가지는 사이트만 찾습니다.

  wifi-scanner --targets 192.168.1.0/24 --mode all
      열린 포트 전체와 사이트 접속 여부를 같이 보여줍니다.

  wifi-scanner --targets 10.0.0.10-50 --ports 22,80,443,3000-3010
      특정 IP 범위와 포트만 스캔합니다.

  wifi-scanner completion zsh
      zsh 자동완성 스크립트를 출력합니다.

자주 쓰는 옵션:
  --targets, -t        스캔 대상. CIDR, 단일 IP, IP 범위 지원. 예: 192.168.1.0/24, 10.0.0.10-50
  --ports, -p          TCP 포트. default, all, 또는 22,80,8000-9000 형태
  --ports-only         열린 포트만 출력합니다. 기본 모드입니다.
  --sites-only         HTTP/S 요청까지 확인해서 들어가지는 사이트만 출력합니다.
  --mode               ports, sites, all 중 선택합니다. 기본값: ports
  --format             table, json, csv 중 선택합니다. 기본값: table
  --deep               더 넓게 찾습니다. 모든 TCP 포트, UDP 기본 probe, 로컬 발견을 포함합니다.
  --timeout            포트 연결 timeout. 기본값: 300ms
  --site-timeout       사이트 접속 확인 timeout. 기본값: 1.2s
  --site-codes         사이트로 인정할 HTTP 코드. 기본값: 200-399
  --concurrency        동시에 검사할 개수. 기본값: 512
  --max-hosts          대상 IP 최대 개수. 기본값: 65536
  --allow-public       공인 IP 스캔 허용. 허가된 대상에만 사용하세요.
  --version            버전을 출력합니다.
  --help               이 도움말을 출력합니다.

자동완성:
  wifi-scanner completion zsh   # zsh
  wifi-scanner completion bash  # bash
  wifi-scanner completion fish  # fish

예시:
  wifi-scanner --sites-only
  wifi-scanner --ports-only --format csv
  wifi-scanner --mode all --site-codes 200-399,401

주의:
  본인 소유이거나 명시적으로 허가받은 내부망에서만 사용하세요.
`, version.Version)
}

func parseStatusRanges(spec string) ([]scanner.StatusRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return scanner.DefaultSiteStatus(), nil
	}
	var ranges []scanner.StatusRange
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			start, err := parseStatusCode(parts[0])
			if err != nil {
				return nil, err
			}
			end, err := parseStatusCode(parts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid descending status range %q", token)
			}
			ranges = append(ranges, scanner.StatusRange{Start: start, End: end})
			continue
		}
		code, err := parseStatusCode(token)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, scanner.StatusRange{Start: code, End: code})
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("no status codes parsed from %q", spec)
	}
	return ranges, nil
}

func parseStatusCode(token string) (int, error) {
	code, err := strconv.Atoi(strings.TrimSpace(token))
	if err != nil {
		return 0, fmt.Errorf("invalid HTTP status code %q", token)
	}
	if code < 100 || code > 599 {
		return 0, fmt.Errorf("HTTP status code %d is outside 100-599", code)
	}
	return code, nil
}
