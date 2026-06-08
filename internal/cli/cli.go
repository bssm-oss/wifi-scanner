package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
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

	localDiscovery := cfg.deep && !cfg.noLocalDiscovery
	banner := cfg.banner || cfg.deep
	fmt.Fprintf(stderr, "Scanning %d hosts, %d TCP ports", len(targets), len(tcpPorts))
	if len(udpPorts) > 0 {
		fmt.Fprintf(stderr, ", %d UDP probes", len(udpPorts))
	}
	if localDiscovery {
		fmt.Fprint(stderr, ", local discovery")
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
	})
	if err != nil && err != context.Canceled {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := output.Write(stdout, cfg.format, results); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stderr, "Found %d responsive services or hosts.\n", len(results))
	return 0
}

type config struct {
	targets          string
	tcpPorts         string
	udpPorts         string
	format           string
	timeout          time.Duration
	concurrency      int
	retries          int
	maxHosts         int
	deep             bool
	banner           bool
	noLocalDiscovery bool
	allowPublic      bool
	showVersion      bool
}

func parseFlags(args []string, stderr io.Writer, version VersionInfo) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("wifi-scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `wifi-scanner %s

Fast authorized internal network asset discovery.

Usage:
  wifi-scanner --targets 192.168.1.0/24 --ports default
  wifi-scanner -t 10.0.0.10-50 -p 22,80,443 --format json
  wifi-scanner --targets 172.16.0.0/24 --deep --format csv

Flags:
`, version.Version)
		fs.PrintDefaults()
	}

	var shortTargets, shortPorts string
	fs.StringVar(&cfg.targets, "targets", "", "CIDR, IP, or range list to scan. Defaults to active private IPv4 interfaces.")
	fs.StringVar(&shortTargets, "t", "", "Short form of --targets.")
	fs.StringVar(&cfg.tcpPorts, "ports", "", "TCP ports: default, all, or comma/range list like 22,80,8000-9000.")
	fs.StringVar(&shortPorts, "p", "", "Short form of --ports.")
	fs.StringVar(&cfg.udpPorts, "udp-ports", "", "UDP probes: default, none, all, or comma/range list. Deep mode uses default when omitted.")
	fs.StringVar(&cfg.format, "format", "table", "Output format: table, json, or csv.")
	fs.DurationVar(&cfg.timeout, "timeout", 300*time.Millisecond, "Per-port timeout.")
	fs.IntVar(&cfg.concurrency, "concurrency", 512, "Maximum concurrent probes.")
	fs.IntVar(&cfg.retries, "retries", 0, "Retry count for failed TCP connects.")
	fs.IntVar(&cfg.maxHosts, "max-hosts", 65536, "Maximum expanded hosts. Use 0 for no limit.")
	fs.BoolVar(&cfg.deep, "deep", false, "Use exhaustive TCP ports, default UDP probes, local discovery, banners, and retries-friendly behavior.")
	fs.BoolVar(&cfg.banner, "banner", false, "Try to collect lightweight service banners for open TCP ports.")
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
	if cfg.concurrency < 1 {
		return config{}, fmt.Errorf("--concurrency must be at least 1")
	}
	if cfg.timeout <= 0 {
		return config{}, fmt.Errorf("--timeout must be positive")
	}
	if cfg.retries < 0 {
		return config{}, fmt.Errorf("--retries cannot be negative")
	}
	if cfg.maxHosts < 0 {
		return config{}, fmt.Errorf("--max-hosts cannot be negative")
	}
	return cfg, nil
}
