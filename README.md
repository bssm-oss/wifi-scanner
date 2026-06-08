# wifi-scanner

Fast Go CLI for authorized internal network asset discovery. It scans private networks for responsive hosts and open server ports, with speed-first defaults and an explicit deep mode for broader discovery.

## Install

With Homebrew:

```sh
brew tap bssm-oss/wifi-scanner https://github.com/bssm-oss/wifi-scanner.git
brew install wifi-scanner
```

From source:

```sh
go install github.com/bssm-oss/wifi-scanner/cmd/wifi-scanner@latest
```

## Usage

Fast scan of a CIDR using common server ports:

```sh
wifi-scanner --targets 192.168.1.0/24
```

Scan a host range and specific ports:

```sh
wifi-scanner -t 10.0.0.10-50 -p 22,80,443,3000-3010
```

Deep scan with all TCP ports, default UDP probes, ARP/SSDP local discovery, and lightweight banners:

```sh
wifi-scanner --targets 172.16.0.0/24 --deep --format json
```

CSV output:

```sh
wifi-scanner --targets 192.168.1.0/24 --ports default --format csv > assets.csv
```

## Defaults

- If `--targets` is omitted, active private IPv4 interfaces are used.
- Public IPs are rejected unless `--allow-public` is set.
- Default TCP ports are a speed-first set of common server ports.
- `--deep` scans all TCP ports and adds default UDP probes, ARP/SSDP local discovery, and banner collection.
- `--max-hosts` defaults to `65536` to prevent accidental massive scans.

## Flags

```text
--targets, -t           CIDR, IP, or range list
--ports, -p             TCP ports: default, all, or list/range
--udp-ports             UDP probes: default, none, all, or list/range
--deep                  Exhaustive TCP ports plus discovery helpers
--format                table, json, or csv
--timeout               Per-port timeout, default 300ms
--concurrency           Maximum concurrent probes, default 512
--retries               Retry count for failed TCP connects
--max-hosts             Expanded host limit, default 65536
--banner                Try lightweight TCP banner collection
--no-local-discovery    Disable ARP/SSDP in deep mode
--allow-public          Allow non-private targets for authorized scans
--version               Print version
```

## Safety Boundary

Use this only on networks you own or are explicitly authorized to assess. This tool performs asset discovery: TCP connects, best-effort UDP probes, ARP table parsing, SSDP discovery, and optional lightweight banner reads. It does not implement exploit execution, authentication bypass, password guessing, stealth, evasion, or credential collection.

## Development

```sh
go test ./...
go build ./cmd/wifi-scanner
```

Run a local smoke test:

```sh
python3 -m http.server 18080 &
wifi-scanner --targets 127.0.0.1 --ports 18080 --banner
```

## Release

Push a version tag to run GoReleaser:

```sh
git tag v0.1.0
git push origin main v0.1.0
```

The release workflow builds macOS, Linux, and Windows binaries and uploads checksums to the GitHub release. The Homebrew formula in `Formula/wifi-scanner.rb` builds the current `main` branch from source, so the tap install path works immediately after the repository is pushed.

