# wifi-scanner

`wifi-scanner`는 허가된 내부망에서 살아있는 장비와 열려 있는 서버 포트를 빠르게 찾는 Go CLI 도구입니다. 기본 모드는 속도 우선으로 자주 쓰는 TCP 서버 포트를 빠르게 훑고, `--deep` 모드는 더 넓은 TCP/UDP 탐색, ARP/SSDP 로컬 발견, 배너 수집까지 수행합니다.

> 본 도구는 본인 소유이거나 명시적으로 허가받은 내부망 자산 발견 용도입니다. 취약점 공격, 인증 우회, 비밀번호 대입, 은닉/회피, credential 수집 기능은 포함하지 않습니다.

## 가장 쉬운 설치

Homebrew를 쓰는 macOS/Linux 환경이면 아래 두 줄이면 됩니다.

```sh
brew tap bssm-oss/wifi-scanner https://github.com/bssm-oss/wifi-scanner.git
brew install bssm-oss/wifi-scanner/wifi-scanner
```

설치 확인:

```sh
wifi-scanner --version
```

## 바로 다운로드

Homebrew 없이 릴리스 파일을 직접 받을 수도 있습니다.

macOS Apple Silicon:

```sh
VERSION=v0.1.1
curl -L -o wifi-scanner.tar.gz "https://github.com/bssm-oss/wifi-scanner/releases/download/${VERSION}/wifi-scanner_${VERSION#v}_darwin_arm64.tar.gz"
tar -xzf wifi-scanner.tar.gz
sudo mv wifi-scanner /usr/local/bin/
wifi-scanner --version
```

macOS Intel:

```sh
VERSION=v0.1.1
curl -L -o wifi-scanner.tar.gz "https://github.com/bssm-oss/wifi-scanner/releases/download/${VERSION}/wifi-scanner_${VERSION#v}_darwin_amd64.tar.gz"
tar -xzf wifi-scanner.tar.gz
sudo mv wifi-scanner /usr/local/bin/
wifi-scanner --version
```

Linux x86_64:

```sh
VERSION=v0.1.1
curl -L -o wifi-scanner.tar.gz "https://github.com/bssm-oss/wifi-scanner/releases/download/${VERSION}/wifi-scanner_${VERSION#v}_linux_amd64.tar.gz"
tar -xzf wifi-scanner.tar.gz
sudo mv wifi-scanner /usr/local/bin/
wifi-scanner --version
```

Windows는 [Releases](https://github.com/bssm-oss/wifi-scanner/releases/latest)에서 `windows_amd64.zip` 또는 `windows_arm64.zip`을 받으면 됩니다.

## Go로 설치

Go가 설치되어 있다면 소스에서 바로 설치할 수 있습니다.

```sh
go install github.com/bssm-oss/wifi-scanner/cmd/wifi-scanner@latest
```

## 빠른 사용법

현재 활성화된 private IPv4 인터페이스를 자동으로 찾아 기본 포트를 스캔:

```sh
wifi-scanner
```

CIDR 대역을 빠르게 스캔:

```sh
wifi-scanner --targets 192.168.1.0/24
```

특정 IP 범위와 포트만 스캔:

```sh
wifi-scanner -t 10.0.0.10-50 -p 22,80,443,3000-3010
```

JSON으로 결과 저장:

```sh
wifi-scanner --targets 192.168.1.0/24 --ports default --format json > assets.json
```

CSV로 결과 저장:

```sh
wifi-scanner --targets 192.168.1.0/24 --ports default --format csv > assets.csv
```

더 깊게 찾기:

```sh
wifi-scanner --targets 172.16.0.0/24 --deep --format table
```

`--deep`은 모든 TCP 포트, 기본 UDP probe, ARP/SSDP 로컬 발견, 가벼운 배너 수집을 포함합니다. 오래 걸릴 수 있으므로 처음에는 작은 대역에서 실행하는 것을 권장합니다.

## 결과 예시

```text
URL                       IP         PORT   PROTO  STATUS  SOURCE   LATENCY_MS  BANNER
https://127.0.0.1:18080  127.0.0.1  18080  tcp    open    connect  0
```

JSON/CSV 출력도 `url` 필드를 제공합니다. 열린 TCP/UDP 포트는 `https://IP:PORT` 형태로 바로 복사해서 브라우저에 붙여 넣을 수 있게 표시됩니다.

## 주요 기능

- CIDR, 단일 IP, IP range 입력 지원
- `--targets` 생략 시 활성 private IPv4 인터페이스 자동 탐색
- 기본 public IP 스캔 차단, `--allow-public`로 명시적 허용
- 속도 우선 TCP connect scan
- `--deep` 확장 스캔
- UDP probe, ARP table, SSDP 발견 지원
- table/json/csv 출력
- timeout, concurrency, retries, max hosts 조절
- GoReleaser 기반 macOS/Linux/Windows 릴리스
- Homebrew 설치 지원

## 옵션

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

## 개발 및 테스트

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/wifi-scanner
```

로컬에서 실제 포트 발견 테스트:

```sh
python3 -m http.server 18080 --bind 127.0.0.1 &
wifi-scanner --targets 127.0.0.1 --ports 18080 --banner --format table
```

## 릴리스

버전 태그를 푸시하면 GitHub Actions가 GoReleaser로 macOS, Linux, Windows 바이너리와 checksums 파일을 생성합니다.

```sh
git tag v0.1.1
git push origin main v0.1.1
```

릴리스 결과는 [GitHub Releases](https://github.com/bssm-oss/wifi-scanner/releases)에서 확인할 수 있습니다.
