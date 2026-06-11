package cli

import (
	"fmt"
	"io"
	"strings"
)

func runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "사용법: wifi-scanner completion [bash|zsh|fish]")
		return 2
	}
	switch strings.ToLower(args[0]) {
	case "bash":
		fmt.Fprint(stdout, bashCompletion)
	case "zsh":
		fmt.Fprint(stdout, zshCompletion)
	case "fish":
		fmt.Fprint(stdout, fishCompletion)
	default:
		fmt.Fprintf(stderr, "지원하지 않는 shell입니다: %s\n", args[0])
		return 2
	}
	return 0
}

const bashCompletion = `# bash completion for wifi-scanner
_wifi_scanner_completion() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  case "$prev" in
    completion)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
      return 0
      ;;
    --format|-format)
      COMPREPLY=( $(compgen -W "table json csv" -- "$cur") )
      return 0
      ;;
    --mode|-mode)
      COMPREPLY=( $(compgen -W "ports sites all" -- "$cur") )
      return 0
      ;;
    --ports|-ports|-p|--udp-ports|-udp-ports)
      COMPREPLY=( $(compgen -W "default all none" -- "$cur") )
      return 0
      ;;
  esac

  local words="completion help --targets -t --ports -p --udp-ports --mode --sites-only --ports-only --site-codes --site-timeout --format --timeout --concurrency --retries --max-hosts --deep --banner --no-local-discovery --allow-public --version --help"
  COMPREPLY=( $(compgen -W "$words" -- "$cur") )
}
complete -F _wifi_scanner_completion wifi-scanner
`

const zshCompletion = `#compdef wifi-scanner

_wifi_scanner() {
  local -a commands
  commands=(
    'completion:셸 자동완성 스크립트 출력'
    'help:도움말 출력'
  )

  _arguments -C \
    '1:command:->command' \
    '--targets[스캔 대상 CIDR/IP/range]:target:' \
    '-t[--targets 단축]:target:' \
    '--ports[TCP 포트 목록]:ports:(default all)' \
    '-p[--ports 단축]:ports:(default all)' \
    '--udp-ports[UDP probe 포트]:udp ports:(default none all)' \
    '--mode[스캔 모드]:mode:(ports sites all)' \
    '--sites-only[들어가지는 사이트만 출력]' \
    '--ports-only[열린 포트만 출력]' \
    '--site-codes[사이트로 인정할 HTTP 코드]:codes:' \
    '--site-timeout[사이트 접속 확인 timeout]:duration:' \
    '--format[출력 형식]:format:(table json csv)' \
    '--timeout[포트 연결 timeout]:duration:' \
    '--concurrency[동시 검사 개수]:number:' \
    '--retries[재시도 횟수]:number:' \
    '--max-hosts[대상 IP 최대 개수]:number:' \
    '--deep[더 넓게 스캔]' \
    '--banner[가벼운 배너 수집]' \
    '--no-local-discovery[deep 모드의 로컬 발견 비활성화]' \
    '--allow-public[공인 IP 스캔 허용]' \
    '--version[버전 출력]' \
    '--help[도움말 출력]' \
    '*::arg:->arg'

  case "$state" in
    command)
      _describe 'command' commands
      ;;
    arg)
      if [[ "${words[2]}" == "completion" ]]; then
        _values 'shell' bash zsh fish
      fi
      ;;
  esac
}

_wifi_scanner "$@"
`

const fishCompletion = `# fish completion for wifi-scanner
complete -c wifi-scanner -f
complete -c wifi-scanner -n '__fish_use_subcommand' -a completion -d '셸 자동완성 스크립트 출력'
complete -c wifi-scanner -n '__fish_use_subcommand' -a help -d '도움말 출력'
complete -c wifi-scanner -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c wifi-scanner -l targets -s t -r -d '스캔 대상 CIDR/IP/range'
complete -c wifi-scanner -l ports -s p -x -a 'default all' -d 'TCP 포트 목록'
complete -c wifi-scanner -l udp-ports -x -a 'default none all' -d 'UDP probe 포트'
complete -c wifi-scanner -l mode -x -a 'ports sites all' -d '스캔 모드'
complete -c wifi-scanner -l sites-only -d '들어가지는 사이트만 출력'
complete -c wifi-scanner -l ports-only -d '열린 포트만 출력'
complete -c wifi-scanner -l site-codes -r -d '사이트로 인정할 HTTP 코드'
complete -c wifi-scanner -l site-timeout -r -d '사이트 접속 확인 timeout'
complete -c wifi-scanner -l format -x -a 'table json csv' -d '출력 형식'
complete -c wifi-scanner -l timeout -r -d '포트 연결 timeout'
complete -c wifi-scanner -l concurrency -r -d '동시 검사 개수'
complete -c wifi-scanner -l retries -r -d '재시도 횟수'
complete -c wifi-scanner -l max-hosts -r -d '대상 IP 최대 개수'
complete -c wifi-scanner -l deep -d '더 넓게 스캔'
complete -c wifi-scanner -l banner -d '가벼운 배너 수집'
complete -c wifi-scanner -l no-local-discovery -d 'deep 모드의 로컬 발견 비활성화'
complete -c wifi-scanner -l allow-public -d '공인 IP 스캔 허용'
complete -c wifi-scanner -l version -d '버전 출력'
complete -c wifi-scanner -l help -d '도움말 출력'
`
