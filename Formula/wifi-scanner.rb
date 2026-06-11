class WifiScanner < Formula
  desc "Fast authorized internal network asset discovery scanner"
  homepage "https://github.com/bssm-oss/wifi-scanner"
  url "https://github.com/bssm-oss/wifi-scanner.git", branch: "main"
  version "0.1.3"
  license "MIT"

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X main.version=#{version} -X main.commit=brew -X main.date=source"
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/wifi-scanner"
    generate_completions_from_executable(bin/"wifi-scanner", "completion")
  end

  test do
    system "#{bin}/wifi-scanner", "--version"
    assert_match "내부망", shell_output("#{bin}/wifi-scanner --help")
    assert_match "_wifi_scanner", shell_output("#{bin}/wifi-scanner completion zsh")
  end
end
