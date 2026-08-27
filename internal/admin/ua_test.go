package admin

import "testing"

func TestUALabel(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"", ""},
		{"curl/8.7.1", "curl"},
		{"Wget/1.21.4", "wget"},
		{"python-requests/2.31.0", "python"},
		{"Go-http-client/2.0", "go"},
		{"PostmanRuntime/7.32.0", "postman"},
		{"insomnia/2023.1.0", "insomnia"},
		{"Mozilla/5.0 (Windows NT 10.0; Microsoft Windows NT 10.0.17763) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763", "powershell"},
		{"Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.9168", "powershell"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.3.0", "powershell"},
		{"axios/1.6.0", "axios"},
		{"okhttp/4.12.0", "okhttp"},
		{"Node.js/20.0.0", "node"},
		{"Mozilla/5.0 Googlebot/2.1", "bot"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0", "edge"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15.7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "chrome"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", "firefox"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "safari"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "ios"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36", "android"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "mac os"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
		{"SomeRandomAgentXYZ", "unknown"},
	}
	for _, tt := range tests {
		if got := uaLabel(tt.ua); got != tt.want {
			t.Errorf("uaLabel(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}
