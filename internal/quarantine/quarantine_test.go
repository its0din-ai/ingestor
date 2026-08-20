package quarantine

import "testing"

func TestIsQuarantined(t *testing.T) {
	tests := []struct {
		name      string
		blacklist []string
		want      bool
	}{
		{"shell.php", DefaultBlacklist, true},
		{"SHELL.PHP", DefaultBlacklist, true},
		{"shell.php.txt", DefaultBlacklist, true},
		{"shell.txt.php", DefaultBlacklist, true},
		{"report.pdf", DefaultBlacklist, false},
		{"archive.tar.gz", DefaultBlacklist, false},
		{"noextension", DefaultBlacklist, false},
		{"malware.exe.quarantined", DefaultBlacklist, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsQuarantined(tt.name, tt.blacklist); got != tt.want {
				t.Errorf("IsQuarantined(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
