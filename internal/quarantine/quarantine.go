package quarantine

import "strings"

var DefaultBlacklist = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phps",
	".cgi", ".pl", ".pm",
	".jsp", ".jspx", ".jspa", ".jsw", ".jsv",
	".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
	".cfm", ".cfc",
	".py", ".rb", ".lua",
	".sh", ".bash", ".csh", ".ksh",
	".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".msi",
	".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".wsh",
	".ps1", ".psc1", ".psc2",
}

// IsQuarantined reports whether any dot-separated extension of filename is
// on the blacklist. It scans every extension, not just the last one, so
// "shell.php.txt" is caught even though filepath.Ext would return ".txt".
func IsQuarantined(filename string, blacklist []string) bool {
	parts := strings.Split(strings.ToLower(filename), ".")
	for _, part := range parts[1:] {
		ext := "." + part
		for _, blocked := range blacklist {
			if ext == blocked {
				return true
			}
		}
	}
	return false
}
