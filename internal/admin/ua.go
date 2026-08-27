package admin

import "strings"

// uaLabel reduces a User-Agent string to a short, human-friendly label
// (e.g. curl, mac os, android, ios) for compact display in the audit table.
// The full User-Agent is still available in the expanded row detail.
func uaLabel(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return ""
	}
	u := strings.ToLower(ua)
	switch {
	// HTTP tools and downloaders.
	case strings.Contains(u, "microsoft windows nt"):
		// PowerShell's Invoke-WebRequest/RestMethod UA mimics Edge but carries
		// the tell-tale "Microsoft Windows NT 10.0.xxxxx" marker.
		return "powershell"
	case strings.Contains(u, "curl"):
		return "curl"
	case strings.Contains(u, "wget"):
		return "wget"
	case strings.Contains(u, "python"):
		return "python"
	case strings.Contains(u, "go-http-client"):
		return "go"
	case strings.Contains(u, "postman"):
		return "postman"
	case strings.Contains(u, "insomnia"):
		return "insomnia"
	case strings.Contains(u, "thunder client"):
		return "thunder"
	case strings.Contains(u, "axios"):
		return "axios"
	case strings.Contains(u, "okhttp"):
		return "okhttp"
	case strings.Contains(u, "node"):
		return "node"
	case strings.Contains(u, "java/"):
		return "java"
	case strings.Contains(u, "libwww"):
		return "libwww"
	// Crawlers and bots.
	case strings.Contains(u, "bot") || strings.Contains(u, "crawler") || strings.Contains(u, "spider"):
		return "bot"
	// Mobile OS wins over the browser label: ios/android is more informative
	// for mobile Safari/Chrome.
	case strings.Contains(u, "iphone") || strings.Contains(u, "ipad") || strings.Contains(u, "ipod"):
		return "ios"
	case strings.Contains(u, "android"):
		return "android"
	// Browsers.
	case strings.Contains(u, "edg/"):
		return "edge"
	case strings.Contains(u, "opr/"):
		return "opera"
	case strings.Contains(u, "chrome"):
		return "chrome"
	case strings.Contains(u, "firefox"):
		return "firefox"
	case strings.Contains(u, "safari"):
		return "safari"
	// Operating systems.
	case strings.Contains(u, "mac os") || strings.Contains(u, "macintosh"):
		return "mac os"
	case strings.Contains(u, "windows"):
		return "windows"
	case strings.Contains(u, "linux"):
		return "linux"
	}
	return "unknown"
}
