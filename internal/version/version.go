// Package version holds the application's semantic version.
package version

// Version is the application's semantic version (https://semver.org,
// SemVer 2.0.0). It is the single source of truth for the running build and
// is reported by /healthz and the startup log.
//
// Release builds override it at link time from the nearest git tag:
//
//	go build -ldflags "-X github.com/encrypt0r/ingestor/internal/version.Version=$(git describe --tags --always --dirty | sed 's/^v//')"
//
// The default below is a valid SemVer prerelease used by untagged
// development builds (for example a plain `go build` or `go run .`).
var Version = "0.0.0-dev"
