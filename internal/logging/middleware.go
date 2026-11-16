package logging

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"bytes", rw.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", ClientIP(r),
		)
	})
}

type ctxKey int

const proxyPolicyKey ctxKey = 0

// ProxyPolicy controls whether forwarded-IP headers are trusted, and which
// headers are honored. Trust is granted only when the request's socket peer is
// in TrustedProxies (or the list is empty, for deployments that restrict
// reachability at the network layer).
type ProxyPolicy struct {
	// Trust enables proxy-header handling at all.
	Trust bool
	// TrustedProxies restricts which peers may supply proxy headers. An empty
	// list trusts every peer when Trust is set.
	TrustedProxies []netip.Prefix
	// TrustMorphRealIP honors the X-Morph-Real-Ip header. It must stay false
	// behind Cloudflare, which forwards a client-supplied value unchanged.
	TrustMorphRealIP bool
}

// allows reports whether the given socket peer may supply forwarded headers.
func (p ProxyPolicy) allows(remoteAddr string) bool {
	if !p.Trust {
		return false
	}
	if len(p.TrustedProxies) == 0 {
		return true
	}
	addr, ok := parsePeerAddr(remoteAddr)
	if !ok {
		return false
	}
	for _, prefix := range p.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ProxyHeaders wraps next and marks the request as arriving through a trusted
// reverse proxy when the policy allows it. ClientIP and base-URL derivation
// then honor the proxy headers. When the peer is not trusted the socket peer
// address and request Host are authoritative, so an untrusted client cannot
// spoof its own IP.
func ProxyHeaders(policy ProxyPolicy, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if policy.allows(r.RemoteAddr) {
			r = r.WithContext(context.WithValue(r.Context(), proxyPolicyKey, policy))
		}
		next.ServeHTTP(w, r)
	})
}

// TrustedProxy reports whether the request context indicates the request
// arrived via a trusted reverse proxy.
func TrustedProxy(r *http.Request) bool {
	_, ok := proxyPolicy(r)
	return ok
}

func proxyPolicy(r *http.Request) (ProxyPolicy, bool) {
	if r == nil {
		return ProxyPolicy{}, false
	}
	p, ok := r.Context().Value(proxyPolicyKey).(ProxyPolicy)
	return p, ok
}

// ClientIP returns the originating client IP. Behind a trusted reverse proxy
// (see ProxyHeaders) it honors CF-Connecting-IP (Cloudflare) and then the
// leftmost X-Forwarded-For entry. X-Morph-Real-Ip is only consulted when the
// policy explicitly opts in, because proxies that do not set it (notably
// Cloudflare) pass a client-supplied value through unchanged. Otherwise the
// socket peer address is returned.
func ClientIP(r *http.Request) string {
	if p, ok := proxyPolicy(r); ok {
		headers := []string{"CF-Connecting-IP", "X-Forwarded-For"}
		if p.TrustMorphRealIP {
			headers = append([]string{"X-Morph-Real-Ip"}, headers...)
		}
		for _, name := range headers {
			if ip := forwardedIP(r.Header.Get(name)); ip != "" {
				return ip
			}
		}
	}
	if ip, ok := parsePeerAddr(r.RemoteAddr); ok {
		return ip.String()
	}
	return r.RemoteAddr
}

// ViaMorphProxy reports whether the request came through a proxy whose
// X-Morph-Real-Ip header is trusted. A client-supplied header on an untrusted
// peer never counts.
func ViaMorphProxy(r *http.Request) bool {
	p, ok := proxyPolicy(r)
	return ok && p.TrustMorphRealIP && forwardedIP(r.Header.Get("X-Morph-Real-Ip")) != ""
}

// parsePeerAddr extracts the host portion of a socket address, normalizes
// IPv4-in-IPv6 addresses, and reports whether it is a usable IP address.
func parsePeerAddr(remoteAddr string) (netip.Addr, bool) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// forwardedIP trims a proxy header value and returns its leftmost, non-empty
// token (the header may carry a comma-separated chain).
func forwardedIP(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	return value
}
