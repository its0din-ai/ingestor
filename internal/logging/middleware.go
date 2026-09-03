package logging

import (
	"context"
	"log/slog"
	"net"
	"net/http"
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

const trustProxyKey ctxKey = 0

// ProxyHeaders wraps next and marks the request as arriving through a trusted
// reverse proxy when trust is true (e.g. nginx, Cloudflare, or a FlareProx
// Cloudflare Worker). ClientIP and base-URL derivation then honor the proxy
// headers (X-Morph-Real-Ip, CF-Connecting-IP, X-Forwarded-For/Proto/Host).
// When trust is false the socket peer address and request Host are
// authoritative, so an untrusted client cannot spoof its own IP.
func ProxyHeaders(trust bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trust {
			r = r.WithContext(context.WithValue(r.Context(), trustProxyKey, true))
		}
		next.ServeHTTP(w, r)
	})
}

// TrustedProxy reports whether the request context indicates the request
// arrived via a trusted reverse proxy.
func TrustedProxy(r *http.Request) bool {
	v, _ := r.Context().Value(trustProxyKey).(bool)
	return v
}

// ClientIP returns the originating client IP. Behind a trusted reverse proxy
// (see ProxyHeaders) it honors, in order: X-Morph-Real-Ip, CF-Connecting-IP
// (Cloudflare), then the leftmost X-Forwarded-For entry. Otherwise the socket
// peer address is returned.
func ClientIP(r *http.Request) string {
	if TrustedProxy(r) {
		for _, name := range []string{"X-Morph-Real-Ip", "CF-Connecting-IP", "X-Forwarded-For"} {
			if ip := forwardedIP(r.Header.Get(name)); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
