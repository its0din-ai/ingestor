package logging

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPUntrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("CF-Connecting-IP", "192.0.2.1")

	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("untrusted ClientIP = %q, want socket peer 203.0.113.9", got)
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "198.51.100.7" {
			t.Fatalf("trusted ClientIP = %q, want X-Forwarded-For 198.51.100.7", got)
		}
	})

	rr := httptest.NewRecorder()
	ProxyHeaders(ProxyPolicy{Trust: true}, next).ServeHTTP(rr, req)
}

func TestClientIPTrustedCloudflare(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("CF-Connecting-IP", "192.0.2.1")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "192.0.2.1" {
			t.Fatalf("trusted ClientIP = %q, want CF-Connecting-IP 192.0.2.1", got)
		}
	})

	rr := httptest.NewRecorder()
	ProxyHeaders(ProxyPolicy{Trust: true}, next).ServeHTTP(rr, req)
}

func TestClientIPXRealIPIgnored(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "198.51.100.7" {
			t.Fatalf("trusted ClientIP = %q, want X-Forwarded-For 198.51.100.7 (X-Real-IP is not trusted)", got)
		}
	})

	rr := httptest.NewRecorder()
	ProxyHeaders(ProxyPolicy{Trust: true}, next).ServeHTTP(rr, req)
}

func TestClientIPMorphRealIPIgnoredByDefault(t *testing.T) {
	// Cloudflare passes a client-supplied X-Morph-Real-Ip through unchanged,
	// so it must not win over CF-Connecting-IP unless explicitly opted in.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Morph-Real-Ip", "198.51.100.44")
	req.Header.Set("CF-Connecting-IP", "192.0.2.1")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "192.0.2.1" {
			t.Fatalf("trusted ClientIP = %q, want CF-Connecting-IP 192.0.2.1", got)
		}
		if ViaMorphProxy(r) {
			t.Fatal("client-supplied X-Morph-Real-Ip must not be treated as a trusted proxy")
		}
	})

	rr := httptest.NewRecorder()
	ProxyHeaders(ProxyPolicy{Trust: true}, next).ServeHTTP(rr, req)
}

func TestClientIPMorphRealIPPriorityWhenOptedIn(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Morph-Real-Ip", "198.51.100.44")
	req.Header.Set("CF-Connecting-IP", "192.0.2.1")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "198.51.100.44" {
			t.Fatalf("trusted ClientIP = %q, want X-Morph-Real-Ip 198.51.100.44", got)
		}
		if !ViaMorphProxy(r) {
			t.Fatal("opted-in X-Morph-Real-Ip should mark the request as proxied")
		}
	})

	rr := httptest.NewRecorder()
	ProxyHeaders(ProxyPolicy{Trust: true, TrustMorphRealIP: true}, next).ServeHTTP(rr, req)
}

func TestClientIPTrustedProxiesAllowList(t *testing.T) {
	policy := ProxyPolicy{
		Trust:          true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}

	// A peer outside the allow-list cannot supply forwarded headers.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("CF-Connecting-IP", "192.0.2.1")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "203.0.113.9" {
			t.Fatalf("untrusted peer ClientIP = %q, want socket peer 203.0.113.9", got)
		}
	})
	ProxyHeaders(policy, next).ServeHTTP(httptest.NewRecorder(), req)

	// A peer inside the allow-list is trusted.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("CF-Connecting-IP", "192.0.2.1")
	next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := ClientIP(r); got != "192.0.2.1" {
			t.Fatalf("trusted peer ClientIP = %q, want CF-Connecting-IP 192.0.2.1", got)
		}
	})
	ProxyHeaders(policy, next).ServeHTTP(httptest.NewRecorder(), req)
}

func TestClientIPMissingPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "2001:db8::1"

	if got := ClientIP(req); got != "2001:db8::1" {
		t.Fatalf("ClientIP = %q, want 2001:db8::1", got)
	}
}
