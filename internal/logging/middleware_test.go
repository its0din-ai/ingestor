package logging

import (
	"net/http"
	"net/http/httptest"
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
	ProxyHeaders(true, next).ServeHTTP(rr, req)
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
	ProxyHeaders(true, next).ServeHTTP(rr, req)
}

func TestClientIPMissingPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "2001:db8::1"

	if got := ClientIP(req); got != "2001:db8::1" {
		t.Fatalf("ClientIP = %q, want 2001:db8::1", got)
	}
}
