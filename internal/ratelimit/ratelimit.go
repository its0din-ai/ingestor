// Package ratelimit provides a small in-memory per-key rate limiter used to
// throttle admin login attempts. It is intentionally limited in scope so it
// is easy to audit; it keeps only the keys it has seen.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a fixed-window limiter keyed by arbitrary strings (e.g. client
// IPs). It is safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string][]time.Time
}

// New returns a Limiter allowing at most limit attempts per window.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:    limit,
		window:   window,
		attempts: make(map[string][]time.Time),
	}
}

// Allow records an attempt for key and reports whether it stays under the
// limit for the current window. Stale attempts are pruned lazily.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	times := l.attempts[key]
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)
	return true
}
