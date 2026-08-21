package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterAllowWithinWindow(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("attempt %d: expected allowed", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("4th attempt: expected blocked")
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	l := New(1, time.Minute)
	if !l.Allow("a") {
		t.Fatal("expected a allowed")
	}
	if l.Allow("a") {
		t.Fatal("expected a blocked")
	}
	if !l.Allow("b") {
		t.Fatal("expected b allowed")
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	l := New(1, 50*time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("expected allowed")
	}
	if l.Allow("k") {
		t.Fatal("expected blocked within window")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("expected allowed after window expired")
	}
}

func TestLimiterStalePruning(t *testing.T) {
	l := New(2, 30*time.Millisecond)
	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("expected allowed")
	}
	time.Sleep(40 * time.Millisecond)
	// Both attempts are stale now; a fresh attempt must be allowed and the
	// map must not grow unboundedly as stale entries are dropped.
	if !l.Allow("k") {
		t.Fatal("expected allowed after pruning stale entries")
	}
}
