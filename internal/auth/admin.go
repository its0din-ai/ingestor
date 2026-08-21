package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/web"
)

const (
	sessionCookieName = "session"
	csrfCookieName    = "csrf_token"
)

type ctxKey int

const (
	csrfKey   ctxKey = 0
	bearerKey ctxKey = 1
)

// Manager issues and verifies HS512-signed JWTs for admin sessions. Each
// token carries a jti that must still exist in the sessions table, so
// logging out (which deletes the row) destroys the token even though its
// signature remains valid.
type Manager struct {
	conn   *sql.DB
	key    []byte
	ttl    time.Duration
	secure bool
}

// NewManager builds a Manager from the configured JWT secret and session TTL.
func NewManager(cfg *config.Config, conn *sql.DB) (*Manager, error) {
	key, err := cfg.JWTSecret()
	if err != nil {
		return nil, err
	}
	return &Manager{
		conn:   conn,
		key:    key,
		ttl:    cfg.SessionTTL(),
		secure: cfg.CookieSecure(),
	}, nil
}

// Admin guards the dashboard routes: session cookie required and CSRF check
// on mutating requests.
func (m *Manager) Admin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.validSession(r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			csrf, ok := csrfToken(r, w)
			if !ok {
				web.JSON(w, http.StatusForbidden, web.ErrorResponse{
					Status:  "error",
					Message: "invalid csrf token",
				})
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), csrfKey, csrf))

			next.ServeHTTP(w, r)
		})
	}
}

// Root redirects the user to /login when unauthenticated, otherwise to the
// dashboard.
func (m *Manager) Root() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.validSession(r) {
			http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// Public guards the login/logout routes with CSRF, but no session requirement.
func (m *Manager) Public() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			csrf, ok := csrfToken(r, w)
			if !ok {
				web.JSON(w, http.StatusForbidden, web.ErrorResponse{
					Status:  "error",
					Message: "invalid csrf token",
				})
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), csrfKey, csrf))

			next.ServeHTTP(w, r)
		})
	}
}

func (m *Manager) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	claims, err := m.parseToken(cookie.Value)
	if err != nil {
		return false
	}
	// The jti must still be present in the sessions allowlist; a deleted row
	// (logout) invalidates the token even though its signature is valid.
	expiresAt, err := db.SessionExpiry(m.conn, claims.ID)
	if err != nil {
		return false
	}
	if time.Now().After(expiresAt) {
		_ = db.DeleteSession(m.conn, claims.ID)
		return false
	}
	return true
}

// StartSession creates a session row and sets the signed JWT session cookie.
func (m *Manager) StartSession(w http.ResponseWriter) error {
	jti := newToken()
	expiresAt := time.Now().Add(m.ttl)
	if err := db.CreateSession(m.conn, jti, expiresAt); err != nil {
		return err
	}
	token, err := m.signToken(jti)
	if err != nil {
		_ = db.DeleteSession(m.conn, jti)
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.ttl.Seconds()),
	})
	return nil
}

// EndSession deletes the session row (destroying the token) and clears the
// cookie.
func (m *Manager) EndSession(r *http.Request, w http.ResponseWriter) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if claims, err := m.parseToken(cookie.Value); err == nil {
			_ = db.DeleteSession(m.conn, claims.ID)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (m *Manager) signToken(jti string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(m.key)
}

// parseToken verifies the HS512 signature, pins the algorithm, checks exp,
// and returns the registered claims.
func (m *Manager) parseToken(raw string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.key, nil
	},
		jwt.WithValidMethods([]string{"HS512"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid || claims.ID == "" || claims.Subject != "admin" {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// csrfToken implements the double-submit cookie pattern. On GET it ensures a
// csrf cookie exists (issuing one if absent) and returns the token. On other
// methods it verifies the submitted form value against the cookie.
func csrfToken(r *http.Request, w http.ResponseWriter) (string, bool) {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		cookie = &http.Cookie{Name: csrfCookieName, Value: newToken()}
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    cookie.Value,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
	}

	if r.Method != http.MethodGet {
		// Prefer the header so the body is left untouched for endpoints that
		// stream it (e.g. multipart uploads); fall back to the form field for
		// plain HTML form posts such as login/logout.
		submitted := r.Header.Get("X-CSRF-Token")
		if submitted == "" {
			submitted = r.FormValue("csrf_token")
		}
		if !subtleEquals(cookie.Value, submitted) {
			return "", false
		}
	}
	return cookie.Value, true
}

func subtleEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func CSRFToken(r *http.Request) string {
	token, _ := r.Context().Value(csrfKey).(string)
	return token
}

// TokenID returns a short hex fingerprint (first 3 bytes of the token's
// SHA-256) used to attribute uploads in the audit log without exposing the
// token itself.
func TokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:3])
}

// BearerIdentity is the fingerprint and optional label of the token that
// authenticated an upload request.
type BearerIdentity struct {
	ID    string
	Label string
}

// BearerIdentityFromContext returns the token identity for a request, if any.
func BearerIdentityFromContext(r *http.Request) (BearerIdentity, bool) {
	v, ok := r.Context().Value(bearerKey).(BearerIdentity)
	return v, ok
}
