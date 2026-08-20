package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/web"
)

const (
	sessionCookieName = "admin_session"
	csrfCookieName    = "csrf_token"
	sessionTTL        = 24 * time.Hour
)

type ctxKey int

const csrfKey ctxKey = 0

// Admin guards the dashboard routes: session cookie required and CSRF check
// on mutating requests.
func Admin(conn *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !validSession(conn, r) {
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
func Root(conn *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if validSession(conn, r) {
			http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// Public guards the login/logout routes with CSRF, but no session requirement.
func Public(conn *sql.DB) func(http.Handler) http.Handler {
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

func validSession(conn *sql.DB, r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	expiresAt, err := db.SessionExpiry(conn, cookie.Value)
	if err != nil {
		return false
	}
	if time.Now().After(expiresAt) {
		_ = db.DeleteSession(conn, cookie.Value)
		return false
	}
	return true
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
		submitted := r.FormValue("csrf_token")
		if submitted == "" {
			submitted = r.Header.Get("X-CSRF-Token")
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

func StartSession(conn *sql.DB, w http.ResponseWriter) error {
	id := newToken()
	if err := db.CreateSession(conn, id, time.Now().Add(sessionTTL)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return nil
}

func EndSession(conn *sql.DB, r *http.Request, w http.ResponseWriter) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = db.DeleteSession(conn, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func CSRFToken(r *http.Request) string {
	token, _ := r.Context().Value(csrfKey).(string)
	return token
}
