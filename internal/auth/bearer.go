package auth

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
	"github.com/encrypt0r/ingestor/internal/web"
)

// Bearer guards the upload API. Per-user tokens are looked up by digest;
// legacy tokens from .env remain valid and upload to unowned storage. The
// matched token's fingerprint and owner are attached to the request context.
func Bearer(cfg *config.Config, conn *sql.DB, auditLog *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerFromHeader(r.Header.Get("Authorization"))

			// Single-user mode ignores per-user tokens; only the legacy .env
			// token list is honored, matching the pre-multi-user release.
			if !cfg.SingleUser() {
				if u, ok := users.AuthenticateToken(conn, token); ok {
					id := BearerIdentity{ID: TokenID(token), Label: u.Username, UserID: u.ID}
					ctx := identity.WithUser(r.Context(), u)
					ctx = context.WithValue(ctx, bearerKey, id)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			if matched, ok := cfg.AuthenticateBearer(token); ok {
				id := BearerIdentity{ID: TokenID(matched.Token), Label: matched.Label}
				ctx := identity.WithUser(r.Context(), identity.User{Role: identity.RoleLegacy})
				ctx = context.WithValue(ctx, bearerKey, id)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			auditLog.BearerFailed(r, r.URL.Path)
			web.JSON(w, http.StatusUnauthorized, web.ErrorResponse{
				Status:  "error",
				Message: "unauthorized",
			})
		})
	}
}

func bearerFromHeader(header string) string {
	const prefix = "Bearer "
	if len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
