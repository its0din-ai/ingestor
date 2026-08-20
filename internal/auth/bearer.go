package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/web"
)

func Bearer(cfg *config.Config, auditLog *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerFromHeader(r.Header.Get("Authorization"))
			expected := cfg.BearerToken()
			if expected == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
				auditLog.BearerFailed(logging.ClientIP(r), r.URL.Path)
				web.JSON(w, http.StatusUnauthorized, web.ErrorResponse{
					Status:  "error",
					Message: "unauthorized",
				})
				return
			}
			next.ServeHTTP(w, r)
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
