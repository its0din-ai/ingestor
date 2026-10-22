// Package identity carries the authenticated user through a request context.
// It is a leaf package so both auth and audit can use it without an import
// cycle.
package identity

import (
	"context"
	"net/http"
)

const (
	RoleSuperadmin = "superadmin"
	RoleUser       = "user"
	// RoleLegacy marks uploads authenticated by the global bearer tokens that
	// were configured before multi-user support. They are owned by nobody.
	RoleLegacy = "legacy"
)

type User struct {
	ID       int64
	Username string
	Role     string
}

func (u User) IsSuperadmin() bool {
	return u.Role == RoleSuperadmin
}

func (u User) IsUser() bool {
	return u.Role == RoleUser
}

type ctxKey int

const userKey ctxKey = 0

func WithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func FromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey).(User)
	return u, ok
}

func FromRequest(r *http.Request) (User, bool) {
	return FromContext(r.Context())
}
