package main

import (
	"context"
	"errors"
	"net/http"
)

// RequireRole middleware otorisasi RBAC (Role-Based Access Control).
// Membatasi akses endpoint hanya untuk peran-peran tertentu (student, judge, admin).
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roleVal := r.Context().Value(ContextKeyRole)
			if roleVal == nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized: missing session role")
				return
			}

			userRole, ok := roleVal.(string)
			if !ok {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized: invalid role context")
				return
			}

			// Pengecekan apakah peran pengguna diizinkan
			isAllowed := false
			for _, allowed := range allowedRoles {
				if userRole == allowed {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				writeJSONError(w, http.StatusForbidden, "forbidden: insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserIDFromContext mengambil user ID dari request context secara aman.
func GetUserIDFromContext(ctx context.Context) (string, error) {
	val := ctx.Value(ContextKeyUserID)
	if val == nil {
		return "", errors.New("missing user id in context")
	}
	id, ok := val.(string)
	if !ok {
		return "", errors.New("invalid user id type")
	}
	return id, nil
}

// GetRoleFromContext mengambil peran pengguna dari request context.
func GetRoleFromContext(ctx context.Context) (string, error) {
	val := ctx.Value(ContextKeyRole)
	if val == nil {
		return "", errors.New("missing role in context")
	}
	role, ok := val.(string)
	if !ok {
		return "", errors.New("invalid role type")
	}
	return role, nil
}

