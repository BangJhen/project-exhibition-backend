package main

import (
	"context"
	"errors"
	"net/http"
)

func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			val := r.Context().Value(ContextRole)
			if val == nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			userRole, ok := val.(string)
			if !ok {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			allowed := false
			for _, r := range allowedRoles {
				if userRole == r {
					allowed = true
					break
				}
			}

			if !allowed {
				writeJSONError(w, http.StatusForbidden, "forbidden: insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func GetUserID(ctx context.Context) (string, error) {
	val := ctx.Value(ContextUserID)
	if val == nil {
		return "", errors.New("missing user id")
	}
	id, ok := val.(string)
	if !ok {
		return "", errors.New("invalid user id")
	}
	return id, nil
}

func GetRole(ctx context.Context) (string, error) {
	val := ctx.Value(ContextRole)
	if val == nil {
		return "", errors.New("missing role")
	}
	role, ok := val.(string)
	if !ok {
		return "", errors.New("invalid role")
	}
	return role, nil
}
