package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
)

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v", rec)
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func AuditLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapper, r)

		endpoint := r.URL.Path
		method := r.Method
		statusCode := wrapper.statusCode
		clientIP := getClientIP(r)

		var userIDPtr *string
		if val := r.Context().Value(ContextUserID); val != nil {
			if idStr, ok := val.(string); ok && idStr != "" {
				userIDPtr = &idStr
			}
		}

		// Asynchronous audit log insertion
		go func(uid *string, ep, m string, sc int, ip string) {
			if db == nil {
				return
			}
			query := `INSERT INTO audit_logs (user_id, endpoint, method, status_code, ip_address, timestamp) 
			          VALUES ($1, $2, $3, $4, $5, NOW())`
			_, _ = db.Exec(query, uid, ep, m, sc, ip)
		}(userIDPtr, endpoint, method, statusCode, clientIP)
	})
}

func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return strings.TrimSpace(rip)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
