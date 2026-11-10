package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
)

// responseWriterWrapper pembungkus ResponseWriter untuk merekam status code HTTP.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// writeJSONError menulis pesan error terstandarisasi dalam format JSON.
func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// RecoveryMiddleware menangani panic secara anggun agar server tetap stabil.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC RECOVERED] %v", rec)
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// AuditLoggerMiddleware merekam seluruh interaksi endpoint ke tabel audit_logs.
// Bersifat asinkron dan non-blocking (via goroutine) demi performa latensi tinggi.
func AuditLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrappedWriter := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // default jika WriteHeader tidak dipanggil eksplisit
		}

		next.ServeHTTP(wrappedWriter, r)

		// Ekstraksi metadata request
		endpoint := r.URL.Path
		method := r.Method
		statusCode := wrappedWriter.statusCode
		clientIP := getClientIP(r)

		var userIDPtr *string
		if val := r.Context().Value(ContextKeyUserID); val != nil {
			if idStr, ok := val.(string); ok && idStr != "" {
				userIDPtr = &idStr
			}
		}

		// Eksekusi pencatatan asinkronus (non-blocking) ke database
		go func(uid *string, ep, m string, sc int, ip string) {
			if db == nil {
				return
			}
			query := `INSERT INTO audit_logs (user_id, endpoint, method, status_code, ip_address, timestamp) 
			          VALUES ($1, $2, $3, $4, $5, NOW())`
			_, err := db.Exec(query, uid, ep, m, sc, ip)
			if err != nil {
				log.Printf("[AUDIT ERROR] failed to write audit log: %v", err)
			}
		}(userIDPtr, endpoint, method, statusCode, clientIP)
	})
}

// getClientIP mengambil IP asli klien termasuk jika berada di balik reverse proxy.
func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

