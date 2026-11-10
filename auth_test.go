package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestArgon2idHashing(t *testing.T) {
	password := "Password123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected $argon2id$ prefix, got: %s", hash)
	}

	match, err := VerifyPassword(password, hash)
	if err != nil || !match {
		t.Fatalf("expected password to match hash")
	}

	wrongMatch, _ := VerifyPassword("WrongPassword", hash)
	if wrongMatch {
		t.Fatalf("expected wrong password to not match")
	}
}

func TestJWTLifecycle(t *testing.T) {
	userID := "usr-001"
	role := "student"

	tokenStr, err := GenerateJWT(userID, role)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	claims, err := ValidateJWT(tokenStr)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if claims.UserID != userID || claims.Role != role {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Tampered token test
	parts := strings.Split(tokenStr, ".")
	if len(parts) == 3 {
		tampered := parts[0] + "." + parts[1] + ".invalidSig"
		if _, err := ValidateJWT(tampered); err == nil {
			t.Fatalf("expected error for tampered token")
		}
	}

	// Expired token test
	expiredClaims := &JWTClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	expiredToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims).SignedString(jwtKey)
	if _, err := ValidateJWT(expiredToken); err == nil {
		t.Fatalf("expected error for expired token")
	}
}

func TestAuthnMiddleware(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := AuthnMiddleware(nextHandler)

	// Missing header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	// Invalid format
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	req.Header.Set("Authorization", "InvalidHeader")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	// Valid token
	token, _ := GenerateJWT("usr-001", "student")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAuthzMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	judgeOnly := RequireRole("judge", "admin")(next)

	// Student access
	token, _ := GenerateJWT("usr-std", "student")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/grade", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	AuthnMiddleware(judgeOnly).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	// Judge access
	token, _ = GenerateJWT("usr-jdg", "judge")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/grade", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()

	AuthnMiddleware(judgeOnly).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
