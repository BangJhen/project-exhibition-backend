package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestArgon2idHashing menguji keandalan password hashing dan verifikasi kata sandi.
func TestArgon2idHashing(t *testing.T) {
	rawPassword := "PasswordMahasiswa2026!"

	// 1. Uji Hashing
	hash, err := HashPassword(rawPassword)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected hash to start with $argon2id$, got: %s", hash)
	}

	// 2. Uji Verifikasi Kata Sandi Benar
	match, err := VerifyPassword(rawPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed with error: %v", err)
	}
	if !match {
		t.Fatalf("expected password to match hash")
	}

	// 3. Uji Verifikasi Kata Sandi Salah
	matchWrong, err := VerifyPassword("PasswordSalah123", hash)
	if err != nil {
		t.Fatalf("VerifyPassword on wrong password failed: %v", err)
	}
	if matchWrong {
		t.Fatalf("expected wrong password to not match")
	}
}

// TestJWTLifecycle menguji penerbitan, verifikasi tanda tangan, dan penanganan kedaluwarsa token.
func TestJWTLifecycle(t *testing.T) {
	userID := "usr-student-001"
	role := "student"

	// 1. Uji Token Valid
	tokenStr, err := GenerateJWT(userID, role)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	claims, err := ValidateJWT(tokenStr)
	if err != nil {
		t.Fatalf("ValidateJWT failed for valid token: %v", err)
	}

	if claims.UserID != userID || claims.Role != role {
		t.Fatalf("expected userID=%s and role=%s, got userID=%s, role=%s", userID, role, claims.UserID, claims.Role)
	}

	// 2. Uji Token dengan Tanda Tangan Palsu (Tampered Signature)
	parts := strings.Split(tokenStr, ".")
	if len(parts) == 3 {
		tamperedSig := parts[2] + "tampered"
		tamperedToken := parts[0] + "." + parts[1] + "." + tamperedSig
		_, err := ValidateJWT(tamperedToken)
		if err == nil {
			t.Fatalf("expected error for tampered token signature, got nil")
		}
	}

	// 3. Uji Token Kedaluwarsa (Expired Token)
	expiredClaims := &JWTClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Kedaluwarsa 1 jam lalu
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	expiredTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenStr, _ := expiredTokenObj.SignedString(jwtSecretKey)

	_, errExpiredToken := ValidateJWT(expiredTokenStr)
	if errExpiredToken == nil || !strings.Contains(errExpiredToken.Error(), "expired") {
		t.Fatalf("expected token expired error, got: %v", errExpiredToken)
	}
}

// TestAuthnMiddleware menguji seluruh 5 skenario otentikasi sesuai laporan Task 1.
func TestAuthnMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "authenticated"}`))
	})

	handler := AuthnMiddleware(testHandler)

	// Skenario 1: Permintaan tanpa header Authorization
	t.Run("Skenario 1: Tanpa Header Authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// Skenario 2: Format header salah (tanpa Bearer prefix)
	t.Run("Skenario 2: Format Header Salah", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// Skenario 3: Token kedaluwarsa
	t.Run("Skenario 3: Token Kedaluwarsa", func(t *testing.T) {
		expiredClaims := &JWTClaims{
			UserID: "usr-01",
			Role:   "student",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
			},
		}
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims).SignedString(jwtSecretKey)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// Skenario 4: Token dengan tanda tangan tidak valid
	t.Run("Skenario 4: Tanda Tangan Tidak Valid", func(t *testing.T) {
		claims := &JWTClaims{
			UserID: "usr-01",
			Role:   "student",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		// Ditandatangani dengan kunci rahasia lain yang tidak sah
		wrongKey := []byte("kunci-rahasia-palsu-penyerang")
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(wrongKey)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// Skenario 5: Token valid
	t.Run("Skenario 5: Token Valid", func(t *testing.T) {
		tok, _ := GenerateJWT("usr-01", "student")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})
}

// TestAuthzMiddleware menguji penegakan Role-Based Access Control (RBAC).
func TestAuthzMiddleware(t *testing.T) {
	dummyNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access": "granted"}`))
	})

	// Endpoint khusus judge dan admin
	judgeOnlyHandler := RequireRole("judge", "admin")(dummyNext)

	// Skenario: Student mencoba mengakses endpoint judge
	t.Run("Student mengakses endpoint judge (Harus 403 Forbidden)", func(t *testing.T) {
		tok, _ := GenerateJWT("usr-std", "student")
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/grade", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()

		// Jalankan AuthnMiddleware lalu Authz
		AuthnMiddleware(judgeOnlyHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
	})

	// Skenario: Judge mengakses endpoint judge
	t.Run("Judge mengakses endpoint judge (Harus 200 OK)", func(t *testing.T) {
		tok, _ := GenerateJWT("usr-jdg", "judge")
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/grade", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()

		AuthnMiddleware(judgeOnlyHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})
}
