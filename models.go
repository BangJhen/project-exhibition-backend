package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User merepresentasikan entitas pengguna dalam sistem.
type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // Tidak boleh diekspos ke respon JSON demi privasi
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserProfileResponse DTO untuk respon profil yang aman (tanpa password hash).
type UserProfileResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Project merepresentasikan proyek pameran yang diajukan oleh mahasiswa.
type Project struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"owner_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Grade merepresentasikan penilaian proyek oleh juri atau admin.
type Grade struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	JudgeID   string    `json:"judge_id"`
	Score     float64   `json:"score"`
	Feedback  string    `json:"feedback"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditLog merepresentasikan catatan jejak akses untuk akuntabilitas.
type AuditLog struct {
	ID         int       `json:"id"`
	UserID     *string   `json:"user_id,omitempty"`
	Endpoint   string    `json:"endpoint"`
	Method     string    `json:"method"`
	StatusCode int       `json:"status_code"`
	IPAddress  string    `json:"ip_address"`
	Timestamp  time.Time `json:"timestamp"`
}

// JWTClaims merepresentasikan klaim sesi stateless JWT.
type JWTClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// Structs untuk Request Payloads
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // student, judge, admin
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SubmitProjectRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type GradeProjectRequest struct {
	Score    float64 `json:"score"`
	Feedback string  `json:"feedback"`
}

type UpdateUserDataRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// ExportUserDataResponse format portabilitas data terstruktur (Pasal 13 UU PDP).
type ExportUserDataResponse struct {
	Profile   UserProfileResponse `json:"profile"`
	Projects  []Project           `json:"projects"`
	Grades    []Grade             `json:"grades"`
	AuditLogs []AuditLog          `json:"audit_logs"`
}

