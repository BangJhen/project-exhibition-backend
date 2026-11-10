package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {
	// Konfigurasi Database PostgreSQL
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/project_exhibition?sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("[WARNING] Unable to connect to postgres: %v (running in mock/test mode)", err)
	} else if err = db.Ping(); err != nil {
		log.Printf("[WARNING] Database ping failed: %v. Please ensure PostgreSQL is running.", err)
	} else {
		log.Println("[INFO] Successfully connected to PostgreSQL database.")
	}

	// Router Utama
	mux := http.NewServeMux()

	// --- 1. Public Endpoints ---
	mux.HandleFunc("/api/v1/register", Register)
	mux.HandleFunc("/api/v1/login", Login)

	// --- 2. Exhibition Endpoints (AAA Protected) ---
	// GET /api/v1/projects (student, judge, admin)
	// POST /api/v1/projects (student only)
	mux.Handle("/api/v1/projects", AuthnMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			RequireRole("student", "judge", "admin")(http.HandlerFunc(ListProjects)).ServeHTTP(w, r)
		case http.MethodPost:
			RequireRole("student")(http.HandlerFunc(SubmitProject)).ServeHTTP(w, r)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})))

	// GET /api/v1/projects/grade (judge, admin only)
	mux.Handle("/api/v1/projects/grade", AuthnMiddleware(
		RequireRole("judge", "admin")(http.HandlerFunc(GetAllProjectGrades)),
	))

	// Sub-routing untuk /api/v1/projects/{id}/...
	mux.Handle("/api/v1/projects/", AuthnMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/grade") && r.Method == http.MethodPost {
			// POST /api/v1/projects/{id}/grade (judge, admin only)
			RequireRole("judge", "admin")(http.HandlerFunc(GradeProject)).ServeHTTP(w, r)
		} else if strings.HasSuffix(path, "/grades") && r.Method == http.MethodGet {
			// GET /api/v1/projects/{id}/grades (ownership check inside handler)
			RequireRole("student", "judge", "admin")(http.HandlerFunc(GetProjectGrades)).ServeHTTP(w, r)
		} else {
			writeJSONError(w, http.StatusNotFound, "endpoint not found")
		}
	})))

	// --- 3. Compliance Endpoints (UU PDP Protected) ---
	// GET & PUT /api/v1/users/me/data
	mux.Handle("/api/v1/users/me/data", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				GetMyData(w, r)
			case http.MethodPut:
				UpdateMyData(w, r)
			default:
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
		})),
	))

	// GET /api/v1/users/me/export
	mux.Handle("/api/v1/users/me/export", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(ExportMyData)),
	))

	// GET /api/v1/users/me/audit-log
	mux.Handle("/api/v1/users/me/audit-log", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(GetMyAuditLog)),
	))

	// DELETE /api/v1/users/me
	mux.Handle("/api/v1/users/me", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(DeleteMyAccount)),
	))

	// Pasang Pipeline Middleware Global:
	// Request -> Recovery (Panic Safety) -> AuditLogger (Asynchronous non-blocking audit) -> Router/Handlers
	finalHandler := RecoveryMiddleware(AuditLoggerMiddleware(mux))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	log.Printf("[INFO] Server Project Exhibition berjalan pada http://localhost%s", addr)
	if err := http.ListenAndServe(addr, finalHandler); err != nil {
		log.Fatalf("[FATAL] Server gagal berjalan: %v", err)
	}
}

// Register mendaftarkan akun pengguna baru (POST /api/v1/register).
func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	if req.Role != "student" && req.Role != "judge" && req.Role != "admin" {
		writeJSONError(w, http.StatusBadRequest, "role must be one of: student, judge, admin")
		return
	}

	if len(req.Password) < 6 {
		writeJSONError(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}

	// Password Hashing menggunakan Argon2id
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to hash password: "+err.Error())
		return
	}

	userID := "usr-" + uuid.New().String()[:8]
	query := `INSERT INTO users (id, name, email, password_hash, role, created_at, updated_at) 
	          VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`
	_, err = db.Exec(query, userID, req.Name, req.Email, hashedPassword, req.Role)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to register user (email might already exist): "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"user_id": userID,
		"message": "user registered successfully",
	})
}

// Login memvalidasi kredensial dan menerbitkan token JWT stateless (POST /api/v1/login).
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var user User
	query := `SELECT id, name, email, password_hash, role FROM users WHERE email = $1`
	err := db.QueryRow(query, req.Email).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Verifikasi hash Argon2id secara constant-time
	match, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !match {
		writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	// Penerbitan JWT Token Stateless
	token, err := GenerateJWT(user.ID, user.Role)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate session token: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"token":  token,
		"user": map[string]string{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}
