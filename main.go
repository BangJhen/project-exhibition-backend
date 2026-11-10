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
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/project_exhibition?sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("database connection error: %v", err)
	} else if err = db.Ping(); err != nil {
		log.Printf("database ping failed: %v", err)
	} else {
		log.Println("connected to postgresql database")
	}

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/v1/register", Register)
	mux.HandleFunc("/api/v1/login", Login)

	// Projects
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

	mux.Handle("/api/v1/projects/grade", AuthnMiddleware(
		RequireRole("judge", "admin")(http.HandlerFunc(GetAllProjectGrades)),
	))

	mux.Handle("/api/v1/projects/", AuthnMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/grade") && r.Method == http.MethodPost {
			RequireRole("judge", "admin")(http.HandlerFunc(GradeProject)).ServeHTTP(w, r)
		} else if strings.HasSuffix(path, "/grades") && r.Method == http.MethodGet {
			RequireRole("student", "judge", "admin")(http.HandlerFunc(GetProjectGrades)).ServeHTTP(w, r)
		} else {
			writeJSONError(w, http.StatusNotFound, "endpoint not found")
		}
	})))

	// Compliance
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

	mux.Handle("/api/v1/users/me/export", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(ExportMyData)),
	))

	mux.Handle("/api/v1/users/me/audit-log", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(GetMyAuditLog)),
	))

	mux.Handle("/api/v1/users/me", AuthnMiddleware(
		RequireRole("student", "judge", "admin")(http.HandlerFunc(DeleteMyAccount)),
	))

	// Global middleware chain: Recovery -> AuditLogger -> Router
	handler := RecoveryMiddleware(AuditLoggerMiddleware(mux))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	log.Printf("server running on port %s", port)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

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
		writeJSONError(w, http.StatusBadRequest, "role must be student, judge, or admin")
		return
	}

	if len(req.Password) < 6 {
		writeJSONError(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}

	hashed, err := HashPassword(req.Password)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	userID := "usr-" + uuid.New().String()[:8]
	query := `INSERT INTO users (id, name, email, password_hash, role, created_at, updated_at) 
	          VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`
	_, err = db.Exec(query, userID, req.Name, req.Email, hashed, req.Role)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to register user")
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

	match, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !match {
		writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := GenerateJWT(user.ID, user.Role)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
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
