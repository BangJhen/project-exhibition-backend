package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// SubmitProject menyimpan proyek baru atas nama mahasiswa yang login (POST /api/v1/projects).
// Peran yang diizinkan: student. Respons 201 dengan project_id.
func SubmitProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	var req SubmitProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Description) == "" {
		writeJSONError(w, http.StatusBadRequest, "title and description are required")
		return
	}

	projectID := "prj-" + uuid.New().String()[:8]
	query := `INSERT INTO projects (id, owner_id, title, description, created_at, updated_at) 
	          VALUES ($1, $2, $3, $4, NOW(), NOW())`
	_, err = db.Exec(query, projectID, userID, req.Title, req.Description)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to save project: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"project_id": projectID,
		"message":    "project submitted",
	})
}

// ListProjects mengembalikan daftar seluruh proyek pameran dalam format JSON (GET /api/v1/projects).
// Peran yang diizinkan: seluruh pengguna terautentikasi (student, judge, admin).
func ListProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	query := `SELECT id, owner_id, title, description, created_at, updated_at FROM projects ORDER BY created_at DESC`
	rows, err := db.Query(query)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query projects: "+err.Error())
		return
	}
	defer rows.Close()

	// Pastikan slice selalu terinisialisasi agar mengembalikan [] bukan null dalam JSON
	projects := make([]Project, 0)
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OwnerID, &p.Title, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan project: "+err.Error())
			return
		}
		projects = append(projects, p)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(projects)
}

// GradeProject menyimpan nilai proyek (score, feedback) untuk proyek {id} (POST /api/v1/projects/{id}/grade).
// Peran yang diizinkan: judge, admin. Respons 201 dengan pesan "Grade Submitted".
func GradeProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	judgeID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// Ekstrak ID proyek dari URL path: /api/v1/projects/{id}/grade
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "grade" {
		writeJSONError(w, http.StatusBadRequest, "invalid project grade URL path")
		return
	}
	projectID := parts[0]

	var req GradeProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Score < 0 || req.Score > 100 {
		writeJSONError(w, http.StatusBadRequest, "score must be between 0 and 100")
		return
	}

	// Pastikan proyek yang dinilai ada
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)", projectID).Scan(&exists)
	if err != nil || !exists {
		writeJSONError(w, http.StatusNotFound, "project not found")
		return
	}

	gradeID := "grd-" + uuid.New().String()[:8]
	query := `INSERT INTO grades (id, project_id, judge_id, score, feedback, created_at)
	          VALUES ($1, $2, $3, $4, $5, NOW())`
	_, err = db.Exec(query, gradeID, projectID, judgeID, req.Score, req.Feedback)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to submit grade: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"grade_id": gradeID,
		"message":  "Grade Submitted",
	})
}

// GetAllProjectGrades mengembalikan nilai seluruh proyek dalam format JSON (GET /api/v1/projects/grade).
// Peran yang diizinkan: judge, admin.
func GetAllProjectGrades(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	query := `SELECT id, project_id, judge_id, score, feedback, created_at FROM grades ORDER BY created_at DESC`
	rows, err := db.Query(query)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query grades: "+err.Error())
		return
	}
	defer rows.Close()

	grades := make([]Grade, 0)
	for rows.Next() {
		var g Grade
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.JudgeID, &g.Score, &g.Feedback, &g.CreatedAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan grade: "+err.Error())
			return
		}
		grades = append(grades, g)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(grades)
}

// GetProjectGrades mengembalikan daftar nilai proyek {id} dengan pengecekan kepemilikan eksplisit di handler.
// Endpoint: GET /api/v1/projects/{id}/grades.
// Jika user adalah student dan proyek bukan miliknya, respons 403 Forbidden.
// Jika proyek miliknya atau user adalah judge/admin, respons 200 OK dengan daftar nilai.
func GetProjectGrades(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	userRole, err := GetRoleFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// Ekstrak ID proyek dari URL path: /api/v1/projects/{id}/grades
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "grades" {
		writeJSONError(w, http.StatusBadRequest, "invalid project grades URL path")
		return
	}
	projectID := parts[0]

	// Query pemilik proyek
	var ownerID string
	err = db.QueryRow("SELECT owner_id FROM projects WHERE id = $1", projectID).Scan(&ownerID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "project not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	// Pengecekan kepemilikan objek (Object-Level Ownership Check):
	// Jika user adalah student dan proyek bukan miliknya, tolak dengan 403 Forbidden!
	if userRole == "student" && ownerID != userID {
		writeJSONError(w, http.StatusForbidden, "access denied: you do not own this project")
		return
	}

	// Ambil daftar nilai proyek
	query := `SELECT id, project_id, judge_id, score, feedback, created_at FROM grades WHERE project_id = $1 ORDER BY created_at DESC`
	rows, err := db.Query(query, projectID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query grades: "+err.Error())
		return
	}
	defer rows.Close()

	grades := make([]Grade, 0)
	for rows.Next() {
		var g Grade
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.JudgeID, &g.Score, &g.Feedback, &g.CreatedAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan grade: "+err.Error())
			return
		}
		grades = append(grades, g)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(grades)
}

