package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func SubmitProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req SubmitProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Description) == "" {
		writeJSONError(w, http.StatusBadRequest, "title and description required")
		return
	}

	projectID := "prj-" + uuid.New().String()[:8]
	query := `INSERT INTO projects (id, owner_id, title, description, created_at, updated_at) 
	          VALUES ($1, $2, $3, $4, NOW(), NOW())`
	_, err = db.Exec(query, projectID, userID, req.Title, req.Description)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to save project")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"project_id": projectID,
		"message":    "project submitted",
	})
}

func ListProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	query := `SELECT id, owner_id, title, description, created_at, updated_at FROM projects ORDER BY created_at DESC`
	rows, err := db.Query(query)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query projects")
		return
	}
	defer rows.Close()

	projects := make([]Project, 0)
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OwnerID, &p.Title, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan project")
			return
		}
		projects = append(projects, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

func GradeProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	judgeID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "grade" {
		writeJSONError(w, http.StatusBadRequest, "invalid url path")
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
		writeJSONError(w, http.StatusInternalServerError, "failed to submit grade")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"grade_id": gradeID,
		"message":  "Grade Submitted",
	})
}

func GetAllProjectGrades(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	query := `SELECT id, project_id, judge_id, score, feedback, created_at FROM grades ORDER BY created_at DESC`
	rows, err := db.Query(query)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query grades")
		return
	}
	defer rows.Close()

	grades := make([]Grade, 0)
	for rows.Next() {
		var g Grade
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.JudgeID, &g.Score, &g.Feedback, &g.CreatedAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan grade")
			return
		}
		grades = append(grades, g)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(grades)
}

func GetProjectGrades(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	userRole, err := GetRole(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "grades" {
		writeJSONError(w, http.StatusBadRequest, "invalid url path")
		return
	}
	projectID := parts[0]

	var ownerID string
	err = db.QueryRow("SELECT owner_id FROM projects WHERE id = $1", projectID).Scan(&ownerID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "project not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Ownership check for student
	if userRole == "student" && ownerID != userID {
		writeJSONError(w, http.StatusForbidden, "forbidden: not project owner")
		return
	}

	query := `SELECT id, project_id, judge_id, score, feedback, created_at FROM grades WHERE project_id = $1 ORDER BY created_at DESC`
	rows, err := db.Query(query, projectID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query grades")
		return
	}
	defer rows.Close()

	grades := make([]Grade, 0)
	for rows.Next() {
		var g Grade
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.JudgeID, &g.Score, &g.Feedback, &g.CreatedAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan grade")
			return
		}
		grades = append(grades, g)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(grades)
}
