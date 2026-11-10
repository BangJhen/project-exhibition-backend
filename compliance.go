package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

func GetMyData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var user UserProfileResponse
	query := `SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = $1`
	err = db.QueryRow(query, userID).Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "user profile not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func UpdateMyData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req UpdateUserDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if req.Name == "" || req.Email == "" {
		writeJSONError(w, http.StatusBadRequest, "name and email required")
		return
	}

	query := `UPDATE users SET name = $1, email = $2, updated_at = NOW() WHERE id = $3`
	res, err := db.Exec(query, req.Name, req.Email, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to update user data")
		return
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "data updated successfully",
		"user": map[string]string{
			"id":    userID,
			"name":  req.Name,
			"email": req.Email,
		},
	})
}

func GetMyAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	query := `SELECT id, user_id, endpoint, method, status_code, ip_address, timestamp 
	          FROM audit_logs WHERE user_id = $1 ORDER BY timestamp DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query audit logs")
		return
	}
	defer rows.Close()

	logs := make([]AuditLog, 0)
	for rows.Next() {
		var log AuditLog
		if err := rows.Scan(&log.ID, &log.UserID, &log.Endpoint, &log.Method, &log.StatusCode, &log.IPAddress, &log.Timestamp); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan log")
			return
		}
		logs = append(logs, log)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func ExportMyData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var export ExportUserDataResponse
	export.Projects = make([]Project, 0)
	export.Grades = make([]Grade, 0)
	export.AuditLogs = make([]AuditLog, 0)

	err = db.QueryRow(`SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = $1`, userID).
		Scan(&export.Profile.ID, &export.Profile.Name, &export.Profile.Email, &export.Profile.Role, &export.Profile.CreatedAt, &export.Profile.UpdatedAt)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to export profile")
		return
	}

	projRows, err := db.Query(`SELECT id, owner_id, title, description, created_at, updated_at FROM projects WHERE owner_id = $1`, userID)
	if err == nil {
		defer projRows.Close()
		for projRows.Next() {
			var p Project
			if err := projRows.Scan(&p.ID, &p.OwnerID, &p.Title, &p.Description, &p.CreatedAt, &p.UpdatedAt); err == nil {
				export.Projects = append(export.Projects, p)
			}
		}
	}

	gradeRows, err := db.Query(`SELECT g.id, g.project_id, g.judge_id, g.score, g.feedback, g.created_at 
	                           FROM grades g 
	                           JOIN projects p ON g.project_id = p.id 
	                           WHERE p.owner_id = $1 OR g.judge_id = $1`, userID)
	if err == nil {
		defer gradeRows.Close()
		for gradeRows.Next() {
			var g Grade
			if err := gradeRows.Scan(&g.ID, &g.ProjectID, &g.JudgeID, &g.Score, &g.Feedback, &g.CreatedAt); err == nil {
				export.Grades = append(export.Grades, g)
			}
		}
	}

	auditRows, err := db.Query(`SELECT id, user_id, endpoint, method, status_code, ip_address, timestamp FROM audit_logs WHERE user_id = $1`, userID)
	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			var l AuditLog
			if err := auditRows.Scan(&l.ID, &l.UserID, &l.Endpoint, &l.Method, &l.StatusCode, &l.IPAddress, &l.Timestamp); err == nil {
				export.AuditLogs = append(export.AuditLogs, l)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=user_export.json")
	json.NewEncoder(w).Encode(export)
}

func DeleteMyAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserID(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE audit_logs SET user_id = NULL WHERE user_id = $1`, userID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to anonymize logs")
		return
	}

	res, err := tx.Exec(`DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	if err := tx.Commit(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "account and associated personal data deleted successfully",
	})
}
