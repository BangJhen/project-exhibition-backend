package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

// GetMyData mengembalikan data profil pengguna yang sedang login (GET /api/v1/users/me/data).
// Pemenuhan Pasal 5 UU No. 27 Tahun 2022 (Hak transparansi dan akses data pribadi).
// Atribut PasswordHash secara ketat dikecualikan dari respon.
func GetMyData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
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
		writeJSONError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// UpdateMyData memperbarui data nama dan email pengguna (PUT /api/v1/users/me/data).
// Pemenuhan Pasal 6 UU No. 27 Tahun 2022 (Hak perbaikan dan pemutakhiran data yang tidak akurat).
func UpdateMyData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
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
		writeJSONError(w, http.StatusBadRequest, "name and email cannot be empty")
		return
	}

	query := `UPDATE users SET name = $1, email = $2, updated_at = NOW() WHERE id = $3`
	result, err := db.Exec(query, req.Name, req.Email, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to update user data: "+err.Error())
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
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

// GetMyAuditLog mengembalikan riwayat jejak aktivitas pengguna yang bersangkutan (GET /api/v1/users/me/audit-log).
// Pemenuhan Pasal 11 jo. Pasal 31 UU No. 27 Tahun 2022 (Hak akses riwayat & kewajiban pencatatan Pengendali).
func GetMyAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	query := `SELECT id, user_id, endpoint, method, status_code, ip_address, timestamp 
	          FROM audit_logs WHERE user_id = $1 ORDER BY timestamp DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to query audit logs: "+err.Error())
		return
	}
	defer rows.Close()

	logs := make([]AuditLog, 0)
	for rows.Next() {
		var log AuditLog
		if err := rows.Scan(&log.ID, &log.UserID, &log.Endpoint, &log.Method, &log.StatusCode, &log.IPAddress, &log.Timestamp); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to scan audit log: "+err.Error())
			return
		}
		logs = append(logs, log)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(logs)
}

// ExportMyData mengekspor seluruh data pribadi pengguna dalam format JSON terstruktur (GET /api/v1/users/me/export).
// Pemenuhan Pasal 13 UU No. 27 Tahun 2022 (Hak portabilitas data dalam format machine-readable).
func ExportMyData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	var export ExportUserDataResponse
	export.Projects = make([]Project, 0)
	export.Grades = make([]Grade, 0)
	export.AuditLogs = make([]AuditLog, 0)

	// 1. Ambil Profil Pengguna
	err = db.QueryRow(`SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = $1`, userID).
		Scan(&export.Profile.ID, &export.Profile.Name, &export.Profile.Email, &export.Profile.Role, &export.Profile.CreatedAt, &export.Profile.UpdatedAt)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to export user profile: "+err.Error())
		return
	}

	// 2. Ambil Proyek Milik Pengguna
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

	// 3. Ambil Nilai yang Relevan (diberikan atau diterima)
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

	// 4. Ambil Riwayat Audit Log Pengguna
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
	w.Header().Set("Content-Disposition", "attachment; filename=user_data_export.json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(export)
}

// DeleteMyAccount menghapus akun pengguna dan seluruh data terkait secara permanen (DELETE /api/v1/users/me).
// Pemenuhan Pasal 8 jo. Pasal 43 UU No. 27 Tahun 2022 (Hak penghapusan dan pemusnahan data / right to erasure).
func DeleteMyAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized access")
		return
	}

	// Gunakan transaksi database atomik untuk memastikan penghapusan menyeluruh
	tx, err := db.Begin()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to start database transaction")
		return
	}
	defer tx.Rollback()

	// 1. Putus kaitan data di audit log agar integritas log tetap terjaga namun teranonimkan
	_, err = tx.Exec(`UPDATE audit_logs SET user_id = NULL WHERE user_id = $1`, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to anonymize audit logs: "+err.Error())
		return
	}

	// 2. Hapus data pengguna pada tabel users (Foreign keys projects dan grades terhapus via CASCADE)
	res, err := tx.Exec(`DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to delete user account: "+err.Error())
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		writeJSONError(w, http.StatusNotFound, "user account not found")
		return
	}

	if err := tx.Commit(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to commit transaction: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "account and associated personal data permanently deleted",
	})
}

