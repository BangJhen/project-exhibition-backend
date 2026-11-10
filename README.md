# Project Exhibition Backend

Backend API untuk Project Exhibition menggunakan Golang dan PostgreSQL. Dibuat untuk memenuhi Tugas Kelompok mata kuliah Keamanan Data (CDK3CAB3), S1 Sains Data, Telkom University.

## Tim Pengembang (Kelompok 4)
- **Muhamad Alexander**
- **Muhammad Ammar Ridho** (103052400009)
- **Muflih Rafif Ibrahim**
- **Wijdanadam Rafifilmi Nadarosula**

## Fitur Utama
1. **Authentication (authn.go)**: Password hashing menggunakan Argon2id dan sesi stateless dengan JWT (HS256, 24 jam).
2. **Authorization (authz.go & exhibition.go)**: Role-Based Access Control (RBAC) untuk peran `student`, `judge`, dan `admin`. Dilengkapi pengecekan kepemilikan objek pada nilai proyek mahasiswa.
3. **Accountability (middleware.go)**: Pencatatan jejak audit akses secara asinkron ke tabel `audit_logs` (non-blocking).
4. **Kepatuhan UU PDP (compliance.go)**:
   - `GET /api/v1/users/me/data` (Pasal 5 - Akses Profil)
   - `PUT /api/v1/users/me/data` (Pasal 6 - Perbaikan Data)
   - `GET /api/v1/users/me/audit-log` (Pasal 11 & 31 - Riwayat Audit)
   - `GET /api/v1/users/me/export` (Pasal 13 - Portabilitas Data JSON)
   - `DELETE /api/v1/users/me` (Pasal 8 & 43 - Penghapusan Akun & Data Pribadi)

## Menjalankan Aplikasi

### 1. Inisialisasi Database
Jalankan PostgreSQL lokal, buat database, dan migrasi skema tabel:
```bash
createdb project_exhibition
psql -U postgres -d project_exhibition -f schema.sql
```

### 2. Menjalankan Server
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/project_exhibition?sslmode=disable"
export PORT="8080"
go run .
```

### 3. Menjalankan Unit Test
```bash
go test -v .
```

## Contoh Pengujian Endpoint (cURL)

### Register & Login
```bash
# Register Student
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Ammar Ridho", "email": "ammar@telkom.ac.id", "password": "Password123!", "role": "student"}'

# Login
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email": "ammar@telkom.ac.id", "password": "Password123!"}'
```

### Submit & Grade Proyek
```bash
# Submit Proyek (Student)
curl -X POST http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer <TOKEN_STUDENT>" \
  -H "Content-Type: application/json" \
  -d '{"title": "Exhibition Security System", "description": "Implementasi AAA Framework"}'

# Submit Nilai (Judge)
curl -X POST http://localhost:8080/api/v1/projects/<PROJECT_ID>/grade \
  -H "Authorization: Bearer <TOKEN_JUDGE>" \
  -H "Content-Type: application/json" \
  -d '{"score": 90.5, "feedback": "Implementasi sangat baik"}'

# Cek Nilai (Student hanya bisa lihat miliknya)
curl -X GET http://localhost:8080/api/v1/projects/<PROJECT_ID>/grades \
  -H "Authorization: Bearer <TOKEN_STUDENT>"
```

### Kepatuhan UU PDP
```bash
# Akses Profil
curl -X GET http://localhost:8080/api/v1/users/me/data -H "Authorization: Bearer <TOKEN>"

# Export Data (JSON)
curl -X GET http://localhost:8080/api/v1/users/me/export -H "Authorization: Bearer <TOKEN>"

# Hapus Akun
curl -X DELETE http://localhost:8080/api/v1/users/me -H "Authorization: Bearer <TOKEN>"
```
