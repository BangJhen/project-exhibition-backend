# Project Exhibition Backend: Implementasi AAA Framework & Kepatuhan UU No. 27 Tahun 2022

Repositori ini memuat implementasi lengkap backend API berbasis **Golang** dan **PostgreSQL** untuk sistem manajemen pameran proyek (*Project Exhibition*), yang dibangun guna memenuhi penugasan besar mata kuliah **Keamanan Data (CDK3CAB3)**, Program Studi Sarjana Sains Data, School of Computing, Telkom University.

---

## 1. Identitas Kelompok

- **Kelompok**: Kelompok 8
- **Kelas**: Sarjana Sains Data (DS-47-01)
- **Dosen Pengampu**: Pratama Azmi Atmajaya
- **Anggota Tim**:
  1. **Muhamad Alexander**
  2. **Muhammad Ammar Ridho** (103052400009)
  3. **Muflih Rafif Ibrahim**
  4. **Wijdanadam Rafifilmi Nadarosula**

---

## 2. Arsitektur Keamanan Data (AAA Framework) & UU PDP

### A. Authentication (Otentikasi - `authn.go`)
- **Password Hashing Modern (Argon2id)**:
  - Menggunakan algoritma berbasis memori Argon2id untuk menangkal serangan brute-force berbasis GPU/ASIC.
  - Parameter: Salt kriptografis unik 16-byte (`crypto/rand`), iterasi $t=3$, memori $m=64\text{ MB}$, paralelisme $p=2$, dan panjang kunci 32-byte.
  - Verifikasi kata sandi dieksekusi secara *constant-time comparison* (`crypto/subtle`) guna mencegah *timing attacks*.
- **Stateless Session (JSON Web Token / JWT)**:
  - Klaim token memuat identitas `user_id`, `role`, `exp` (masa berlaku 24 jam), dan `iat`.
  - Tanda tangan kriptografis divalidasi menggunakan HMAC-SHA256 (`HS256`).
  - Penolakan otentikasi otomatis menghasilkan HTTP `401 Unauthorized` pada skenario: header kosong, format salah (bukan `Bearer <token>`), tanda tangan rusak/palsu, dan token kedaluwarsa.

### B. Authorization (Otorisasi - `authz.go` & `exhibition.go`)
- **Role-Based Access Control (RBAC)**:
  - Sistem menegakkan hak akses pada 3 peran: `student`, `judge`, dan `admin`.
- **Verifikasi Kepemilikan Objek (Object-Level Ownership Check)**:
  - Pada endpoint `GET /api/v1/projects/{id}/grades`, mahasiswa (`student`) **hanya diizinkan** melihat nilai proyek miliknya sendiri. Akses terhadap nilai proyek mahasiswa lain ditolak dengan HTTP `403 Forbidden`.
  - Mahasiswa **dilarang keras** memberikan nilai pada proyek siapa pun, termasuk proyek miliknya sendiri (`POST /api/v1/projects/{id}/grade` $\rightarrow$ `403 Forbidden`).
  - Peran `judge` dan `admin` memiliki hak untuk melihat dan memberi nilai pada seluruh proyek.

### C. Accountability (Akuntabilitas - `middleware.go`)
- **Non-blocking Asynchronous Audit Logging**:
  - Setiap request ke endpoint terlindungi dicatat ke tabel `audit_logs` (mencatat `user_id`, `endpoint`, `method`, `status_code`, `ip_address`, dan `timestamp`).
  - Pencatatan log dieksekusi secara asinkron menggunakan goroutine latar belakang (`go func(...)`) sehingga latensi respon HTTP ke pengguna sama sekali tidak terhambat.

### D. Kepatuhan UU No. 27 Tahun 2022 (UU PDP - `compliance.go`)
- **`GetMyData` (`GET /api/v1/users/me/data`)**: Memenuhi **Pasal 5 UU PDP** (Hak transparansi identitas dan akses data pribadi). Kolom sensitif `password_hash` secara ketat difilter dan tidak disertakan.
- **`UpdateMyData` (`PUT /api/v1/users/me/data`)**: Memenuhi **Pasal 6 UU PDP** (Hak melengkapi, memperbarui, dan memperbaiki ketidakakuratan data).
- **`GetMyAuditLog` (`GET /api/v1/users/me/audit-log`)**: Memenuhi **Pasal 11 jo. Pasal 31 UU PDP** (Hak akses rekam jejak pemrosesan data & kewajiban Pengendali Data merekam seluruh kegiatan pemrosesan).
- **`ExportMyData` (`GET /api/v1/users/me/export`)**: Memenuhi **Pasal 13 UU PDP** (Hak portabilitas data dalam format terstruktur dan lazim dibaca mesin / *machine-readable* JSON).
- **`DeleteMyAccount` (`DELETE /api/v1/users/me`)**: Memenuhi **Pasal 8 jo. Pasal 43 UU PDP** (Hak pengakhiran pemrosesan dan pemusnahan data / *right to erasure*) via transaksi basis data atomik.

---

## 3. Prasyarat & Panduan Instalasi

### Prasyarat Lingkungan
- Go versi 1.23 atau lebih tinggi
- PostgreSQL versi 14 atau lebih tinggi

### Langkah Setup Basis Data
1. Buat database PostgreSQL:
   ```bash
   createdb project_exhibition
   ```
2. Jalankan skema migrasi tabel:
   ```bash
   psql -U postgres -d project_exhibition -f schema.sql
   ```

### Menjalankan Server Backend
Set environment variable koneksi basis data (opsional jika menggunakan default lokal):
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/project_exhibition?sslmode=disable"
export PORT="8080"
```
Jalankan aplikasi:
```bash
go run .
```
Server akan aktif pada `http://localhost:8080`.

---

## 4. Panduan Pengujian Endpoint API (cURL)

### 1. Registrasi & Login (Public Endpoints)
```bash
# Register Akun Mahasiswa
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Muhammad Ammar Ridho", "email": "ammar@telkom.ac.id", "password": "PasswordAman123!", "role": "student"}'

# Login Akun Mahasiswa
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email": "ammar@telkom.ac.id", "password": "PasswordAman123!"}'
# Ambil nilai "token" dari respon JSON untuk pengujian protected endpoint
```

### 2. Pengujian Autentikasi (Task 1)
```bash
# Skenario 1: Permintaan tanpa header Authorization (Harapan: 401 Unauthorized)
curl -i -X GET http://localhost:8080/api/v1/projects

# Skenario 2: Format header salah (Harapan: 401 Unauthorized)
curl -i -X GET http://localhost:8080/api/v1/projects \
  -H "Authorization: TokenFormatSalah"

# Skenario 3: Token tanda tangan tidak valid / tampered (Harapan: 401 Unauthorized)
curl -i -X GET http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"

# Skenario 4: Token valid (Harapan: 200 OK)
curl -i -X GET http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer <TOKEN_VALID>"
```

### 3. Pengujian Otorisasi & Pameran Proyek (Task 1)
```bash
# Mahasiswa Mengajukan Proyek (Harapan: 201 Created)
curl -X POST http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer <STUDENT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title": "Sistem Keamanan Data Berbasis AAA", "description": "Implementasi otentikasi Argon2id dan JWT pada pameran proyek"}'

# Mahasiswa Mencoba Melihat Nilai Proyek Mahasiswa Lain (Harapan: 403 Forbidden)
curl -i -X GET http://localhost:8080/api/v1/projects/<OTHER_PROJECT_ID>/grades \
  -H "Authorization: Bearer <STUDENT_TOKEN>"

# Mahasiswa Melihat Nilai Proyek Miliknya Sendiri (Harapan: 200 OK)
curl -i -X GET http://localhost:8080/api/v1/projects/<MY_PROJECT_ID>/grades \
  -H "Authorization: Bearer <STUDENT_TOKEN>"
```

### 4. Pengujian Kepatuhan UU PDP (Task 2)
```bash
# 1. Hak Akses Data Diri (Pasal 5)
curl -X GET http://localhost:8080/api/v1/users/me/data \
  -H "Authorization: Bearer <TOKEN_VALID>"

# 2. Hak Perbaikan Data Diri (Pasal 6)
curl -X PUT http://localhost:8080/api/v1/users/me/data \
  -H "Authorization: Bearer <TOKEN_VALID>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Muhammad Ammar Ridho, S.Stat.", "email": "ammar.ridho@telkom.ac.id"}'

# 3. Hak Akses Audit Trail Pemrosesan (Pasal 11 jo. 31)
curl -X GET http://localhost:8080/api/v1/users/me/audit-log \
  -H "Authorization: Bearer <TOKEN_VALID>"

# 4. Hak Portabilitas Data Pribadi (Pasal 13)
curl -X GET http://localhost:8080/api/v1/users/me/export \
  -H "Authorization: Bearer <TOKEN_VALID>"

# 5. Hak Penghapusan Akun & Data (Pasal 8 & 43 - Right to Erasure)
curl -X DELETE http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer <TOKEN_VALID>"
```

---

## 5. Lisensi & Integritas Akademik

Karya ini disusun secara mandiri oleh Kelompok 8 dalam rangka penugasan akademik mata kuliah Keamanan Data (CDK3CAB3) Telkom University. Seluruh logika keamanan dan pemenuhan regulasi hukum dirancang untuk mematuhi integritas kode dan tata kelola privasi data nasional.

