# Backend Development Notes

Status per 2026-11-16, branch `dev`. Dokumen ini menggantikan bagian
`docs/api.md` yang sudah tidak akurat (dokumen itu masih menjanjikan JWT tanpa
endpoint login, error format JSON yang belum ada, dan path
`/api/auth-credentials`).

## 1. Yang sudah nyata

| Area | Status |
|---|---|
| Persistensi (scan, finding, ticket, user, credential, audit) | GORM + Postgres, query nyata |
| Auth | `POST /api/auth/login` → JWT HS256, middleware di semua route `/api` |
| Otorisasi | RBAC 4 role + ownership check (anti-IDOR) di lapisan aplikasi *dan* query |
| SSRF | validasi URL + validasi IP saat dial + redirect re-check (target & credential URL) |
| CORS | allowlist origin eksak + preflight |
| Error | JSON envelope seragam, pesan internal tidak bocor |
| Kredensial | AES-256-GCM at rest, `config` tidak pernah dikembalikan ke klien |
| Password | bcrypt cost 12, timing uniform untuk user tidak dikenal |
| Rate/limit | body 1 MiB, target ≤ 50, pagination ≤ 100/halaman |
| Mesin scanning | tiap task menjalankan **satu** plugin dari registry embedded (9 plugin); temuan disimpan lewat `CreateBatch` |
| Guard jalur keluar | client hasil `ssrf.Guard.Client` dipakai detector **dan** crawler: IP diperiksa saat dial, redirect divalidasi ulang |
| Batas keluar | budget request per scan (default 60 × jumlah target), rate limit per host (5 rps / burst 10), timeout task dari config |
| Pembatalan | `POST /scans/{id}/cancel` membatalkan context scan, bukan hanya kolom status |

Masih **belum** (jangan diasumsikan jalan): engine headless (selalu error
`ErrHeadlessNotImplemented`), crawl (kode ada, belum dipanggil), WebSocket stream
(501), export/download report (501), template registry endpoint (`[]` — pakai
daftar plugin di bawah), RabbitMQ (ditolak saat startup), frontend-facing
progress realtime.

## 2. Menjalankan

```bash
docker-compose up -d postgres            # Postgres 16 di :5432
export DATABASE_HOST=127.0.0.1
export JWT_SECRET="minimal-32-karakter-ganti-di-produksi"
export CRED_ENC_KEY="kunci-enkripsi-kredensial-ganti"
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='password-kuat-8+'
export CORS_ALLOWED_ORIGINS="http://localhost:5173"
go run .                                  # atau: go build -o bin/sentinel . && ./bin/sentinel
```

Server: `http://localhost:8080`. Skema dibuat otomatis via `AutoMigrate`
(sumber kebenaran: `internal/infrastructure/database/postgres/postgres.go`).
`db/schema.sql` sudah tidak dipakai dan sebaiknya dihapus saat migrasi
ber-versi (golang-migrate) dipasang.

### Environment

| Variabel | Default | Catatan |
|---|---|---|
| `DATABASE_HOST/PORT/USER/PASSWORD/DBNAME/SSLMODE` | localhost/5432/postgres/postgres/vulnscanner/disable | |
| `JWT_SECRET` | acak per boot | minimal 32 karakter; produksi wajib diset |
| `JWT_TTL_MINUTES` | 15 | |
| `CRED_ENC_KEY` | fallback `JWT_SECRET` | kunci enkripsi kredensial |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_EMAIL` | admin / (kosong) / admin@sentinel.local | admin dibuat saat boot jika password diset |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173` | exact match |
| `CORS_ALLOW_CREDENTIALS` | false | |
| `SSRF_ALLOWED_PORTS` | `80,443,8080,8443` | |
| `SSRF_ALLOW_PRIVATE` | false | hanya untuk lab |
| `RABBITMQ_ENABLED` | false | true → **server menolak start**: publisher masih stub dan akan membuang task tanpa error |
| `SCAN_RATE_PER_SECOND` | 5 | batas request per host, dibagi semua worker |
| `SCAN_RATE_BURST` | 10 | |
| `SCAN_MAX_REQUESTS_PER_SCAN` | 0 | 0 → diturunkan dari target × `SCAN_MAX_REQUESTS_PER_TARGET` |
| `SCAN_MAX_REQUESTS_PER_TARGET` | 60 | 38 payload + 2 baseline per target dengan margin |
| `SCAN_MAX_PAYLOADS_PER_PLUGIN` | 20 | |

### Template selectors

`template_selectors` adalah daftar dipisah koma. Satu term cocok bila sama dengan
**id plugin**, **tag**, atau **severity** (tidak peka huruf besar/kecil).
Kosong berarti semua plugin. Term yang tidak dikenal → `400`, bukan scan semua
plugin. Contoh: `xss`, `critical`, `sqli,xss-reflected`.

Plugin yang tersedia (registry embedded `internal/infrastructure/detector/plugins`):
`idor`, `open-redirect`, `path-traversal`, `sql-injection-error`,
`sql-injection-boolean`, `sql-injection-time`, `ssrf`, `xss-reflected`, `xxe`.

### Budget dan pembatalan

Setiap scan mendapat context sendiri dengan budget request. Saat budget habis,
context dibatalkan: task yang sedang berjalan berhenti, scan ditandai
`truncated: true` dan berstatus `completed` (laporan parsial, bukan gagal).
`cancel` memakai jalur yang sama, jadi tidak ada lagi scan berstatus
`cancelled` yang worker-nya masih menembak target.

## 3. Alur auth

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | jq -r .token)

curl -s localhost:8080/api/scans -H "Authorization: Bearer $TOKEN"
```

Semua endpoint `/api/*` (kecuali `/api/auth/login`) butuh Bearer token.
Tanpa token → `401 {"error":{"code":"UNAUTHORIZED",...}}`.

## 4. Endpoint

| Method | Path | Perilaku |
|---|---|---|
| GET | `/health` | publik, tanpa auth |
| POST | `/api/auth/login` | publik, `{username,password}` → `{token,expires_at,user}` |
| GET | `/api/auth/me` | profil pemanggil |
| POST | `/api/scans` | 202 + scan; validasi SSRF; `auth_credential_id` harus milik pemanggil |
| GET | `/api/scans` | pagination `page`,`page_size`,`status`; admin lihat semua |
| GET | `/api/scans/{id}` | 404 jika bukan milik pemanggil |
| POST | `/api/scans/{id}/cancel` | transisi status sah saja |
| GET | `/api/scans/{id}/results` | `?limit=` (maks 1000) |
| GET | `/api/scans/{id}/stream` | 501 (belum diimplementasi) |
| GET/POST | `/api/credentials` | config selalu diredaksi jadi `{"configured":true}` |
| GET/PUT/DELETE | `/api/credentials/{id}` | scoped ke pemilik; milik orang lain → 404/403 |
| POST | `/api/credentials/{id}/verify` | fetch `verify_url` lewat client SSRF-safe |
| GET | `/api/scans/{id}/report-data` | ringkasan severity + findings |
| POST/GET | `/api/scans/{id}/report/export`,`/download` | 501 |
| GET | `/api/templates`, `/api/templates/{id}` | `[]` / 404 (registry belum di-wire) |

Error selalu `{"error":{"code":"...","message":"..."}}` — bukan plain text.

## 5. Kontrol keamanan & lokasi kode

| Kontrol | File |
|---|---|
| JWT issue/verify, actor context | `internal/middleware/auth.go` |
| RBAC + ownership rule | `internal/domain/policy/policy.go` |
| SSRF guard + hardened client | `internal/security/ssrf/guard.go` |
| Enkripsi kredensial | `internal/security/secretbox/secretbox.go` |
| CORS allowlist | `internal/middleware/cors.go` |
| Security headers (CSP, nosniff) | `internal/middleware/security.go` |
| JSON/error envelope + body limit | `internal/httpx/respond.go` |
| Password hashing + timing | `internal/security/passwd/passwd.go` |
| Ownership di query (`FindByIDOwned`, `DeleteOwned`) | `internal/infrastructure/database/postgres/*_repository.go` |

Aturan yang harus dijaga saat menambah endpoint:

1. Ambil actor dari context (`middleware.ActorFrom`), jangan hardcode user ID.
2. Untuk resource milik user, pakai method `*Owned`; 404 untuk resource asing.
3. Setiap URL yang berasal dari user dan di-fetch server wajib lewat `ssrf.Guard`.
4. Jangan pernah `http.Error` — pakai `httpx.Error`/`httpx.ErrorFrom`.
5. Jangan mengembalikan `err.Error()` ke klien; log saja.

## 6. Perbaikan kebocoran yang sudah dikerjakan

- `SessionManager`: mutex + TTL 30 menit + `Sweep` (sebelumnya map tumbuh tanpa batas, tanpa lock).
- `event.Bus.Unsubscribe`: `delete` key saat subscriber terakhir keluar.
- Worker pool: eksekusi memakai `p.ctx` + timeout 30s (sebelumnya `context.Background()`).
- Crawler brute-force: pengiriman task `select` dengan `ctx.Done()` + `close` dijamin.
- Crawler link discovery: drain antrean saat cancel agar `WaitGroup` mencapai nol.

Batas body respons sudah dikerjakan: `detector.MaxResponseBytes` dan
`crawler.MaxBodyBytes` (2 MiB, ditandai `Truncated`). Belum: cleanup temp file PDF
Chromium dan `gofmt` untuk file lama yang tak tersentuh.

## 7. Langkah berikutnya (prioritas)

1. Sambungkan crawl: `crawler.Run` → daftar URL/form → deteksi per hasil.
2. Implementasikan WebSocket di atas `event.Bus` (+ `Unsubscribe` di `defer`).
3. Migrasi ber-versi (golang-migrate) menggantikan `AutoMigrate`; index unik
   parsial `findings(scan_id,target,template_id) WHERE deleted_at IS NULL`
   sudah dibuat lewat tag GORM dan perlu ikut dipindahkan.
4. FK + strategi delete: hapus scan saat ini menghapus findings, tetapi ticket
   yang menunjuk finding tersebut menjadi yatim (lihat §9).
5. Perbaiki test yang masih di-`//go:build ignore` (`messaging_test.go`,
   `websocket_test.go`, `user_repository_test.go`, `headless_engine_test.go`).

## 8. Utang keamanan: CVE dependensi (per 2026-11-16)

`osv-scanner` (advisory di CI) menemukan CVE *module-level* pada:

| Modul | Versi | Perbaikan | Contoh advisory |
|---|---|---|---|
| `golang.org/x/crypto` | 0.51.0 | ≥ 0.56.0 | GO-2026-5023 (CVSS 10.0), GO-2026-6303/6354/6355 |
| `golang.org/x/net` | 0.55.0 | ≥ 0.60.0 / 0.62.0 | GO-2026-6611/6617/6860 |
| `golang.org/x/text` | 0.37.0 | ≥ 0.39.0 / 0.41.0 | GO-2026-5970/6629 |

Semua versi perbaikan menuntut `go >= 1.26`, jadi migrasinya satu paket:

1. Naikkan `go.mod` ke `go 1.26.0` (+ `toolchain go1.26.x`).
2. `go get golang.org/x/{crypto,net,text,sys,sync}@latest`.
3. Migrasikan `.golangci.yml` ke skema golangci-lint **v2** (v1.64 dibangun
   dengan Go 1.25 sehingga menolak menganalisis modul `go 1.26`), lalu ganti
   langkah install lint di CI.
4. CI ikut otomatis karena memakai `go-version-file: go.mod`.

Catatan penting: ini temuan *module-level*, bukan bukti eksploitasi. Dari
`golang.org/x/crypto` kode ini hanya mengimpor `bcrypt`, sehingga permukaan
serangannya jauh lebih kecil daripada daftar advisory. Tetap harus dinaikkan
sebelum rilis.
