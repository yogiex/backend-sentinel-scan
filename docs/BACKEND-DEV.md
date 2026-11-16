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

Masih **belum** (jangan diasumsikan jalan): engine HTTP/headless (stub),
WebSocket stream (501), export/download report (501), template registry (`[]`),
worker/RabbitMQ (stub), frontend-facing progress realtime.

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
| `RABBITMQ_ENABLED` | false | true → mode RabbitMQ (masih stub) |

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

Belum dikerjakan: batas ukuran body respons di `detector/executor.go` dan
`crawler/fetcher.go` (`io.ReadAll` masih unbounded), cleanup temp file PDF
Chromium, dan `gofmt` untuk file lama yang tak tersentuh.

## 7. Langkah berikutnya (prioritas)

1. Wire `HTTPEngine.Execute` ke `detector` + `crawler` yang sudah ada, lalu
   simpan finding via `findingRepo.CreateBatch`.
2. Implementasikan WebSocket di atas `event.Bus` (+ `Unsubscribe` di `defer`).
3. Ganti `io.ReadAll` dengan `io.LimitReader` + `resp.Body.Close()` yang konsisten.
4. Migrasi ber-versi (golang-migrate) menggantikan `AutoMigrate`.
5. Perbaiki test yang tidak dapat dikompilasi (`messaging_test.go`,
   `websocket_test.go`, `user_repository_test.go`, `headless_engine_test.go`).
