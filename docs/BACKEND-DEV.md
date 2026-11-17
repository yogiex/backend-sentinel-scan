# Backend Development Notes

Status per 2026-11-17, branch `dev`. Dokumen ini menggantikan bagian
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
| Rate/limit | body 1 MiB, target ≤ 50, pagination ≤ 100/halaman; login: 5 percobaan per (klien+akun) dan 100 per klien dalam 15 menit, maksimum `GOMAXPROCS` verifikasi bcrypt bersamaan |
| Mesin scanning | tiap task menjalankan **satu** plugin dari registry embedded (7 plugin); temuan disimpan lewat `CreateBatch` |
| Guard jalur keluar | client hasil `ssrf.Guard.Client` dipakai detector **dan** crawler: IP diperiksa saat dial, redirect divalidasi ulang |
| Batas keluar | budget request per scan (default 60 × jumlah target), rate limit per host (5 rps / burst 10), timeout task dari config |
| Pembatalan | `POST /scans/{id}/cancel` membatalkan context scan, bukan hanya kolom status |
| Crawl | `crawl` opsional per scan: link discovery same-domain, `max_depth`/`max_pages`/`robots.txt` benar-benar ditegakkan, URL temuan divalidasi ulang ke kebijakan SSRF |
| Katalog template | `GET /api/templates` mengembalikan 7 plugin yang benar-benar dijalankan (bukan `[]`) |
| Streaming | `GET /scans/{id}/stream` WebSocket nyata: `progress`/`finding`/`complete`/`failed`, ownership dicek sebelum upgrade |
| Tiket remediasi | finding → tiket dengan severity/`scan_id` yang **diturunkan dari finding**, 8 endpoint (list/detail/create/status/assign/komentar/stats/overdue), status 5 tahap + SLA |
| Siklus hidup scan | scan `pending`/`running` yang prosesnya mati ditandai `failed` dengan alasan (`interrupted_by_restart`, `interrupted_by_shutdown`, `heartbeat_lost`); heartbeat 15 detik, ambang 45 detik |
| Integritas hasil | task yang tidak pernah mendapat respons dihitung gagal; semua task gagal → `failed` + `failure_reason=all_tasks_failed`; sebagian gagal → `completed` + `degraded: true` |
| Pencabutan sesi | `POST /api/auth/logout` menaikkan `users.token_version`; setiap request membandingkan versi token dengan baris user, sekaligus memakai role/`is_active` dari DB (bukan dari token) |
| Matcher header | `location: "header"` + `header_name` benar-benar membaca header; `no_redirect: true` menghentikan client di 3xx pertama |

Masih **belum** (jangan diasumsikan jalan): engine headless (selalu error
`ErrHeadlessNotImplemented`), export/download report PDF (501), RabbitMQ
(ditolak saat startup), stream audit log (`/ws/logs`), manajemen user, audit
trail, autoscaling worker.

Plugin `idor` dan `ssrf` **dihapus** (bukan diperbaiki): keduanya mencocokkan
`status 200` yang juga dikembalikan halaman normal. `Plugin.Validate` sekarang
menolak plugin yang satu-satunya bukti adalah status 2xx, jadi bentuk itu tidak
bisa kembali tanpa sengaja.

Catatan batas: crawl **hanya** link discovery. Brute-force path guessing ada di
kode (`BruteForceDiscovery`) tetapi tidak bisa dipilih lewat API, karena satu
submission bisa berubah menjadi ribuan request ke host yang belum tentu milik
pemanggil.

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
| `CRAWLER_MAXDEPTH` | 2 | batas kedalaman link discovery |
| `CRAWLER_MAXPAGES` | 50 | batas halaman per crawl |
| `CRAWLER_CONCURRENCY` | 4 | worker crawl |
| `CRAWLER_RATELIMITMS` | 200 | jeda antar request crawl |
| `CRAWLER_TIMEOUTSEC` | 10 | timeout per request crawl |
| `CRAWLER_MAXDURATIONSEC` | 60 | batas total fase crawl |
| `CRAWLER_RESPECTROBOTS` | true | patuhi robots.txt |
| `CRAWLER_USERAGENT` | `SentinelScan-Crawler/1.0` | |
| `LOGIN_MAX_ATTEMPTS` | 5 | percobaan per (klien+akun) per window; sukses me-reset counter akun |
| `LOGIN_MAX_IP_ATTEMPTS` | 100 | percobaan per klien lintas username (anti password spraying) |
| `LOGIN_WINDOW_SECONDS` | 900 | panjang window throttle |
| `LOGIN_MAX_CONCURRENCY` | `GOMAXPROCS` | jumlah verifikasi bcrypt bersamaan; 0 = default |

### Template selectors

`template_selectors` adalah daftar dipisah koma. Satu term cocok bila sama dengan
**id plugin**, **tag**, atau **severity** (tidak peka huruf besar/kecil).
Kosong berarti semua plugin. Term yang tidak dikenal → `400`, bukan scan semua
plugin. Contoh: `xss`, `critical`, `sqli,xss-reflected`.

Plugin yang tersedia (registry embedded `internal/infrastructure/detector/plugins`):
`open-redirect`, `path-traversal`, `sql-injection-error`, `sql-injection-boolean`,
`sql-injection-time`, `xss-reflected`, `xxe`.

### Crawl

Body `POST /api/scans` boleh membawa objek `crawl`:

```json
{
  "targets": ["https://contoh.test/"],
  "template_selectors": "xss",
  "crawl": {"enabled": true, "max_depth": 1, "max_pages": 20, "respect_robots": true}
}
```

Aturan yang berlaku:

1. `max_depth` 0 → default 2, batas 1..5; `max_pages` 0 → default 50, batas 1..200.
   Di luar rentang → `400`.
2. Crawl **hanya** link discovery, scope same-domain, dan tidak pernah mengirim
   POST/DELETE ke target.
3. Setiap URL hasil crawl divalidasi ulang `ssrf.Guard` sebelum menjadi target;
   host di luar kebijakan dibuang, bukan dipindai (link di HTML target adalah
   input penyerang).
4. Crawl berjalan sebagai fase sendiri (`progress.phase = "crawling"`), lalu
   `scanning`. `total_tasks` baru terisi setelah crawl selesai.
5. Crawl gagal/timeout → scan tetap jalan dengan target yang disubmit
   (graceful degradation).
6. Bila `max_pages` tercapai dan masih ada halaman yang ingin diambil, scan
   ditandai `truncated: true`. Menghabiskan kuota tanpa sisa halaman **tidak**
   dianggap truncated.
7. Request crawl memakai budget scan yang sama, jadi crawl dan pemindaian tidak
   bisa dipakai membanjiri target secara terpisah.

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

Setiap request terautentikasi membaca baris user (PK lookup) untuk memeriksa
`token_version`, `is_active`, dan role. Konsekuensinya:

- `POST /api/auth/logout` mencabut **semua** token user tersebut (bukan hanya
  perangkat yang logout). Token yang dicabut → `401`.
- Menonaktifkan atau menurunkan role user langsung berlaku, tanpa menunggu token
  kedaluwarsa.
- Kalau lookup DB gagal (bukan "user tidak ada"), jawabannya `503`, bukan `401`:
  token yang benar tidak boleh dilaporkan rusak saat DB bermasalah.

## 4. Endpoint

| Method | Path | Perilaku |
|---|---|---|
| GET | `/health` | publik, tanpa auth |
| POST | `/api/auth/login` | publik, `{username,password}` → `{token,expires_at,user}` |
| GET | `/api/auth/me` | profil pemanggil |
| POST | `/api/auth/logout` | 204; mencabut semua token pemanggil |
| POST | `/api/scans` | 202 + scan; validasi SSRF; `auth_credential_id` harus milik pemanggil |
| GET | `/api/scans` | pagination `page`,`page_size`,`status`; admin lihat semua |
| GET | `/api/scans/{id}` | 404 jika bukan milik pemanggil; `degraded`/`truncated`/`failure_reason` ikut di respons |
| POST | `/api/scans/{id}/cancel` | transisi status sah saja |
| GET | `/api/scans/{id}/results` | `?limit=` (maks 1000) |
| GET | `/api/scans/{id}/stream` | WebSocket `{type,data}`; token boleh lewat `?token=` (khusus route ini), `Origin` dicek terhadap allowlist |
| GET | `/api/templates` | 7 plugin dengan filter `severity`,`tag`,`search` |
| GET/POST | `/api/credentials` | config selalu diredaksi jadi `{"configured":true}` |
| GET/PUT/DELETE | `/api/credentials/{id}` | scoped ke pemilik; milik orang lain → 404/403 |
| POST | `/api/credentials/{id}/verify` | fetch `verify_url` lewat client SSRF-safe |
| GET | `/api/scans/{id}/report-data` | ringkasan severity + findings |
| POST/GET | `/api/scans/{id}/report/export`,`/download` | 501 |
| GET | `/api/templates/{id}` | satu plugin, 404 bila tidak ada |
| GET | `/api/tickets` | pagination `page`,`page_size` + filter `status`,`priority`,`severity`,`scan_id`,`assigned_to`,`search`; non-reviewer hanya melihat tiket milik/ditugaskan |
| POST | `/api/tickets` | `{finding_id,title,description,priority?,assigned_to?,due_date?}` → 201; `severity`/`scan_id` diabaikan karena diambil dari finding |
| GET | `/api/tickets/stats` | total per status/prioritas + `overdue` (di-scope seperti list) |
| GET | `/api/tickets/overdue` | tiket lewat `due_date` dan belum selesai |
| GET | `/api/tickets/{id}` | detail + `comments[]`; tiket asing → 404 |
| PATCH | `/api/tickets/{id}/status` | state machine 5 tahap; transisi ilegal → 400 |
| POST | `/api/tickets/{id}/assign` | `{"assigned_to":<id>}` atau `null`; user tidak ada/nonaktif → 400 |
| POST | `/api/tickets/{id}/comments` | `{"message":"..."}` → 201, author dari token |

Error selalu `{"error":{"code":"...","message":"..."}}` — bukan plain text.

## 5. Kontrol keamanan & lokasi kode

| Kontrol | File |
|---|---|
| JWT issue/verify, actor context | `internal/middleware/auth.go` |
| RBAC + ownership rule | `internal/domain/policy/policy.go` |
| SSRF guard + hardened client | `internal/security/ssrf/guard.go` |
| Enkripsi kredensial | `internal/security/secretbox/secretbox.go` |
| CORS allowlist | `internal/middleware/cors.go` |
| Throttle login + batas konkurensi bcrypt | `internal/security/loginguard/guard.go` |
| Pencabutan token (`tv`) + role dari DB | `internal/middleware/auth.go` |
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
- Stream WebSocket: `Subscribe` dilakukan sebelum snapshot ditulis; sebelumnya
  event yang terbit di celah itu hilang dan test menjadi flaky.
- Orchestrator `StopAll`: shutdown kini menulis status + alasan, bukan hanya
  membatalkan context (menyebabkan baris `running` abadi).
- Crawl scope: `<form action>` lintas host dulu dikirim ke hasil **sebelum**
  dicek scope, jadi crawl satu situs bisa menembak host pihak ketiga. Sekarang
  dicek dulu, dan orchestrator menyaring ulang seluruh URL hasil crawl terhadap
  scope sebelum URL menjadi target (dua lapis, karena provider bisa salah).
- Detector: error transport per payload dulu di-`continue`, sehingga target yang
  menolak semua koneksi tampak "bersih". Sekarang jumlah request yang dicoba/
  berhasil/gagal dicatat (`detector.CheckStats`), dan engine mengembalikan
  `ErrNoRequestCompleted` bila tidak ada satu pun respons.
- Orchestrator: scan dengan 100% task gagal dulu ditandai `completed` tanpa
  finding (laporan palsu "tidak ada kerentanan"). Sekarang `failed` +
  `all_tasks_failed`; kegagalan sebagian menandai `degraded: true`.
- Matcher `location: "header"` dulu tidak pernah membaca header (selalu body),
  jadi plugin open-redirect tidak bisa match. Sekarang header dibaca lewat
  `header_name`, dan plugin memakai canary `.invalid` + regex yang di-anchor agar
  redirect internal yang hanya menggemakan URL tidak menjadi false positive.
- Redirect: client produksi (`egress.Transport.Client`) dulu dibuat tanpa
  `CheckRedirect`, sehingga validasi per-hop milik guard hilang dan port
  allowlist bisa dilewati. Kebijakan itu dipasang kembali di `main.go`.
- Login: tidak ada throttle. Sekarang `loginguard` membatasi per klien dan per
  akun, membatasi verifikasi bcrypt bersamaan, dan menjaga tabel counter tetap
  berbatas ukuran.
- Token: tidak bisa dicabut. Sekarang `users.token_version` + endpoint logout;
  role dan `is_active` juga diambil dari DB, bukan dari claim token.
- `last_login`: dulu menulis ulang seluruh baris user, sehingga login yang
  sedang berjalan bisa mengembalikan role/nonaktif yang baru diubah. Sekarang
  hanya kolom `last_login`.

Batas body respons sudah dikerjakan: `detector.MaxResponseBytes` dan
`crawler.MaxBodyBytes` (2 MiB, ditandai `Truncated`). Belum: cleanup temp file PDF
Chromium dan `gofmt` untuk file lama yang tak tersentuh.

## 7. Langkah berikutnya (prioritas)

1. Migrasi ber-versi (golang-migrate) menggantikan `AutoMigrate`; index unik
   parsial `findings(scan_id,target,template_id) WHERE deleted_at IS NULL`
   sudah dibuat lewat tag GORM dan perlu ikut dipindahkan.
2. FK + strategi delete: hapus scan saat ini menghapus findings, tetapi ticket
   yang menunjuk finding tersebut menjadi yatim (lihat §6, utang DB).
3. Report PDF (`report/generator.go` masih struct kosong; `chromedp` belum jadi
   dependency) + cleanup temp file Chromium.
4. Perbaiki test yang masih di-`//go:build ignore` (`messaging_test.go`,
   `websocket_test.go`, `user_repository_test.go`, `headless_engine_test.go`).
5. ~~Rekonsiliasi scan zombie~~ **selesai**: boot sweep, shutdown sweep, dan
   heartbeat 15 detik/ambang 45 detik (`orchestrator/lifecycle.go`). Sisa
   terkait: kolom `failure_reason`/`heartbeat_at` baru ada lewat `AutoMigrate`,
   jadi ikut dipindahkan ke migrasi ber-versi pada butir 1.
6. Manajemen user (create/list/nonaktifkan/reset/role) + audit trail. Tanpa ini
   `user:manage` hanya dekorasi dan operator bergantung pada SQL manual.
7. `/readyz` yang memeriksa DB + registry plugin, `slog` + request ID, metrics.
8. Literasi utang test: 10 file `//go:build ignore` (119 test) dan `test/e2e`
   yang tidak compile. E2E tidak pernah jalan di CI.
9. Dead code: paket legacy `db/`, `detection/`, `event/`, `worker/`, `template/`
   di root masih ikut build dan test; binary 21 MB `vulnerability-scanner` masih
   ter-commit.

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
