# Changelog

Semua perubahan penting pada backend SentinelScan dicatat di sini.

Format mengikuti [Keep a Changelog](https://keepachangelog.com/id/1.1.0/),
versi mengikuti [Semantic Versioning](https://semver.org/lang/id/).

## Cara mencatat perubahan

1. Setiap perubahan masuk ke bagian `## [Unreleased]` pada kategori yang sesuai.
2. Kategori yang dipakai: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
   `Security`, `CI`, `Docs`. Hapus kategori yang kosong saat rilis.
3. Setiap entri diawali lingkup dalam kurung siku, mis. `[scan]`, `[auth]`,
   `[persistence]`, `[ci]`.
4. Saat rilis: ganti `Unreleased` menjadi versi + tanggal (`## [0.2.0] - 2026-11-16`),
   buat bagian `Unreleased` baru yang kosong, lalu `git tag v0.2.0`.
5. Referensikan commit/issue bila membantu penelusuran: `([f8f4c03])`.

---

## [Unreleased]

### Added

- **[scan]** Mesin scanning benar-benar menembak target: `HTTPEngine` menjadi
  adapter yang menjalankan **satu** plugin per task dari registry embedded
  (`RunWithPlugins` + `Registry.Get`), lalu memetakan hasilnya ke `Finding`.
  Sebelumnya `Execute` mengembalikan `Matched: false` tanpa satu pun request.
- **[scan]** Enumerasi task dari `detector.Registry` (9 plugin) menggantikan
  `template.Loader` yang membaca `./templates` kosong, sehingga `total_tasks`
  tidak lagi nol dan scan dapat mencapai `completed`.
- **[scan]** `template_selectors` benar-benar memfilter: satu term cocok dengan
  id plugin, tag, atau severity; term tak dikenal → `400`; kosong → semua plugin.
- **[security]** `internal/security/egress`: budget request per scan (lewat
  context) dan rate limiter token-bucket per host yang dibagi semua worker.
- **[security]** Detector dan crawler memakai client dari `ssrf.Guard.Client`,
  jadi pemeriksaan IP saat dial dan validasi ulang redirect berlaku untuk
  seluruh trafik scan — bukan hanya validasi URL saat submit.
- **[persistence]** Index unik parsial `findings(scan_id, target, template_id)
  WHERE deleted_at IS NULL` + `ON CONFLICT ... DO NOTHING` bertarget, membuat
  penyimpanan temuan idempoten; `scan_jobs.truncated` untuk laporan parsial.
- **[scan]** `PATCH/POST /scans/{id}/cancel` kini membatalkan context scan;
  setiap scan punya context sendiri (`worker.Task.Ctx`) dan `orchestrator.Cancel`.
- **[docs]** `docs/BACKEND-DEV.md`: tata bahasa selector, tabel budget, status
  engine, dan sisa pekerjaan yang diperbarui.

### Changed

- **[scan]** Orchestrator menjadi satu-satunya penulis finding: result worker
  dipersist via `CreateBatch` di dispatch loop, worker tetap tanpa akses DB.
- **[scan]** Timeout task diambil dari `worker.task_timeout` (bukan konstanta
  30 detik), dan tiap request dibatasi `detector.MaxResponseBytes` /
  `crawler.MaxBodyBytes` (2 MiB) dengan penanda `Truncated`.
- **[security]** `RABBITMQ_ENABLED=true` sekarang **menggagalkan startup**:
  publisher masih stub dan akan membuang task tanpa error.
- **[scan]** `HeadlessEngine` mengembalikan `ErrHeadlessNotImplemented` alih-alih
  "tidak ada temuan", supaya scan headless tidak tampak bersih.

### Fixed

- **[scan]** Template `idor` dan `path-traversal` memakai path tanpa `?`
  (`/api/users/FUZZ&id=FUZZ`), sehingga semua parameter setelah `&` menjadi
  bagian path dan tiga dari empat titik injeksi tidak pernah diuji.
- **[scan]** Payload tidak lagi disisipkan mentah ke URL: karakter `&`, `#`, dan
  spasi di-encode persen (URL) sementara body tetap mentah agar payload XXE utuh.
- **[scan]** `Registry.LoadFromDir` membaca file disk dari filesystem embedded
  sehingga tidak pernah memuat apa pun; kini memakai `os.ReadFile` dan
  mengembalikan error parsing alih-alih melewatinya diam-diam.
- **[scan]** `Plugin.Validate` menolak method/severity/matcher tak dikenal,
  payload kosong, id tidak valid, dan baseline yang mengandung `FUZZ`.

### Security

- **[scan]** Redirect dari target menuju `169.254.169.254`, `127.0.0.1`, atau
  `10.0.0.0/8` kini gagal di lapisan dial; sebelumnya diikuti sampai 10 hop.
- **[scan]** Respons target dibatasi 2 MiB untuk mencegah kehabisan memori worker.
- **[scan]** Budget request membatasi volume keluar per scan (default 60 × target),
  sehingga scan tidak bisa dipakai membanjiri target.

### Tests

- **[scan]** Test baru: budget/rate egress, validasi plugin, encoding payload,
  batas body, resolusi selector, engine satu-plugin-per-task, guard redirect
  metadata, serta alur orchestrator (progress, persistensi, cancel, truncated).

## [0.2.0] - 2026-11-16

Rilis ini mengubah backend dari kerangka (semua repositori dan use case berupa
stub yang mengembalikan data palsu) menjadi layanan yang benar-benar menyimpan
data, mengautentikasi pengguna, dan menolak permintaan berbahaya.

### Added

- **[persistence]** Repositori GORM nyata untuk `scan_jobs`, `findings`,
  `tickets`, `users`, `auth_credentials`, `auth_logs` — menggantikan seluruh
  implementasi `return nil`. Model dipisah ke `postgres.go` (model + mapping)
  dan satu berkas per agregat (`scan_repository.go`, dst).
- **[persistence]** State machine status scan dengan compare-and-swap
  (`pending → running → completed/failed/cancelled`); transisi ilegal
  menghasilkan `409 CONFLICT`.
- **[persistence]** Progres scan disimpan sebagai kolom integer
  (`total_tasks`, `completed_tasks`, `failed_tasks`, `in_progress_tasks`)
  agar aman dari lost update saat banyak worker menulis bersamaan.
- **[persistence]** Penulisan finding per batch 500 baris dalam satu transaksi,
  dengan de-duplikasi `(target, template)` di dalam batch.
- **[scan]** `GET /api/scans` (paginasi `page`, `page_size`, filter `status`,
  `X-Total` lewat `total` di body), `POST /api/scans/{id}/cancel`.
- **[auth]** `POST /api/auth/login` menerbitkan JWT HS256 (TTL default 15 menit)
  dan `GET /api/auth/me`. Middleware `Require` melindungi seluruh `/api/*`.
- **[auth]** Bootstrap admin dari environment (`ADMIN_USERNAME`,
  `ADMIN_PASSWORD`, `ADMIN_EMAIL`) saat start.
- **[security]** Paket `internal/domain/policy`: RBAC 4 role
  (`admin`, `security_analyst`, `auditor`, `viewer`) dengan *deny by default*,
  plus aturan kepemilikan `CanAccessOwner`.
- **[security]** SSRF guard (`internal/security/ssrf`): allowlist skema
  (http/https) dan port, blokir loopback/private/link-local/CGNAT/multicast/
  IPv6 ULA, validasi IP **saat dial** (anti DNS rebinding), batas redirect,
  dan klien tanpa proxy environment.
- **[security]** Enkripsi kredensial at rest (AES-256-GCM,
  `internal/security/secretbox`, kunci dari `CRED_ENC_KEY`); `config`
  kredensial tidak pernah dikembalikan utuh ke API (`{"configured": true}`).
- **[security]** Password hashing bcrypt cost 12 dengan waktu verifikasi yang
  seragam untuk username tidak dikenal (`internal/security/passwd`).
- **[security]** Endpoint `POST /api/credentials/{id}/verify` benar-benar
  mengambil `verify_url` lewat klien SSRF-safe dan mencocokkan pola.
- **[http]** Paket `internal/httpx`: envelope error seragam
  `{"error":{"code":"...","message":"..."}}`, `X-Content-Type-Options:
  nosniff`, escaping HTML, dan batas body 1 MiB.
- **[http]** Middleware CORS allowlist (match eksak, `Vary: Origin`, preflight
  `204`, origin asing `403`) dan security headers (CSP `default-src 'none'`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`).
- **[test]** Unit test untuk kontrol keamanan baru: SSRF (`guard_test.go`),
  JWT/CORS (`middleware_test.go`), policy RBAC (`policy_test.go`), secretbox
  (`secretbox_test.go`).
- **[docs]** `docs/BACKEND-DEV.md` — status nyata, environment, alur auth,
  daftar endpoint, aturan menambah endpoint, dan utang teknis.
- **[ci]** `.gitleaks.toml` dengan allowlist untuk kredensial dev yang memang
  di-commit (`config.yaml`, `docker-compose.yml`).

### Changed

- **[api]** `CreateScan` kini menyimpan scan lebih dulu, lalu men-dispatch;
  kegagalan dispatch menandai scan `failed`, bukan menghilangkan request.
- **[api]** Respons error di seluruh handler memakai JSON (bukan
  `http.Error` plain text); `GET /templates/{id}` mengembalikan `404` yang jujur.
- **[api]** `POST /api/scans` memvalidasi target (maks 50, dedup, normalisasi
  URL) dan memastikan `auth_credential_id` milik pemanggil.
- **[api]** Kredensial selalu diambil dengan `FindByIDOwned`; admin pun tidak
  melihat rahasia pengguna lain.
- **[api]** Pembacaan scan/finding/report memakai 404 untuk resource milik
  pengguna lain (bukan 403) agar ID tidak bisa dienumerasi.
- **[server]** `main.go` dipecah menjadi `run()` dengan graceful shutdown,
  timeout HTTP (`ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`),
  dan keyakinan konfigurasi (gagal cepat bila kunci tidak valid).
- **[config]** RabbitMQ kini opt-in (`RABBITMQ_ENABLED=false` default) sehingga
  mode in-memory benar-benar dipakai di pengembangan.
- **[persistence]** `tickets` menaut ke `finding_id` (sebelumnya `scan_id`),
  sehingga tiket bisa ditelusuri ke temuan aslinya.
- **[security]** `MkdirAll` direktori template memakai `0750` (sebelumnya `0755`).

### Fixed

- **[leak]** `SessionManager`: mutex, TTL 30 menit, dan goroutine `Sweep`
  (sebelumnya map tumbuh tanpa batas dan diakses tanpa lock).
- **[leak]** `event.Bus.Unsubscribe` menghapus key scan yang sudah kosong
  (sebelumnya menyisakan slice kosong per scan).
- **[leak]** Worker pool memakai context milik pool + deadline 30 detik
  (sebelumnya `context.Background()` sehingga task tak bisa dibatalkan).
- **[leak]** Crawler brute-force: pengiriman task sadar-context dan channel
  selalu ditutup.
- **[leak]** Crawler link discovery: antrean dikuras saat cancel agar
  `WaitGroup` mencapai nol dan goroutine penutup tidak menggantung.
- **[persistence]** `FindByID` scan tidak lagi mengarang status `completed`;
  `FindByUsername` tidak lagi mengembalikan admin untuk user apa pun.
- **[auth]** `Authenticate` tidak lagi menerima password apa pun; login yang
  gagal mengembalikan pesan seragam agar tidak membocorkan keberadaan akun.

### Security

- IDOR: kepemilikan diperiksa di lapisan aplikasi **dan** di query
  (`FindByIDOwned`, `DeleteOwned`), termasuk `auth_credential_id` pada scan dan
  `finding_id` pada tiket.
- SSRF: target scan dan URL kredensial (`login_url`, `verify_url`) divalidasi
  saat disimpan dan IP-nya diperiksa ulang saat koneksi dibuat.
- CORS: allowlist eksak; origin asing tidak pernah menerima header CORS.
- XSS: seluruh respons JSON + `nosniff` + CSP; `details` finding disimpan
  sebagai data, bukan HTML.
- Kredensial: ciphertext AES-256-GCM di database, diredaksi di API.
- Body request dibatasi 1 MiB; pesan error internal tidak diteruskan ke klien.

### CI

- Seluruh job memakai `go-version-file: go.mod` (sebelumnya `go-version: 1.21`
  yang tidak cocok dengan `go 1.25.10`).
- Job test menjalankan `go build ./...`, `go vet ./...`, dan `go test ./...`
  (sebelumnya hanya build sebagian paket + E2E yang tidak bisa dikompilasi).
- `golangci-lint` dibangun dari sumber (`go install ...@v1.64.8`) agar memakai
  toolchain modul; `errcheck`/`revive` dinonaktifkan sementara dengan catatan
  utang teknis, temuan `gosec`/`staticcheck`/`unused` dibersihkan.
- Sepuluh berkas test lama yang menargetkan simbol tidak pernah ada diberi
  `//go:build ignore` (isi dipertahankan) sehingga build dan test kembali hijau.
- Pemindaian CVE memakai `osv-scanner v2` yang di-pin, dijalankan sebagai
  advisory selama migrasi Go 1.26 belum dilakukan.

### Deprecated

- `db/schema.sql` dan model GORM di paket `db/` tidak dipakai lagi; sumber
  kebenaran skema adalah `AutoMigrate` di `internal/infrastructure/database/postgres`.
  Akan dihapus saat migrasi ber-versi (golang-migrate) dipasang.

### Removed

- Jalur "RabbitMQ selalu aktif": `Connect()` yang selalu sukses tidak lagi
  dianggap sebagai koneksi nyata.
- Fungsi `filterLinksByScope` dikembalikan hanya untuk test (ditandai
  `//nolint:unused`), bukan lagi dead code tanpa alasan.

### Known limitations

- Engine pemindaian (`HTTPEngine`/`HeadlessEngine`) masih stub: belum ada
  request HTTP ke target dan finding belum pernah tersimpan.
- WebSocket `/api/scans/{id}/stream` masih `501`; report export/download `501`;
  template registry mengembalikan `[]`.
- `io.ReadAll` pada `detector/executor.go` dan `crawler/fetcher.go` masih
  unbounded.
- CVE module-level pada `golang.org/x/{crypto,net,text}` baru bisa diperbaiki
  setelah modul naik ke Go 1.26 (lihat `docs/BACKEND-DEV.md` §8).

## [0.1.0] - 2026-05-31

Titik awal repository: kerangka layanan dengan router HTTP, model GORM, worker
pool, event bus, crawler/detector, dan dokumentasi produk. Sebagian besar
lapisan aplikasi, repositori, dan engine masih stub — endpoint mengembalikan
data contoh dan skema dibuat lewat `AutoMigrate`.

[Unreleased]: https://github.com/yogiex/backend-sentinel-scan/compare/v0.2.0...dev
[0.2.0]: https://github.com/yogiex/backend-sentinel-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/yogiex/backend-sentinel-scan/commit/b2cd049
[f8f4c03]: https://github.com/yogiex/backend-sentinel-scan/commit/f8f4c03
