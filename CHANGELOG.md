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

- **[auth]** `POST /api/auth/logout` mencabut seluruh token user lewat kolom
  `users.token_version`. Setiap request terautentikasi membandingkan `tv` di token
  dengan baris user, dan mengambil role + `is_active` dari DB, sehingga logout,
  demosi, dan penonaktifan berlaku seketika — bukan setelah token kedaluwarsa.
- **[auth]** `internal/security/loginguard`: throttle login per klien dan per
  (klien+akun), `429` + `Retry-After`, batas verifikasi bcrypt bersamaan, dan
  tabel counter berbatas ukuran. `X-Forwarded-For` sengaja diabaikan.
- **[scan]** `scan_jobs.degraded`: scan yang selesai tetapi sebagian task tidak
  pernah mendapat respons kini jujur menyebut cakupannya parsial.
- **[detector]** `CheckWithPlugins` mengembalikan `CheckStats`
  (attempted/succeeded/failed) bersama hasil match; `MatchResponseWithHeaders`
  membaca header respons.
- **[detector]** dukungan `location: "header"` + `header_name` dan
  `no_redirect: true` pada plugin; plugin open-redirect memakai canary
  `.invalid` dengan regex yang di-anchor ke awal `Location`.
- **[docs]** `docs/FEATURE-STATUS.md`: satu tabel status fitur sebagai sumber
  kebenaran, menggantikan klaim "Production" yang tersebar.

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
- **[api]** `GET /api/templates` menyajikan katalog nyata dari registry embedded
  (id, nama, severity, engine, tag, `payload_count`, matcher) dengan filter
  `severity`/`tag`/`search`, dan `GET /api/templates/{id}` mengembalikan satu
  plugin atau `404`. Sebelumnya endpoint ini selalu `[]` dan `404`.
- **[stream]** `GET /api/scans/{id}/stream` kini WebSocket sungguhan: ownership
  diperiksa sebelum upgrade, `Origin` dicocokkan eksak, dan frame dikirim sebagai
  `{type,data}` untuk `progress`, `finding`, `complete`, `failed`. Klien yang
  telat connect menerima snapshot progress + maksimal 50 finding.
- **[scan]** Crawl opsional per scan (`crawl.enabled/max_depth/max_pages/
  respect_robots`) dijalankan sebagai fase sendiri sebelum fan-out task; opsi
  disimpan di `scan_jobs` sehingga laporan bisa menjelaskan asal target.
- **[docs]** `docs/BACKEND-DEV.md`: tata bahasa selector, tabel budget, kontrak
  crawl, status engine, env `CRAWLER_*`, dan sisa pekerjaan yang diperbarui.
- **[tickets]** Alur remediasi nyata: `GET/POST /api/tickets`,
  `GET /tickets/stats`, `GET /tickets/overdue`, `GET /tickets/{id}`,
  `PATCH /tickets/{id}/status`, `POST /tickets/{id}/assign`, dan
  `POST /tickets/{id}/comments`. Service dan repository sudah ada tetapi tidak
  pernah punya route, jadi temuan tidak bisa menjadi tiket sama sekali.
- **[tickets]** Status 5 tahap (`open`, `in_progress`, `fixed`, `verified`,
  `wont_fix`) dengan state machine dan `closed_at`, prioritas terpisah dari
  severity, SLA default (3/7/14/30 hari), komentar append-only, dan kode
  `TKT-000123` yang diturunkan dari ID.
- **[scan]** Kolom `failure_reason` + `heartbeat_at` dan rekonsiliasi tiga arah:
  saat boot (`interrupted_by_restart`), saat shutdown (`interrupted_by_shutdown`),
  dan saat heartbeat hilang (`heartbeat_lost`).

### Changed

- **[detector]** plugin `idor` dan `ssrf` **dihapus**: keduanya hanya
  mencocokkan `status 200`, yang juga dikembalikan halaman normal. Registry kini
  7 plugin. `Plugin.Validate` menolak plugin yang satu-satunya matcher adalah
  status 2xx, jadi bentuk itu tidak bisa kembali tanpa sengaja.
- **[api]** `GET /api/scans/{id}` menyertakan `degraded`; frame WebSocket
  `complete` menyertakan `degraded`, dan `failed` memakai `failure_reason`
  sebagai `reason` alih-alih mengulang string status.
- **[auth]** `last_login` ditulis lewat `UpdateLastLogin` (satu kolom), bukan
  `Update` seluruh baris: login yang sedang berjalan tidak lagi bisa
  mengembalikan role atau menonaktifkan user yang baru diubah.

- **[scan]** Orchestrator menjadi satu-satunya penulis finding: result worker
  dipersist via `CreateBatch` di dispatch loop, worker tetap tanpa akses DB.
- **[scan]** Timeout task diambil dari `worker.task_timeout` (bukan konstanta
  30 detik), dan tiap request dibatasi `detector.MaxResponseBytes` /
  `crawler.MaxBodyBytes` (2 MiB) dengan penanda `Truncated`.
- **[security]** `RABBITMQ_ENABLED=true` sekarang **menggagalkan startup**:
  publisher masih stub dan akan membuang task tanpa error.
- **[scan]** `HeadlessEngine` mengembalikan `ErrHeadlessNotImplemented` alih-alih
  "tidak ada temuan", supaya scan headless tidak tampak bersih.
- **[scan]** Budget request dibuat saat scan dimulai, bukan setelah task diantre,
  sehingga request crawl ikut terhitung. `total_tasks` dihitung ulang setelah
  crawl (fase `crawling` → `scanning`).
- **[stream]** `middleware.QueryToken` menerima `?token=` hanya untuk route
  `/stream`, karena browser tidak bisa memasang header pada handshake WebSocket.
- **[tickets]** `severity`, `scan_id`, dan target tiket diturunkan dari finding,
  bukan dari body request: sebelumnya klien bisa mengirim `severity: critical`
  untuk temuan `info`. Assignee juga wajib user yang ada dan aktif.
- **[tickets]** Daftar tiket untuk non-reviewer mencakup tiket yang dibuat
  **atau** ditugaskan kepadanya; sebelumnya hanya `created_by`, sehingga
  assignee tidak bisa melihat pekerjaannya sendiri.
- **[scan]** `Shutdown` membatalkan run sekaligus menulis statusnya. Sebelumnya
  `StopAll` hanya membatalkan context, sehingga setiap restart meninggalkan
  baris `running` yang tidak pernah ditutup.

### Fixed

- **[crawler]** `<form action>` lintas host dikirim ke hasil discovery
  **sebelum** dicek scope, sehingga crawl satu situs bisa mengirim payload ke
  host pihak ketiga. Sekarang dicek dulu, dan orchestrator menyaring ulang semua
  URL hasil crawl terhadap scope sebelum menjadi target.
- **[scan]** Scan dengan 100% task gagal dulu berakhir `completed` tanpa finding
  — laporan palsu "tidak ada kerentanan". Sekarang `failed` +
  `failure_reason=all_tasks_failed`; kegagalan sebagian menandai `degraded`.
- **[detector]** Error transport per payload ditelan (`continue`), sehingga
  timeout/koneksi ditolak tampak seperti target bersih. Sekarang dihitung, dan
  engine mengembalikan `ErrNoRequestCompleted` bila tidak ada satu pun respons.
- **[detector]** Matcher `location: "header"` tidak pernah membaca header
  (selalu body), jadi plugin open-redirect tidak mungkin match.
- **[security]** Client scan produksi dibuat tanpa `CheckRedirect`, menghapus
  validasi per-hop milik SSRF guard; kebijakan dipasang kembali di `main.go`.
- **[security]** Login tidak punya rate limit maupun batas konkurensi bcrypt.

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
- **[crawl]** `max_pages` tidak pernah ditegakkan (semua link yang terjangkau
  diambil) dan filter robots selalu `nil` sehingga `respect_robots` tidak
  berpengaruh; keduanya kini benar-benar membatasi crawl.
- **[crawl]** `Crawler.Run` tidak lagi menumpuk hasil antar-pemanggilan dan
  `truncated` hanya ditandai bila ada halaman yang benar-benar terlewat.
- **[stream]** Orchestrator sebelumnya tidak lagi menerbitkan event apa pun
  (bus dicabut sebagai "unused"), sehingga `/stream` akan menggantung tanpa
  `complete`; event progress/complete/failed kini diproduksi lagi.
- **[stream]** `Subscribe` dipindah **sebelum** snapshot ditulis: event yang
  terbit saat snapshot masih dikirim dulu jatuh ke celah antara "baca state" dan
  "dengarkan perubahan" dan hilang. Ini penyebab flaky test stream.

### Security

- **[auth]** Token kini dapat dicabut (`token_version`), dan role/status user
  dibaca dari database pada setiap request.
- **[auth]** Throttle login membatasi brute force dan password spraying, serta
  mencegah endpoint login dipakai sebagai amplifier CPU (bcrypt cost 12).
- **[security]** Port allowlist SSRF kembali berlaku pada setiap hop redirect.

- **[scan]** Redirect dari target menuju `169.254.169.254`, `127.0.0.1`, atau
  `10.0.0.0/8` kini gagal di lapisan dial; sebelumnya diikuti sampai 10 hop.
- **[scan]** Respons target dibatasi 2 MiB untuk mencegah kehabisan memori worker.
- **[scan]** Budget request membatasi volume keluar per scan (default 60 × target),
  sehingga scan tidak bisa dipakai membanjiri target.
- **[crawl]** URL hasil crawl adalah input dari penyerang: setiap URL divalidasi
  ulang ke kebijakan SSRF sebelum dipindai, scope dibatasi same-domain
  (`ScopeUnrestricted` dipaksa turun), dan brute-force path guessing tidak
  diekspos ke API.
- **[tickets]** Tiket asing tidak bisa dibaca, diubah, atau dikomentari: query
  memakai bentuk `*Owned` (404, bukan 403) dan reviewer (admin/auditor) tetap
  melihat seluruh papan. Assignee palsu ditolak `400` agar tidak ada tiket
  yang menunjuk user yang tidak ada.
- **[scan]** Status scan tidak lagi bisa berbohong selamanya: rekonsiliasi
  menghapus baris `running`/`pending` yatim, dan shutdown mencatat alasannya.

### Docs

- **[docs]** README ditulis ulang: status nyata, daftar fitur yang **tidak**
  ada, dan instruksi yang cocok dengan kode.
- **[docs]** `prd.md`, `srs.md`, `api.md`, `architecture.md`, `deployment.md`,
  `testing.md`, dan `features/milestones.md` diberi banner historis; klaim
  "Production" untuk auth-scanning/PDF/headless/RabbitMQ/autoscaling dihapus.
- **[docs]** BACKEND-DEV: endpoint logout, env `LOGIN_*`, 7 plugin, integritas
  hasil, dan daftar perbaikan diperbarui.

### Tests

- **[tests]** Test baru: `detector/check_test.go`, `detector/matcher_header_test.go`,
  `orchestrator/orchestrator_integrity_test.go`,
  `orchestrator/orchestrator_scope_test.go`, `api/auth_test.go`,
  `security/loginguard/guard_test.go`, plus kasus revocation/role-di-middleware
  dan engine "target tidak terjangkau".

- **[scan]** Test baru: budget/rate egress, validasi plugin, encoding payload,
  batas body, resolusi selector, engine satu-plugin-per-task, guard redirect
  metadata, serta alur orchestrator (progress, persistensi, cancel, truncated).
- **[crawl]** Test baru: `max_pages`/`max_depth`/`robots.txt` benar-benar
  membatasi crawl, crawl memperluas target dan membuang host asing, kegagalan
  crawl jatuh ke target awal, serta nilai `crawl` divalidasi sebelum disimpan.
- **[api]** Test baru: katalog template (filter + 404 + permission), stream
  (snapshot, event live, terminal via polling status, 404 scan asing, 403
  origin, 501 tanpa bus), dan `QueryToken` hanya berlaku di route stream.
- **[tickets]** Test baru: severity/scan/prioritas diturunkan dari finding,
  validasi assignee, transisi status (termasuk transisi ilegal), visibilitas
  assignee vs reviewer, komentar, stats, dan overdue. Di level HTTP: shape
  list/detail, `/tickets/stats` tidak tertelan `/tickets/{id}`, 404 tiket asing.
- **[scan]** Test baru: rekonsiliasi boot, shutdown yang mencatat alasan,
  heartbeat untuk run hidup, penandaan scan tanpa heartbeat, dan maintenance
  yang berhenti bersama context.

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
