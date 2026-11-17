# Feature Status

Satu-satunya tabel status fitur. Dokumen lain boleh menjelaskan cara kerja,
tetapi **status** diambil dari sini. Terakhir diperbarui: 2026-11-17.

Legenda:

- **Nyata** — ada kode, ada test yang berjalan, dan dipakai lewat API.
- **Sebagian** — berfungsi tetapi dengan batasan yang harus disebutkan.
- **Stub** — ada permukaan API/tipe, perilakunya belum ada (sering `501`).
- **Belum ada** — tidak ada kode; jangan diasumsikan jalan.
- **Dihapus** — pernah ada, sengaja dibuang (alasannya dicatat).

| Fitur | Status | Bukti / batasan |
|---|---|---|
| Login JWT (HS256) + RBAC 4 role | Nyata | `api/handlers.go`, `internal/middleware/auth.go`, `internal/domain/policy/policy.go` |
| Throttle login (per klien + per akun) | Sebagian | `internal/security/loginguard`; counter in-memory → hanya benar untuk 1 replika |
| Pencabutan token (`token_version`) | Sebagian | `POST /api/auth/logout`; mencabut **semua** sesi user sekaligus (belum per-perangkat) |
| Role & status user dibaca dari DB tiap request | Nyata | `Auth.WithUserState`; demosi/nonaktif berlaku langsung |
| Manajemen user (buat/reset/role) | Belum ada | user kedua masih lewat SQL; `PermUserManage` tidak ditegakkan |
| Audit trail | Belum ada | tabel `audit_logs` + repo ada, tidak pernah dipanggil |
| Scan HTTP (7 plugin embedded) | Nyata | `internal/infrastructure/detector/plugins`, `scanner.HTTPEngine` |
| Integritas hasil scan | Nyata | scan gagal total → `failed` + `failure_reason=all_tasks_failed`; sebagian gagal → `degraded: true` |
| Crawl link discovery (same-domain) | Nyata | `internal/infrastructure/crawler`; `max_depth`/`max_pages`/robots ditegakkan |
| Crawl brute-force path | Dihapus dari API | kode ada, tidak bisa dipilih; satu submission bisa jadi ribuan request |
| Authenticated scanning | **Belum ada** | `auth_credential_id` disimpan lalu diabaikan; `authscan.Executor` tanpa implementasi; cookie/header sesi tidak pernah dikirim |
| Headless engine | Stub | `scanner.HeadlessEngine` selalu `ErrHeadlessNotImplemented`; tanpa dependency browser |
| Report data JSON | Nyata | `GET /api/scans/{id}/report-data` |
| Export / download PDF | Stub | `501`; `report/generator.go` hanya struct kosong |
| WebSocket stream | Nyata | `api/stream.go`; `progress`/`finding`/`complete`/`failed` |
| Tiket remediasi (8 endpoint) | Nyata | `api/tickets.go`, `internal/application/tickets.go`; severity/`scan_id` diturunkan dari finding |
| Rekonsiliasi scan yatim | Nyata | `orchestrator/lifecycle.go`; alasan `interrupted_by_restart`/`interrupted_by_shutdown`/`heartbeat_lost` |
| Kredensial (vault) | Sebagian | CRUD + enkripsi AES-256-GCM; **tidak dipakai** saat memindai |
| RabbitMQ | Ditolak | startup gagal bila `RABBITMQ_ENABLED=true` (publisher stub) |
| Autoscaling worker | Belum ada | `AutoScaler.Start/Stop` no-op; `worker.autoscale.*` tidak dipakai |
| Migrasi skema ber-versi | Belum ada | hanya `AutoMigrate` saat boot |
| Readiness probe | Sebagian | `/health` selalu `200` tanpa cek DB/worker; tidak ada `/readyz` |
| Metrics / structured log | Belum ada | `log.Printf` tersebar; tanpa Prometheus/OTel/request ID |
| Dockerfile backend | Belum ada | `docker-compose.yml` hanya infrastruktur |
| Suite e2e | Belum bisa dipakai | `test/e2e` tidak compile (signature konstruktor berubah); 10 file test `//go:build ignore` |

## Klaim yang sengaja tidak dibuat

Dokumen lama (README/PRD/SRS) menyebut fitur-fitur ini sebagai "Production".
Itu tidak benar dan sudah diperbaiki:

- authenticated scanning (vault ada, pemakaiannya tidak)
- PDF report via chromedp (tidak ada dependency-nya, endpoint 501)
- headless/browser scanning (stub)
- RabbitMQ + in-memory fallback (startup menolak)
- worker autoscaling (no-op)
- integrasi Nuclei templates (yang jalan plugin embedded yang ditulis sendiri)
