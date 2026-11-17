# Detection Engine — Milestones & Status

> **Feature:** Declarative Plugin-based Vulnerability Detection Engine
> **Referensi:** `docs/features/detection-engine-plan.md`

---

## 5 Fase Implementasi

### Phase 1: Core Framework

| # | Task | Status |
|:--|:-----|:-------|
| 1.1 | Define plugin types and YAML schema (`types.go`, `plugin.go`) | ✅ Selesai |
| 1.2 | Implement plugin loader / YAML parser (`detector.go`, `registry.go`) | ✅ Selesai |
| 1.3 | Implement placeholder replacement FUZZ/HOST/PORT (`payload.go`) | ✅ Selesai |
| 1.4 | Implement request builder — method, path, headers, body (`executor.go`) | ✅ Selesai |
| 1.5 | Implement keyword matcher (`matcher.go`) | ✅ Selesai |
| 1.6 | Implement regex matcher (`matcher.go`) | ✅ Selesai |
| 1.7 | Implement status code matcher (`matcher.go`) | ✅ Selesai |

**Estimasi:** 4-5 hari &nbsp;|&nbsp; **Progress:** 100% ✅

---

### Phase 2: Advanced Matchers

| # | Task | Status |
|:--|:-----|:-------|
| 2.1 | Implement error-based matcher with built-in DBMS pattern database (`matcher_advanced.go`) | ✅ Selesai |
| 2.2 | Implement boolean-based blind matcher (`matcher_advanced.go`) | ✅ Selesai |
| 2.3 | Implement time-based blind matcher (`matcher_advanced.go`) | ✅ Selesai |
| 2.4 | Implement response comparison utility (`compare.go`) | ✅ Selesai |

**Estimasi:** 3-4 hari &nbsp;|&nbsp; **Progress:** 100% ✅

---

### Phase 3: Built-in Plugins

| # | Plugin | File | Status |
|:--|:-------|:-----|:-------|
| 3.1 | SQL Injection (error-based) | `plugins/sql_injection.yaml` | ✅ Selesai |
| 3.2 | Cross-Site Scripting (reflected) | `plugins/xss.yaml` | ✅ Selesai |
| 3.3 | Path Traversal / File Inclusion | `plugins/path_traversal.yaml` | ✅ Selesai |
| 3.4 | IDOR (Insecure Direct Object Reference) | `plugins/idor.yaml` | ✅ Selesai |
| 3.5 | Open Redirect | `plugins/open_redirect.yaml` | ✅ Selesai |
| 3.6 | XXE (XML External Entity) | `plugins/xxe.yaml` | ✅ Selesai |
| 3.7 | SSRF (Server-Side Request Forgery) | `plugins/ssrf.yaml` | ✅ Selesai |

**Estimasi:** 2-3 hari &nbsp;|&nbsp; **Progress:** 100% ✅

---

### Phase 4: Integration & Testing

| # | Task | Status |
|:--|:-----|:-------|
| 4.1 | Integrasi detector ke HTTPEngine (`scanner/scanner.go`) | ✅ Selesai (`37526c0`) |
| 4.2 | Tambah detector config ke viper loader (`config/config.go`) | ⚠️ Parsial — client/plugin dimuat lewat env di `main.go`; loader viper masih placeholder |
| 4.3 | Unit tests semua matchers (`matcher/*_test.go`) | ✅ Selesai |
| 4.4 | Unit tests plugin loader (`detector_test.go`) | ✅ Selesai |
| 4.5 | Integration tests (httptest server per vuln type) | ✅ Selesai (`internal/infrastructure/scanner/engine_test.go`) |
| 4.6 | Benchmarks plugin execution | ✅ Selesai (`test/benchmarks/engine_benchmark_test.go`) |

**Estimasi:** 2-3 hari &nbsp;|&nbsp; **Progress:** 33%

---

### Phase 5: Advanced Features

| # | Task | Status |
|---|------|--------|
| 5.1 | Headless engine integration (DOM-based XSS via chromedp) | ❌ Belum |
| 5.2 | Custom user plugins (upload YAML per scan) | ❌ Belum |
| 5.3 | Plugin chaining (multi-step vulnerability) | ❌ Belum |
| 5.4 | Payload fuzzing dari wordlist | ❌ Belum |
| 5.5 | WAF bypass payload variants | ❌ Belum |

**Estimasi:** 5-7 hari &nbsp;|&nbsp; **Progress:** 0%

---

## Ringkasan

| Phase | Nama | Task | Status | Estimasi |
|:------|:-----|:-----|:-------|:---------|
| 1 | Core Framework | 7 | ✅ Selesai | 4-5 hari |
| 2 | Advanced Matchers | 4 | ✅ Selesai | 3-4 hari |
| 3 | Built-in Plugins | 7 | ✅ Selesai | 2-3 hari |
| 4 | Integration & Testing | 6 | ⏳ Parsial (83%) | 2-3 hari |
| 5 | Advanced Features | 5 | ❌ Belum | 5-7 hari |
| | **Total** | **29** | **✅ 17 / ❌ 8 / ⏳ 4** | **16-22 hari** |
