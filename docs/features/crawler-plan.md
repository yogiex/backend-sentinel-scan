# Crawling Engine — Design & Implementation Plan

> **Feature:** Web Crawling Engine for URL Discovery
> **Status:** Planning
> **Target Version:** MVP+1

---

## 1. Product Rationale

### 1.1 Why Crawling?

Current DAST workflow requires users to manually specify every target URL. This misses:

- **Hidden endpoints** not documented or known to the user (`/api/v2/admin/`, `/backup/`, `.git/config`)
- **Forms & parameters** that contain reflected XSS, CSRF, or injection points
- **API endpoints** discovered from client-side JS bundles
- **Path parameters** that can be fuzzed for IDOR, LFI, etc.

Enterprise DAST tools (Burp Suite, ZAP, Acunetix, Nessus) all include crawling as a pre-scan discovery phase.

### 1.2 Alignment with Existing Architecture

The crawler fits naturally as a **pre-processing phase** before template execution:

```
Target URL → Crawler (discover URLs, forms, params, JS endpoints)
           → Scan Engine (run Nuclei templates against ALL discovered URLs)
```

No existing code needs modification — the crawler simply produces a list of discovered URLs that feed into the existing scan pipeline.

---

## 2. Design Principles

| Principle | Rationale |
|-----------|-----------|
| **Non-destructive by default** | Crawler must not POST to forms, DELETE resources, or modify state unless explicitly configured |
| **Configurable depth & scope** | User controls max crawl depth, scope (same-domain/subdomain), and rate limiting |
| **Respects robots.txt** | Follow crawl-delay and disallow directives (configurable override) |
| **Graceful degradation** | If crawling fails/times out, scan proceeds with originally-specified targets |
| **Observable** | Crawl progress & discovered URLs streamed via existing event bus |

---

## 3. Architecture: Pluggable Discovery Providers

Crawler didesain sebagai **framework provider-based**, bukan monolithic. Setiap mode discovery adalah provider terpisah yang mengimplementasi interface yang sama, berbagi infrastruktur yang sama.

```
┌──────────────────────────────────────────────────────┐
│                 Crawler Orchestrator                  │
│  - Lifecycle management (start/stop/await)            │
│  - Merge results dari semua provider                  │
│  - Deduplikasi global across providers                │
│  - Publish events ke event bus                        │
└──────────┬────────────────────────────────┬───────────┘
           │                                │
           ▼                                ▼
┌──────────────────────┐    ┌──────────────────────────┐
│  LinkDiscovery        │    │  BruteForceDiscovery      │
│  - Parse HTML links   │    │  - Load wordlist file     │
│  - Rekursif follow     │    │  - Generate path combos   │
│  - Form discovery     │    │  - Validate (filter 404)  │
│  - Sitemap/robots     │    │  - Concurrent brute force │
│  - JS asset extraction │   │                           │
└──────────┬────────────┘    └──────────┬────────────────┘
           │                            │
           └──────────┬─────────────────┘
                      ▼
      ┌──────────────────────────────┐
      │      Shared Infrastructure    │
      │  - URL normalizer             │
      │  - Deduplicator (visited set) │
      │  - Scope enforcer             │
      │  - Rate limiter               │
      │  - HTTP fetcher (client pool) │
      │  - Robots.txt cache           │
      └──────────────────────────────┘
```

### 3.1 Provider Interface

```go
type DiscoveryProvider interface {
    Name() string
    Start(ctx context.Context, seedURLs []string, results chan<- DiscoveredURL)
}
```

Setiap provider:
- Menerima seed URLs + shared context
- Mengirim discovered URLs ke channel yang sama (merged oleh orchestrator)
- Independen — bisa jalan sendiri atau paralel
- Berbagi rate limiter, scope, dan deduplicator yang di-inject dari orchestrator

---

## 4. Proposed Package Structure

```
internal/infrastructure/crawler/
├── crawler.go              # Orchestrator: lifecycle, provider management, result merge
├── crawler_test.go
├── provider.go             # DiscoveryProvider interface
├── provider_test.go
├── link/
│   ├── discovery.go        # LinkDiscovery provider: recursive HTML crawling
│   ├── discovery_test.go
│   ├── parser.go           # HTML parser: extract links, forms, assets
│   └── parser_test.go
├── bruteforce/
│   ├── discovery.go        # BruteForceDiscovery provider: wordlist-based path discovery
│   ├── discovery_test.go
│   ├── wordlist.go         # Wordlist loader (file, embedded, remote)
│   └── wordlist_test.go
├── shared/
│   ├── fetcher.go          # HTTP fetcher with rate limiting, redirect, timeout
│   ├── fetcher_test.go
│   ├── robots.go           # robots.txt parser & cache
│   ├── robots_test.go
│   ├── scope.go            # URL scope/filter logic
│   └── scope_test.go
└── types.go                # Shared types: Page, Form, DiscoveredURL, CrawlConfig, CrawlResult
```

### 4.1 Package Responsibilities

| File | Responsibility |
|------|---------------|
| `crawler.go` | Orchestrate discovery: manage providers, merge results, deduplicate, publish events |
| `provider.go` | `DiscoveryProvider` interface definition |
| `link/discovery.go` | Link-based recursive crawl: seed → fetch → parse → enqueue → loop |
| `link/parser.go` | Parse HTML: extract `<a href>`, `<form>`, `<script src>`, `<link>`, comments |
| `bruteforce/discovery.go` | Wordlist-based: load paths, generate URLs, fetch & validate, throttle |
| `bruteforce/wordlist.go` | Load wordlist from file path (e.g., SecLists `common.txt`) |
| `shared/fetcher.go` | HTTP GET with rate limiting, redirect handling, TLS options, cookie jar |
| `shared/robots.go` | Fetch & cache robots.txt, check Disallow / Crawl-Delay |
| `shared/scope.go` | Validate URL against scope rules: same-origin, path prefix, exclude patterns |
| `types.go` | Domain types used across all providers |

### 4.2 Integration Points with Existing Code

| Integration | Existing File | How |
|-------------|--------------|-----|
| Scan pipeline | `orchestrator/orchestrator.go` | Before template loading, call `Crawler.Start()` → merge discovered URLs with user-specified targets |
| Configuration | `config/config.go` | Add `crawler` section with `link` and `bruteforce` sub-configs |
| Event bus | `event/bus.go` | Publish `crawler_progress`, `crawler_url_discovered`, `crawler_complete` events |
| Worker pool | `internal/infrastructure/worker/pool.go` | Optional: dispatch crawl tasks via worker pool |

---

## 5. Data Types

```go
// types.go — Shared domain types

type ProviderType string

const (
    ProviderLink      ProviderType = "link"
    ProviderBruteForce ProviderType = "bruteforce"
)

type CrawlConfig struct {
    Link       LinkConfig
    BruteForce BruteForceConfig
}

type LinkConfig struct {
    Enabled       bool          // Enable link-based crawling
    MaxDepth      int           // Max crawl depth (0 = start URL only, -1 = unlimited)
    MaxPages      int           // Max total pages to crawl (0 = unlimited)
    RateLimit     time.Duration // Delay between requests
    Concurrency   int           // Concurrent fetch workers
    RespectRobots bool          // Follow robots.txt
    Scope         ScopeRule     // URL scope filter
    Timeout       time.Duration // Per-request timeout
    Headers       map[string]string
}

type BruteForceConfig struct {
    Enabled      bool              // Enable brute-force discovery
    WordlistPath string            // Path to wordlist file (e.g., /opt/SecLists/Discovery/Web-Content/common.txt)
    Concurrency  int               // Concurrent workers
    RateLimit    time.Duration     // Delay between requests
    Timeout      time.Duration     // Per-request timeout
    Scope        ScopeRule
}

type ScopeRule int

const (
    ScopeStrict       ScopeRule = iota // Same origin only (scheme + host + port)
    ScopeSameDomain                    // Same domain (subdomains included)
    ScopePathPrefix                    // URL must start with StartURL path
    ScopeUnrestricted                  // Any URL
)

type Page struct {
    URL        string
    Depth      int
    Links      []string   // Extracted <a href> URLs
    Forms      []Form     // Extracted <form> elements
    Assets     []string   // JS, CSS, image URLs
    RawBody    string     // Raw HTML (for keyword matching)
    StatusCode int
}

type Form struct {
    Action string
    Method string      // GET / POST
    Inputs []FormInput
}

type FormInput struct {
    Name string
    Type string        // text, password, hidden, file, etc.
}

type DiscoveredURL struct {
    URL    string
    Depth  int
    Source string       // "link", "form", "robots", "sitemap", "js", "bruteforce"
}

type CrawlResult struct {
    DiscoveredURLs []DiscoveredURL
    Pages          []Page
    Forms          []Form
    TotalRequests  int
    Duration       time.Duration
    Errors         []error
}
```

---

## 6. Core Algorithm

### 6.1 Orchestrator Loop (crawler.go)

```
Crawl(seedURLs, config):
  results ← make(chan DiscoveredURL)
  ctx, cancel ← context.WithCancel(...)

  IF config.Link.Enabled:
    provider ← LinkDiscovery{config.Link, sharedInfra}
    go provider.Start(ctx, seedURLs, results)

  IF config.BruteForce.Enabled:
    provider ← BruteForceDiscovery{config.BruteForce, wordlist, sharedInfra}
    go provider.Start(ctx, seedURLs, results)

  WHILE providers running:
    url ← <-results
    IF not already visited AND in scope:
      mark visited
      discovered ← append discovered
      publish event "crawler_url_discovered"

  return discovered
```

### 6.2 LinkDiscovery Algorithm (link/discovery.go)

```
Start(seedURLs, results):
  queue ← seedURLs (depth=0)

  WHILE queue not empty AND pages < maxPages:
    url ← queue.dequeue()

    IF visited(url): continue
    IF !inScope(url): continue
    IF robots.disallow(url): continue

    visited ← url
    page ← fetcher.GET(url)

    results ← {url, depth, source: "link"}

    IF depth < maxDepth OR maxDepth == -1:
      links ← parser.Links(page.Body, page.URL)
      forms ← parser.Forms(page.Body, page.URL)

      FOR link IN deduplicate(links):
        queue.enqueue(link, depth+1)
        results ← {link, depth+1, source: "link"}

      FOR form IN forms:
        results ← {form.Action, depth+1, source: "form"}
        queue.enqueue(form.Action, depth+1)
```

### 6.3 BruteForceDiscovery Algorithm (bruteforce/discovery.go)

```
Start(seedURLs, results):
  paths ← wordlist.Load()

  FOR seed IN seedURLs:
    FOR path IN paths:
      url ← seed + path
      IF visited(url): continue
      IF !inScope(url): continue

      resp ← fetcher.HEAD(url)   // HEAD first (fast filter)

      IF resp.StatusCode != 404 AND resp.StatusCode != 0:
        // Potential hit — verify with GET
        page ← fetcher.GET(url)
        IF page.StatusCode != 404:
          visited ← url
          results ← {url, depth: 0, source: "bruteforce"}
```

### 6.4 Deduplication Strategy

- **URL normalization**: lower-case scheme + host, remove default ports (80/443), sort query params, remove fragments
- **Shared visited set** across all providers — LinkDiscovery dan BruteForceDiscovery share deduplicator yang sama
- **Same-page anchors**: skip `#fragment` only URLs

### 6.5 Scope Enforcement

Applied before fetching every URL:

1. Parse normalized URL
2. Check domain matches scope rule
3. Check path matches include/exclude patterns
4. Check not already visited
5. Fetch

---

## 7. link/parser.go — HTML Extraction

| Element | Extracted | Priority |
|---------|-----------|----------|
| `<a href="...">` | Full URL | High |
| `<form action="...">` | Form action URL + input fields | High |
| `<script src="...">` | JS endpoint URLs | Medium |
| `<link href="...">` | CSS/icon URLs | Medium |
| `<iframe src="...">` | Embedded page URLs | Medium |
| `<img src="...">` | Image URLs | Low |
| `<!-- comments -->` | Text content (may contain endpoints) | Low |
| `sitemap.xml` | Parse sitemap XML for additional URLs | High |
| `robots.txt` | Parse for `Sitemap:` directive, `Disallow` paths | High |

URL resolution: relative URLs resolved against page's base URL (handling `<base>` tag).

```go
func parseLinks(body string, baseURL *url.URL) []string {
    // 1. Parse HTML with golang.org/x/net/html
    // 2. Find all <a href="..."> tags
    // 3. Resolve relative URLs against baseURL
    // 4. Filter out: javascript:, mailto:, tel:, #fragment, data:
    // 5. Normalize: remove default ports, sort query params
    // 6. Deduplicate
}
```

---

## 8. bruteforce/wordlist.go — Wordlist Dataset

### 8.1 Sumber Wordlist

BruteForceDiscovery **membutuhkan wordlist eksternal** karena path discovery berbasis tebakan.

| Sumber | Contoh | Ukuran |
|--------|--------|--------|
| [SecLists Discovery/Web-Content](https://github.com/danielmiessler/SecLists) | `common.txt` (4,700 paths), `directory-list-2.3-medium.txt` (220K paths) | ~100KB-10MB |
| Kustom user | User-defined wordlist sesuai target | Terserah user |
| Built-in minimal | Default bawaan (~100 common paths: admin, backup, .git, .env, etc.) | ~5KB |

### 8.2 Wordlist Loader Strategy

```go
type WordlistLoader interface {
    Load(ctx context.Context) ([]string, error)
}

type FileWordlist struct {
    Path string
}

type BuiltinWordlist struct {
    paths []string   // Embedded minimal wordlist
}
```

### 8.3 Rekomendasi

**Opsional — tidak perlu bundled.** Sama seperti nuclei-templates yang di-clone terpisah, SecLists juga bisa di-clone oleh user. Crawler cukup membaca dari path yang dikonfigurasi:

```yaml
crawler:
  bruteforce:
    enabled: false
    wordlist_path: "/opt/SecLists/Discovery/Web-Content/common.txt"
```

Default `enabled: false` — user opt-in untuk brute-force.

---

## 9. Integration with Existing Scan Flow

### 9.1 Modified Scan Lifecycle

```
Client → POST /api/scans {targets, crawl: {link: true, bruteforce: false}, ...}
  → Handler.CreateScan()
    → ScanService.StartScan()
      → [NEW] IF crawl enabled:
          → Crawler.Start(targets, crawlConfig)
          → Crawler.Wait()
          → Merge discovered URLs into targets list
      → Orchestrator.StartScan(targets, template_selectors)
        → TemplateLoader.List()
        → Create tasks → enqueue to worker pool
        → Worker pool executes HTTP/Headless engines
        → Results persisted + event bus publish
      → Scan completed
```

### 9.2 Config Additions (`config.yaml`)

```yaml
crawler:
  link:
    enabled: true
    max_depth: 2
    max_pages: 100
    rate_limit: "200ms"
    concurrency: 5
    respect_robots: true
    scope: "strict"
    timeout: "10s"
    user_agent: "SentinelScan-Crawler/1.0"

  bruteforce:
    enabled: false
    wordlist_path: ""
    concurrency: 10
    rate_limit: "50ms"
    timeout: "5s"
    scope: "strict"
```

### 9.3 API Changes

| Endpoint | Change |
|----------|--------|
| `POST /api/scans` | New optional field: `crawl` object `{link: bool, bruteforce: bool, depth: int, max_pages: int}` |

No new endpoints. Crawling adalah scan option, bukan resource terpisah.

### 9.4 Event Bus Integration

| Event Type | Payload | When |
|------------|---------|------|
| `crawler_progress` | `{provider, discovered, total, current_url}` | After each page fetch |
| `crawler_url_discovered` | `{url, source, depth}` | New URL discovered by any provider |
| `crawler_complete` | `{total_urls, duration, errors}` | Crawl finished |

Events stream via existing WebSocket connection.

---

## 10. Phased Implementation Plan

### Phase 1: Shared Infrastructure (Priority: High)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 1.1 | Define domain types & config | `types.go`, `config/config.go` | None |
| 1.2 | URL normalization & dedup utilities | `shared/normalize.go` | None |
| 1.3 | Scope enforcement | `shared/scope.go` | `types.go` |
| 1.4 | HTTP fetcher with rate limiting | `shared/fetcher.go` | None |
| 1.5 | robots.txt parser & cache | `shared/robots.go` | `fetcher.go` |
| 1.6 | Provider interface definition | `provider.go` | `types.go` |
| 1.7 | Crawler orchestrator | `crawler.go` | All above |

**Effort estimate:** 2-3 days

### Phase 2: LinkDiscovery Provider (Priority: High)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 2.1 | HTML parser (links, forms, assets) | `link/parser.go` | Phase 1 |
| 2.2 | LinkDiscovery recursive crawl loop | `link/discovery.go` | Phase 1 + 2.1 |
| 2.3 | Sitemap XML parser | `link/parser.go` | Phase 1 |
| 2.4 | Unit tests | `link/*_test.go` | Implementation |

**Effort estimate:** 2-3 days

### Phase 3: BruteForceDiscovery Provider (Priority: Medium)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 3.1 | Wordlist loader (file + built-in) | `bruteforce/wordlist.go` | Phase 1 |
| 3.2 | BruteForceDiscovery loop (HEAD+GET validation) | `bruteforce/discovery.go` | Phase 1 + 3.1 |
| 3.3 | Concurrent path checking | `bruteforce/discovery.go` | Phase 1 |
| 3.4 | Unit tests | `bruteforce/*_test.go` | Implementation |

**Effort estimate:** 2 days

### Phase 4: Integration (Priority: High)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 4.1 | Integrate crawler into orchestrator | `orchestrator/orchestrator.go` | Phase 2 |
| 4.2 | Add `crawl` option to scan API handler | `api/handlers.go` | Phase 2 |
| 4.3 | Add crawler config to viper loader | `config/config.go` | Phase 1 |
| 4.4 | Publish crawler events to event bus | `crawler.go` + `event/bus.go` | Phase 1 |
| 4.5 | Wire crawler in main.go | `main.go` | All above |
| 4.6 | E2E tests (httptest server with interlinked pages) | `test/e2e/crawl/` | Phase 2 |

**Effort estimate:** 1-2 days

### Phase 5: Advanced Features (Priority: Low)

| # | Task | Description |
|---|------|-------------|
| 5.1 | JS endpoint extraction | Parse JS files for API paths, endpoint strings |
| 5.2 | Parameter discovery | Extract parameter names from forms, query strings, JS |
| 5.3 | Auth-aware crawling | Inject cookies/headers from existing SessionManager |
| 5.4 | SPA crawling | Use headless engine for JS-rendered link discovery |
| 5.5 | Dictionary brute-force tuning | Auto-detect 404 patterns, exclude noise |

**Effort estimate:** 5-7 days total

---

## 11. Testing Strategy

### 11.1 Unit Tests

| Component | Test Cases |
|-----------|------------|
| `shared/scope.go` | Same-origin match/reject, subdomain inclusion, path prefix filter, exclude pattern |
| `shared/fetcher.go` | Successful fetch, timeout, redirect following (max redirects), non-200, rate limiting |
| `shared/robots.go` | Parse robots.txt, Disallow/Allow, Crawl-Delay, Sitemap:, missing robots.txt |
| `link/parser.go` | Extract links, relative URLs, `<base>` tag, skip javascript:/mailto:, malformed HTML, forms with inputs, JS/CSS assets |
| `link/discovery.go` | Single page, multi-page with depth limit, max pages limit, dedup, scope enforcement |
| `bruteforce/wordlist.go` | Load file, missing file, empty file, filter comments/blank lines |
| `bruteforce/discovery.go` | Hit detection (non-404), miss (404 skip), concurrent workers, scope filtering |

### 11.2 Integration Tests

| Test | Description |
|------|-------------|
| Link crawl e2e | httptest server with 10 interlinked pages → crawl → verify all URLs discovered |
| robots.txt compliance | Server with robots.txt disallowing `/private/` → verify crawler skips it |
| Scope enforcement | Start URL on host A → links to host B → verify host B rejected (strict scope) |
| Form discovery | Server returns form with 3 inputs → verify Form struct parsed correctly |
| Brute-force e2e | httptest server with `/admin`, `/backup`, `.git/config` return 200, rest 404 → verify all 3 discovered |

### 11.3 Test Data

- `httptest.NewServer` with predefined HTML pages (no real network calls)
- robots.txt: custom handler returning specific content
- Link graph: 5-10 interlinked pages with known structure for depth/scope testing
- Wordlist test: temp file with known paths

---

## 12. Scaling from Link-only to Link + Brute-force

### 12.1 Migration Path

```
Phase 2: Link-only          → Extend config crawler.link.enabled = true
Phase 3: Link + Brute-force → Set crawler.bruteforce.enabled = true + wordlist_path
```

Tidak ada perubahan kode di provider yang sudah ada — tinggal inject provider baru ke orchestrator.

### 12.2 Provider Independence

Setiap provider:

- **Berbagi** rate limiter, scope enforcer, dan deduplicator yang sama
- **Independen** — Link bisa jalan sendiri tanpa BruteForce, dan sebaliknya
- **Paralel** — keduanya bisa jalan bersamaan, hasil dari channel di-merge otomatis oleh orchestrator
- **Graceful** — kalau satu provider gagal, provider lain tetap jalan

### 12.3 Impact Table

| Skenario | Link-only | Link + Brute-force |
|----------|-----------|-------------------|
| Halaman normal dengan link | ✅ Coverage penuh | ✅ Coverage penuh |
| Hidden admin panel (no link) | ❌ Tidak ketemu | ✅ Ketemu dari wordlist |
| API docs `/api/v1/` | ❌ Kalau gak di-link | ✅ Discovery via wordlist |
| `.git/config` exposed | ❌ | ✅ Langsung terdeteksi |
| Performa | Cepat (follow link) | Lebih lambat (banyak request) |
| Noise | Rendah | Sedang (false positive 404 filtering) |

---

## 13. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Crawler makes too many requests | Rate limiting per provider, max pages, max depth |
| Brute-force floods server | HEAD request first (fast filter), baru GET untuk non-404 |
| Large sites consume memory | Max pages limit; streaming via channel (bukan store all in memory) |
| Brute-force false positives | HEAD+GET validation (filter 404, redirect, default page) |
| robots.txt blocking everything | Configurable override (`respect_robots: false`) |
| Brute-force needs wordlist | Built-in minimal wordlist sebagai fallback; user bisa kustom via config |

---

## 14. Success Criteria

| Metric | Target |
|--------|--------|
| Link discovery rate | >95% of reachable links found within configured depth |
| Brute-force accuracy | <10% false positives (non-404 pages that aren't real resources) |
| Crawl throughput (link) | 10+ pages/second (rate limiting disabled) |
| Brute-force throughput | 100+ paths/second (HEAD only) |
| Test coverage | >80% on all crawler packages |
| No breaking changes | Existing scan workflow unchanged when `crawl` disabled |
