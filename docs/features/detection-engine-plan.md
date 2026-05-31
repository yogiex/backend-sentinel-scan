# Vulnerability Detection Engine — Design & Implementation Plan

> **Feature:** Declarative Plugin-based Vulnerability Detection Engine
> **Status:** Planning
> **Target Version:** MVP+1

---

## 1. Product Rationale

### 1.1 Why a Plugin-based Detection Engine?

Current architecture relies on **Nuclei YAML templates** executed against targets. This has limitations:

- **No payload customization** — user cannot add/modify payloads per scan
- **No control over matchers** — matching logic is embedded in Nuclei template format
- **External dependency** — requires cloning nuclei-templates repo
- **No real-time injection** — current HTTP engine is a stub, no actual payload sending
- **Limited vuln coverage** — specific checks (time-based blind SQLi, boolean blind, stored XSS, etc.) need dedicated engine logic, not just request/response matching

Enterprise DAST tools build their own detection engines because generic template engines miss nuanced vulnerability patterns.

### 1.2 Alignment with Existing Architecture

The detection engine lives inside the **HTTPEngine** and **HeadlessEngine**, replacing the current stub implementation:

```
Current:
  HTTPEngine.Execute() → return hardcoded "no finding"

Target:
  HTTPEngine.Execute() → load matching plugins → inject payloads → match responses → return Finding
```

---

## 2. Design Principles

| Principle | Rationale |
|-----------|-----------|
| **Declarative plugins** | Vulnerability logic in YAML, not Go code |
| **Configurable per scan** | User can enable/disable vuln types, override payloads, set severity |
| **Stateless detection** | Each Execute() call is independent (no shared state between requests) |
| **Graceful degradation** | If a plugin panics/errors, skip it, don't fail the whole scan |
| **Layered matching** | Support multiple match strategies (keyword, regex, error-based, time-based, boolean) |
| **Extensible** | New vuln types added by creating a new YAML plugin file, no code changes |

---

## 3. Proposed Package Structure

```
internal/infrastructure/detector/
├── detector.go           # PluginManager: load, filter, execute plugins
├── detector_test.go
├── plugin.go             # Plugin type definitions (Plugin, PluginResult)
├── plugin_test.go
├── registry.go           # Built-in plugin registry (embedded YAML)
├── registry_test.go
├── engine/
│   ├── executor.go       # PluginExecutor interface
│   ├── http_executor.go  # HTTP-based plugin execution
│   ├── http_executor_test.go
│   ├── headless_executor.go # Headless/browser-based plugin execution
│   └── headless_executor_test.go
├── matcher/
│   ├── matcher.go        # Matcher interface + factory
│   ├── keyword.go        # Keyword/string matching
│   ├── regex.go          # Regex pattern matching
│   ├── error_based.go    # SQL error pattern matching
│   ├── boolean.go        # Boolean-based blind detection
│   ├── time_based.go     # Time-based blind detection
│   └── status.go         # HTTP status code matching
├── payload/
│   ├── loader.go         # Payload loader (from plugin YAML)
│   └── placeholder.go    # Placeholder replacement (FUZZ, HOST, etc.)
├── plugins/              # Built-in YAML plugin files
│   ├── sql_injection.yaml
│   ├── xss.yaml
│   ├── path_traversal.yaml
│   ├── idor.yaml
│   ├── open_redirect.yaml
│   ├── xxe.yaml
│   └── ssrf.yaml
└── types.go              # Shared types: DetectionConfig, Severity, MatchResult
```

### 3.1 Integration with Existing Code

| Integration | Existing File | How |
|-------------|--------------|-----|
| HTTP Engine | `internal/infrastructure/scanner/scanner.go` | Replace `Execute()` stub with `Detector.Run()` |
| Headless Engine | `internal/infrastructure/scanner/scanner.go` | Same replacement for headless path |
| Template loader | `template/loader.go` | Reuse YAML parsing pattern; plugins are separate from nuclei templates |
| Config | `config/config.go` | Add `detector` section for plugin directory, default severity, timeout |
| Worker pool | `internal/infrastructure/worker/pool.go` | No change — engine is called via existing `Execute()` interface |

---

## 4. Data Types

```go
// types.go — Shared types for detection engine

type Severity string
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type DetectionConfig struct {
    PluginsDir       string   // Directory for custom YAML plugins
    DefaultSeverity  Severity // Fallback severity if plugin doesn't specify
    MaxPayloadsPerPlugin int  // Limit payloads per plugin (performance)
    Timeout          time.Duration
}

type PluginMetadata struct {
    ID          string   `yaml:"id"`
    Name        string   `yaml:"name"`
    Description string   `yaml:"description"`
    Severity    Severity `yaml:"severity"`
    Tags        []string `yaml:"tags"`
    Reference   string   `yaml:"reference"`
}

type Plugin struct {
    Metadata   PluginMetadata    `yaml:"metadata"`
    Engine     string            `yaml:"engine"`     // "http" or "headless"
    Method     string            `yaml:"method"`     // "GET", "POST", etc.
    Path       string            `yaml:"path"`       // e.g., "/search?q=FUZZ"
    Headers    map[string]string `yaml:"headers"`
    Body       string            `yaml:"body"`       // For POST requests
    Payloads   []Payload         `yaml:"payloads"`
    Matchers   []MatcherConfig   `yaml:"matchers"`
    Variables  map[string]string `yaml:"variables"`  // Template variables
}

type Payload struct {
    Name    string `yaml:"name"`
    Value   string `yaml:"value"`
    Encoded bool   `yaml:"encoded"` // URL-encode the payload
}

type MatcherConfig struct {
    Type     string   `yaml:"type"`             // keyword, regex, error_based, boolean, time_based, status
    Patterns []string `yaml:"patterns"`
    Location string   `yaml:"location"`         // body, header, status, response_time
    Negative bool     `yaml:"negative"`         // true = match if pattern NOT found
    Condition string  `yaml:"condition"`        // "and", "or" — how to combine patterns
}

type MatchResult struct {
    Matched   bool
    Type      string
    Pattern   string
    Evidence  string   // Matched content from response
    Payload   string   // Which payload triggered the match
}

type PluginResult struct {
    PluginID      string
    Target        string
    Matched       bool
    Severity      Severity
    Matches       []MatchResult
    RequestDump   string
    ResponseDump  string
    Duration      time.Duration
}
```

---

## 5. Plugin YAML Format

### 5.1 SQL Injection Plugin (`plugins/sql_injection.yaml`)

```yaml
metadata:
  id: "sql-injection-error"
  name: "SQL Injection (Error-Based)"
  description: "Detects SQL injection by triggering database error messages"
  severity: "critical"
  engine: "http"

method: "GET"
path: "/?id=FUZZ"

headers:
  User-Agent: "SentinelScan-Detector/1.0"

payloads:
  - name: "single-quote"
    value: "'"
  - name: "double-quote"
    value: '"'
  - name: "union-select"
    value: "' UNION SELECT NULL--"
  - name: "or-1=1"
    value: "' OR '1'='1"
  - name: "comment-sql"
    value: "'--"

matchers:
  - type: "error_based"
    patterns:
      - "you have an error in your sql"
      - "warning: mysql"
      - "unclosed quotation mark"
      - "odbc driver"
      - "sqlite_error"
      - "ora-[0-9]{5}"
      - "postgresql.*error"
    location: "body"
    condition: "or"

  - type: "boolean"
    patterns:
      - "' AND '1'='1"
      - "' AND '1'='2"
    location: "body"
    condition: "and"
```

### 5.2 XSS Plugin (`plugins/xss.yaml`)

```yaml
metadata:
  id: "xss-reflected"
  name: "Cross-Site Scripting (Reflected)"
  description: "Detects reflected XSS by injecting script payloads"
  severity: "high"
  engine: "http"

method: "GET"
path: "/?q=FUZZ"

payloads:
  - name: "basic-script"
    value: "<script>alert('xss')</script>"
  - name: "img-onerror"
    value: "<img src=x onerror=alert('xss')>"
  - name: "svg-onload"
    value: "<svg onload=alert('xss')>"
  - name: "body-onload"
    value: "<body onload=alert('xss')>"
  - name: "iframe-src"
    value: "<iframe src=javascript:alert('xss')>"

matchers:
  - type: "keyword"
    patterns:
      - "<script>alert('xss')</script>"
      - "<img src=x onerror=alert"
      - "<svg onload=alert"
      - "<body onload=alert"
      - "<iframe src=javascript:alert"
    location: "body"
    condition: "or"
```

### 5.3 Path Traversal Plugin (`plugins/path_traversal.yaml`)

```yaml
metadata:
  id: "path-traversal"
  name: "Path Traversal / File Inclusion"
  description: "Detects path traversal via file path payloads"
  severity: "high"
  engine: "http"

method: "GET"
path: "/file=FUZZ"

payloads:
  - name: "etc-passwd"
    value: "../../../../etc/passwd"
  - name: "etc-passwd-windows"
    value: "..\\..\\..\\windows\\win.ini"
  - name: "etc-shadow"
    value: "../../../../etc/shadow"
  - name: "deep-traversal"
    value: "../../../../../../../../etc/passwd"

matchers:
  - type: "keyword"
    patterns:
      - "root:x:0:0"
      - "daemon:x:1:1"
      - "bin:x:2:2"
      - "for 16-bit app support"
      - "[extensions]"
    location: "body"
    condition: "or"
```

### 5.4 IDOR Plugin (`plugins/idor.yaml`)

```yaml
metadata:
  id: "idor"
  name: "Insecure Direct Object Reference"
  description: "Detects IDOR by accessing another user's resource"
  severity: "high"
  engine: "http"

method: "GET"
path: "/api/users/FUZZ"

payloads:
  - name: "adjacent-id"
    value: "1001"
  - name: "negative-id"
    value: "-1"
  - name: "zero-id"
    value: "0"
  - name: "uuid-guess"
    value: "00000000-0000-0000-0000-000000000001"

matchers:
  - type: "status"
    patterns:
      - "200"
    location: "status"
    negative: false

  - type: "keyword"
    patterns:
      - "\"email\":"
      - "\"role\":"
      - "\"is_admin\":"
    location: "body"
    condition: "or"
```

### 5.5 Open Redirect Plugin (`plugins/open_redirect.yaml`)

```yaml
metadata:
  id: "open-redirect"
  name: "Open Redirect"
  description: "Detects unvalidated redirects via redirect parameters"
  severity: "medium"
  engine: "http"

method: "GET"
path: "/redirect?url=FUZZ&next=FUZZ&return=FUZZ"

payloads:
  - name: "external-http"
    value: "http://evil.com"
  - name: "external-https"
    value: "https://evil.com"
  - name: "protocol-relative"
    value: "//evil.com"
  - name: "data-url"
    value: "data:text/html;base64,test"

matchers:
  - type: "keyword"
    patterns:
      - "evil\\.com"
      - "Location: http://evil"
      - "Location: //evil"
    location: "header"
    condition: "or"

  - type: "status"
    patterns:
      - "301"
      - "302"
      - "303"
      - "307"
      - "308"
    location: "status"
    condition: "or"
```

### 5.6 XXE Plugin (`plugins/xxe.yaml`)

```yaml
metadata:
  id: "xxe"
  name: "XML External Entity Injection"
  description: "Detects XXE by injecting external entity definitions"
  severity: "critical"
  engine: "http"

method: "POST"
path: "/"
body: |
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>

headers:
  Content-Type: "application/xml"

payloads:
  - name: "file-read"
    value: '/etc/passwd'
  - name: "internal-srv"
    value: 'http://169.254.169.254/latest/meta-data/'

matchers:
  - type: "keyword"
    patterns:
      - "root:x:0:0"
      - "daemon:x:1:1"
    location: "body"
    condition: "or"
```

### 5.7 SSRF Plugin (`plugins/ssrf.yaml`)

```yaml
metadata:
  id: "ssrf"
  name: "Server-Side Request Forgery"
  description: "Detects SSRF by injecting internal/external URLs"
  severity: "high"
  engine: "http"

method: "GET"
path: "/fetch?url=FUZZ&file=FUZZ&path=FUZZ"

payloads:
  - name: "local-host"
    value: "http://127.0.0.1:80"
  - name: "local-ip"
    value: "http://10.0.0.1:80"
  - name: "metadata-aws"
    value: "http://169.254.169.254/latest/meta-data/"
  - name: "metadata-gcp"
    value: "http://metadata.google.internal/"
  - name: "internal-service"
    value: "http://localhost:8080/admin"

matchers:
  - type: "keyword"
    patterns:
      - "root:x:0:0"
      - "ami-id"
      - "instance-id"
      - "meta-data"
      - "computeMetadata"
    location: "body"
    condition: "or"

  - type: "status"
    patterns:
      - "200"
    location: "status"
```

---

## 6. Core Algorithm

### 6.1 Plugin Execution Flow

```
Execute(target, task):
  plugins ← LoadPlugins(task.TemplateID)   // Filter by template ID or tags
  results ← []

  FOR plugin IN plugins:
    FOR payload IN plugin.Payloads:
      request ← BuildRequest(target, plugin, payload)
      response ← SendRequest(request)

      matchResult ← MatchResponse(response, plugin.Matchers, payload)

      IF matchResult.Matched:
        results ← append PluginResult{
          PluginID:  plugin.ID,
          Matched:   true,
          Severity:  plugin.Severity,
          Matches:   [matchResult],
          Evidence:  matchResult.Evidence,
          Payload:   payload.Value,
        }
        BREAK  // One match per plugin is enough

  RETURN results
```

### 6.2 Matching Strategies

| Matcher Type | How It Works | Example |
|-------------|--------------|---------|
| `keyword` | Response body/header contains pattern string | Body contains `"root:x:0:0"` |
| `regex` | Response matches regex pattern | `ora-[0-9]{5}` |
| `error_based` | Response contains SQL/database error messages | `"you have an error in your sql"` |
| `boolean` | Compare two responses — different = vulnerable | True condition returns different content than false |
| `time_based` | Response time exceeds threshold | Response takes >5 seconds |
| `status` | HTTP status code matches | `200`, `301`, `302` |

### 6.3 Boolean-based Blind Detection Algorithm

```
MatchBoolean(response, payload):
  // Send true-condition payload
  trueResponse ← Send(payload.TrueValue)
  
  // Send false-condition payload
  falseResponse ← Send(payload.FalseValue)
  
  // If responses differ significantly → likely vulnerable
  similarity ← Compare(trueResponse.Body, falseResponse.Body)
  
  RETURN similarity < threshold
```

### 6.4 Time-based Blind Detection Algorithm

```
MatchTimeBased(response, payload, requestStart):
  elapsed ← time.Since(requestStart)
  
  // If response took significantly longer than expected
  // (e.g., SLEEP(5) caused 5+ second delay)
  RETURN elapsed > payload.ExpectedDelay * 0.8
```

---

## 7. Integration with Existing Scan Flow

### 7.1 Modified HTTPEngine.Execute()

```go
// Current stub
func (e *HTTPEngine) Execute(ctx context.Context, task Task) *Result {
    return &Result{Finding: &Finding{Matched: false}}
}

// New implementation
func (e *HTTPEngine) Execute(ctx context.Context, task Task) *Result {
    detector := detector.New(e.config.DetectorConfig)
    
    pluginResults := detector.Run(ctx, task.Target, task.TemplateID)
    
    if len(pluginResults) > 0 {
        return &Result{
            Finding: &Finding{
                Target:     task.Target,
                TemplateID: task.TemplateID,
                Matched:    true,
                Severity:   pluginResults[0].Severity,
                Details:    map[string]interface{}{
                    "plugin":      pluginResults[0].PluginID,
                    "matches":     pluginResults[0].Matches,
                    "evidence":    pluginResults[0].Evidence,
                },
            },
        }
    }
    
    return &Result{Finding: &Finding{
        Target:     task.Target,
        TemplateID: task.TemplateID,
        Matched:    false,
        Severity:   "info",
    }}
}
```

### 7.2 Config Additions (`config.yaml`)

```yaml
detector:
  plugins_dir: "./plugins"
  default_severity: "info"
  max_payloads_per_plugin: 20
  timeout: "10s"
  boolean:
    threshold: 0.8       # Response similarity threshold (0.0-1.0)
  time_based:
    baseline_ms: 200     # Baseline response time (ms)
    multiplier: 3        # Delay multiplier to confirm
```

### 7.3 API Changes

| Endpoint | Change |
|----------|--------|
| `GET /api/templates` | Now returns both Nuclei templates + built-in detection plugins |
| `GET /api/templates/{id}` | Plugin details with payload/matcher info |

No new endpoints — plugins are a type of template from the API perspective.

---

## 8. Phased Implementation Plan

### Phase 1: Core Framework (Priority: High)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 1.1 | Define plugin types and YAML schema | `types.go`, `plugin.go` | None |
| 1.2 | Implement plugin loader (parse YAML files) | `detector.go`, `registry.go` | Phase 1.1 |
| 1.3 | Implement placeholder replacement (FUZZ, HOST, PORT) | `payload/placeholder.go` | None |
| 1.4 | Implement request builder (method, path, headers, body) | `engine/http_executor.go` | Phase 1.3 |
| 1.5 | Implement keyword matcher | `matcher/keyword.go` | None |
| 1.6 | Implement regex matcher | `matcher/regex.go` | None |
| 1.7 | Implement status code matcher | `matcher/status.go` | None |
| 1.8 | Integrate detector into HTTPEngine.Execute() | `engine/http_executor.go` + `scanner/scanner.go` | All above |

**Effort estimate:** 4-5 days

### Phase 2: Advanced Matchers (Priority: High)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 2.1 | Implement error-based matcher (SQL error patterns) | `matcher/error_based.go` | Phase 1 |
| 2.2 | Implement boolean-based blind matcher | `matcher/boolean.go` | Phase 1 |
| 2.3 | Implement time-based blind matcher | `matcher/time_based.go` | Phase 1 |
| 2.4 | Implement response comparison utility | `matcher/compare.go` | None |

**Effort estimate:** 3-4 days

### Phase 3: Built-in Plugins (Priority: High)

| # | Task | Plugins |
|---|------|---------|
| 3.1 | SQL Injection plugin (error-based, boolean, time-based) | `plugins/sql_injection.yaml` |
| 3.2 | XSS plugin (reflected, stored, DOM) | `plugins/xss.yaml` |
| 3.3 | Path Traversal / File Inclusion plugin | `plugins/path_traversal.yaml` |
| 3.4 | IDOR plugin | `plugins/idor.yaml` |
| 3.5 | Open Redirect plugin | `plugins/open_redirect.yaml` |
| 3.6 | XXE plugin | `plugins/xxe.yaml` |
| 3.7 | SSRF plugin | `plugins/ssrf.yaml` |

**Effort estimate:** 2-3 days

### Phase 4: Integration & Testing (Priority: High)

| # | Task | Files | Dependencies |
|---|------|-------|-------------|
| 4.1 | Integrate detector into HTTPEngine | `scanner/scanner.go` | Phase 1-3 |
| 4.2 | Add detector config to viper loader | `config/config.go` | Phase 1 |
| 4.3 | Unit tests for all matchers | `matcher/*_test.go` | Phase 1-2 |
| 4.4 | Unit tests for plugin loader | `detector_test.go` | Phase 1 |
| 4.5 | Integration tests (httptest server with known vulns) | `test/e2e/detector/` | Phase 3 |
| 4.6 | Benchmarks for plugin execution | `test/benchmarks/` | Phase 1-3 |

**Effort estimate:** 2-3 days

### Phase 5: Advanced Features (Priority: Low)

| # | Task | Description |
|---|------|-------------|
| 5.1 | Headless engine integration | DOM-based XSS detection via chromedp |
| 5.2 | Custom user plugins | User-uploaded YAML plugins per scan |
| 5.3 | Plugin chaining | Chain multiple plugins for multi-step vulns |
| 5.4 | Payload fuzzing | Smart payload generation from wordlists |
| 5.5 | WAF bypass payloads | Additional payload variants for WAF evasion |

**Effort estimate:** 5-7 days total

---

## 9. Testing Strategy

### 9.1 Unit Tests

| Component | Test Cases |
|-----------|------------|
| `plugin.go` | Parse valid YAML, parse missing fields, parse invalid YAML, default values |
| `payload/placeholder.go` | Single FUZZ, multiple FUZZ (e.g., 2 params), no placeholders, URL encoding |
| `engine/http_executor.go` | Build GET request, build POST request with body, custom headers, path injection |
| `matcher/keyword.go` | Match found, match not found, case insensitive, multi-pattern OR/AND, negative match |
| `matcher/regex.go` | Valid regex match, no match, invalid regex (graceful), multi-pattern |
| `matcher/error_based.go` | MySQL error, PostgreSQL error, MSSQL error, Oracle error, no error |
| `matcher/boolean.go` | Different responses (vulnerable), identical responses (not vulnerable), partial diff |
| `matcher/time_based.go` | Response > threshold (match), response < threshold (no match), edge cases |

### 9.2 Integration Tests

| Test | Description |
|------|-------------|
| SQL injection | httptest server that echoes payload + simulates SQL error on `'` → verify detection |
| XSS reflected | httptest server that reflects `<script>` back in body → verify match |
| Path traversal | httptest server that serves `/etc/passwd` for `../../` paths → verify keyword match |
| Boolean blind | httptest server returning different content for `1=1` vs `1=2` → verify boolean detection |
| Time-based | httptest server with `SLEEP(5)` delay on specific payload → verify time detection |
| SSRF | httptest server with metadata endpoint → verify callback detection |

### 9.3 Test Data

- `testdata/plugins/valid/` — Directory with valid plugin YAML files
- `testdata/plugins/invalid/` — Directory with malformed plugin YAML files
- `httptest.NewServer` with configurable handlers for each vuln type
- Pre-recorded response bodies for error-based detection testing

---

## 10. Plugin Execution Performance

| Vuln Type | Payloads | Requests per Plugin | Est. Time (10s timeout) |
|-----------|----------|---------------------|------------------------|
| SQLi (error) | 5 | 5 | ~5s |
| SQLi (boolean) | 2 pairs | 4 | ~4s |
| SQLi (time-based) | 2 | 2 | ~10s+ |
| XSS | 5 | 5 | ~5s |
| Path Traversal | 4 | 4 | ~4s |
| IDOR | 4 | 4 | ~4s |
| Open Redirect | 4 | 4 | ~4s |
| XXE | 2 | 2 | ~2s |
| SSRF | 5 | 5 | ~5s |
| **Total** | **~34** | **~35** | **~40s** |

Performance mitigation: run plugins **concurrently** per target. With worker pool of 50, 35 requests spread across workers = ~1-2s per target.

---

## 11. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Time-based detection slows down scans | Configurable timeout; run time-based plugins last; max 2 time-based payloads per plugin |
| Boolean blind generates many requests | Limit to 2 comparison pairs per plugin; configurable threshold |
| False positives from error-based matchers | Regex patterns are scoped (e.g., `ora-[0-9]{5}` not just `error`); user can tune patterns |
| XXE/SSRF calls out to external servers | Default plugins use local-only payloads (file://, 127.0.0.1); outbound callback requires explicit config |
| Plugin YAML parsing panics | Recovery per plugin (defer/recover); malformed plugin is skipped, not fatal |
| Large number of plugins per target | Configurable `max_payloads_per_plugin`; first match breaks per plugin |

---

## 12. Success Criteria

| Metric | Target |
|--------|--------|
| SQLi detection rate (error-based) | >90% of test cases |
| SQLi detection rate (boolean blind) | >85% of test cases |
| SQLi detection rate (time-based) | >80% of test cases |
| XSS reflected detection rate | >90% of test cases |
| False positive rate | <5% across all plugins |
| Test coverage | >80% on all detector packages |
| Plugin load time (7 plugins) | <100ms |
| No breaking changes | Existing worker pool + scan flow unchanged |
