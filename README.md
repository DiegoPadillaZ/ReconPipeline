# ThreatLens

A Go-based cybersecurity **intelligence engine** — not a scanner.

ThreatLens collects HTTP metadata from websites and correlates findings with MITRE ATT&CK, CAPEC, CWE, and OWASP to explain *why* each finding matters, how an attacker could abuse it, and what should be done about it.

---

## Features

- Collects HTTP headers, TLS details, cookies, redirects, and server banners
- Detects server/framework/language/CDN via fingerprinting
- Offline knowledge database (YAML) — no internet required during a scan
- Correlates findings against security header best practices and TLS weaknesses
- Risk scoring (0–10) weighted by severity and confidence
- Five output formats: **JSON**, **Markdown**, **HTML**, **CSV**, **SARIF 2.1.0**
- Concurrent scanning with worker pool and graceful shutdown
- SQLite persistence for scan history
- Docker and GitHub Actions CI included

---

## Requirements

| Tool | Version |
|---|---|
| Go | 1.25+ |
| Git | any |
| Docker | optional |

---

## Installation

### From source

```sh
git clone https://github.com/DiegoPadillaZ/ReconPipeline.git
cd threatlens
go build -o threatlens ./cmd/threatlens
```

Move the binary to your PATH:

```sh
# Linux/macOS
mv threatlens /usr/local/bin/

# Windows (PowerShell)
Move-Item threatlens.exe C:\Windows\System32\
```

### With Go install

```sh
go install github.com/DiegoPadillaZ/ReconPipeline/cmd/threatlens@latest
```

### Docker

```sh
docker build -t threatlens .
docker run --rm threatlens scan https://example.com
```

---

## Quick Start

> All examples use `go run` (no build step required). If you built the binary, replace
> `go run ./cmd/threatlens` with `./threatlens` (Linux/macOS) or `.\threatlens.exe` (Windows).

### 1 — First scan (JSON, default)

```sh
go run ./cmd/threatlens scan -c config.example.yaml https://example.com
# Output: ./reports/report.json
```

### 2 — HTML report you can open in a browser

```sh
go run ./cmd/threatlens scan -c config.example.yaml -f html -o ./reports https://example.com
# Output: ./reports/report.html
```

### 3 — Custom report name

```sh
go run ./cmd/threatlens scan -c config.example.yaml -f html -n tesla-audit -o ./reports https://www.tesla.com
# Output: ./reports/tesla-audit.html
```

### 4 — All five output formats

```sh
go run ./cmd/threatlens scan -c config.example.yaml -f json     -n scan-result -o ./reports https://example.com
go run ./cmd/threatlens scan -c config.example.yaml -f markdown -n scan-result -o ./reports https://example.com
go run ./cmd/threatlens scan -c config.example.yaml -f html     -n scan-result -o ./reports https://example.com
go run ./cmd/threatlens scan -c config.example.yaml -f csv      -n scan-result -o ./reports https://example.com
go run ./cmd/threatlens scan -c config.example.yaml -f sarif    -n scan-result -o ./reports https://example.com
```

### 5 — Scan multiple targets at once

```sh
go run ./cmd/threatlens scan -c config.example.yaml -f html -n multi-scan \
  https://example.com https://www.tesla.com https://google.com
```

### 6 — Targets defined in the config file

Edit `config.yaml`:
```yaml
targets:
  - https://example.com
  - https://www.tesla.com
```
Then run:
```sh
go run ./cmd/threatlens scan -c config.yaml -f html -n my-report -o ./reports
```

### 7 — Debug mode (see every pipeline step)

```sh
go run ./cmd/threatlens scan -c config.example.yaml -v debug https://example.com
# Logs: DNS/TCP/TLS timing, parser, fingerprint, correlation, risk score steps
```

### 8 — SARIF for GitHub Code Scanning / VS Code

```sh
go run ./cmd/threatlens scan -c config.example.yaml -f sarif -n results -o ./reports https://example.com
# Output: ./reports/results.sarif
# Upload to GitHub: Settings → Security → Code scanning → Upload SARIF
```

All reports are saved in the directory set by `-o` (default: `./reports/`).
The SQLite scan history is stored alongside them as `threatlens.db`.

---

## Configuration

Copy the example config and edit as needed:

```sh
cp config.example.yaml config.yaml
```

Key fields:

```yaml
concurrency: 5          # parallel scans
timeout_seconds: 30
knowledge_db_path: "./knowledge"
output_dir: "./reports"
verbosity: "info"       # debug | info | warn | error

targets:
  - https://example.com
  - https://other.example.org
```

Full reference: [config.example.yaml](config.example.yaml)

---

## CLI Reference

```
threatlens scan [url...] [flags]

Flags:
  -f, --format string      report format: json|markdown|html|csv|sarif (default "json")
  -n, --name string        output filename without extension (default "report")
  -o, --output string      output directory for reports (default "./reports")
  -c, --config string      config file (default: threatlens.yaml)
  -v, --verbosity string   log level: debug | info | warn | error (default "info")

Examples:
  # Minimal — JSON to ./reports/report.json
  threatlens scan -c config.yaml https://example.com

  # Named HTML report
  threatlens scan -c config.yaml -f html -n my-report -o ./reports https://example.com

  # Multiple targets, CSV output
  threatlens scan -c config.yaml -f csv -n batch https://a.com https://b.com

  # Full debug output
  threatlens scan -c config.yaml -v debug https://example.com
```

---

## Running Tests

```sh
# All tests
go test ./...

# With coverage
go test ./... -cover

# End-to-end only
go test ./tests/...

# Race detector
go test -race ./...
```

---

## Project Structure

```
cmd/threatlens/       CLI entry point (Cobra)
internal/
  collector/          HTTP metadata collection (no analysis)
  parser/             Normalize raw data → internal models
  fingerprint/        Detect server, framework, CDN, language
  knowledge/          Offline YAML knowledge database
  correlation/        Map findings to attack scenarios
  risk/               Severity scoring and recommendations
  report/             JSON / Markdown / HTML / CSV / SARIF output
  database/           SQLite persistence
  plugins/            Plugin registry
models/               Shared domain types
pkg/utils/            Pure utilities
knowledge/            Seed YAML knowledge files
tests/                End-to-end integration tests
```

---

## Knowledge Database

Knowledge files live in `./knowledge/` and are plain YAML — no internet connection needed at scan time.

| File | Content |
|---|---|
| `security_headers.yaml` | Missing security header findings |
| `tls.yaml` | Weak protocol / cipher findings |
| `server.yaml` | Server/framework/language disclosure findings |
| `meta.yaml` | DB version metadata |

To add your own findings, drop a `.yaml` file into the `knowledge/` directory and restart the scan.

---

## Output Formats

| Format | Use case |
|---|---|
| `json` | Machine-readable, API integration |
| `markdown` | Documentation, GitHub issues |
| `html` | Human-readable browser report |
| `csv` | Spreadsheet import, ticket systems |
| `sarif` | GitHub Code Scanning, VS Code, IDE plugins |

---

## Security

- No credentials or secrets are stored in code or config files — use environment variables.
- TLS verification is enabled by default (`InsecureSkipVerify: false`).
- Knowledge DB integrity is checked at startup.
- Input URLs are validated at the system boundary before any network call is made.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for new behaviour
4. Run `go test ./...` and `go vet ./...`
5. Open a pull request

See [AGENTS.md](AGENTS.md) for architecture rules and code conventions that all contributions must follow.

---

## License

MIT — see [LICENSE](LICENSE) for details.
