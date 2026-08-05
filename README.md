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

```sh
# Scan a single URL (JSON output)
threatlens scan https://example.com

# HTML report
threatlens scan -f html -o ./reports https://example.com

# SARIF (for GitHub Code Scanning / IDE integration)
threatlens scan -f sarif -o ./reports https://example.com

# Multiple targets with a config file
threatlens scan -c config.yaml
```

Reports are written to `./reports/` (or the directory specified by `-o`).

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
  -f, --format string    report format: json|markdown|html|csv|sarif (default "json")
  -o, --output string    output directory (default "./reports")
  -c, --config string    config file (default: threatlens.yaml)
  -v, --verbosity string log level: debug | info | warn | error
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
