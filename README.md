# dorkforge

`dorkforge` is a high-performance, modular Command-Line Interface (CLI) tool written in Go for automated search engine dorking, passive reconnaissance, and attack surface exposure assessment.

It generates structured, targeted queries across major search providers (Google, GitHub Code Search, DuckDuckGo, Bing, and Shodan) categorized by risk severity and asset type.

---

## Key Features

- **12 Specialized Categories**: Configurations, credentials & secrets, administration panels, database dumps, cloud storage buckets, source code leaks, application logs & error traces, sensitive documents, API endpoints & OpenAPI specs, subdomain discovery, IoT/network appliances, and OSINT employee footprints.
- **Multi-Engine Adapters**: Native query synthesis and URL generation for **Google**, **GitHub Code Search**, **DuckDuckGo**, **Bing**, and **Shodan**.
- **Multi-Target Support**: Audit single targets (`-d target.com`) or iterate over target lists (`-l domains.txt`).
- **Flexible Filtering**: Filter by category (`-c configs,secrets`), severity (`--min-severity high`), search engine (`-e google,github`), or text search (`-q password`).
- **Export Capabilities**: Export findings to **Markdown** audit reports, **JSON** data structures, interactive **HTML** dashboards, or plain **URL** lists.
- **Safe Browser Launching**: Interactive `--open` mode with configurable batching (`--batch-size 5`) and delay (`--delay 2000`) to avoid anti-bot rate limits.
- **Subdomain Enumeration**: Dedicated `subdomains` command to generate negative exclusion chains for subdomain discovery.
- **Extensible**: Load custom signature rules via JSON files (`--custom ./my-dorks.json`).
- **Zero External Dependencies**: Built strictly with standard Go libraries and ANSI formatting for fast, self-contained single binaries.

---

## Installation

### From Source (Requires Go 1.22+)

```bash
git clone https://github.com/Nerd658/dorkforge.git
cd dorkforge
make build
# Binary will be placed in ./bin/dorkforge
```

### Install to System

```bash
make install
# or
go install github.com/Nerd658/dorkforge/cmd/dorkforge@latest
```

---

## Usage Guide

### 1. Basic Scan
Scan a domain across all default categories:

```bash
dorkforge scan -d example.com
```

### 2. High-Severity & Specific Categories
Target only configuration files and leaked credentials with high or critical severity:

```bash
dorkforge scan -d example.com -c configs,secrets -s high
```

### 3. Generate Reports (Markdown, HTML, JSON)
Export results directly to a formatted Markdown audit report or interactive HTML dashboard:

```bash
# Markdown Report
dorkforge scan -d example.com -o audit-report.md -f markdown

# Interactive HTML Dashboard
dorkforge scan -d example.com -o dashboard.html -f html

# JSON Export
dorkforge scan -d example.com -o dorks.json -f json
```

### 4. Subdomain Discovery
Generate negative search engine queries excluding known subdomains:

```bash
dorkforge subdomains -d example.com --exclude mail,blog,dev
```

### 5. Multi-Target Batch Processing
Audit a list of domains from a file:

```bash
dorkforge scan -l targets.txt -s high -o multi-target-report.md
```

### 6. Safe Browser Launching
Open generated queries directly in your default browser in controlled batches:

```bash
dorkforge scan -d example.com -c configs,admin --open --batch-size 5 --delay 2000
```

### 7. List Built-in Catalog
Inspect all signatures in the built-in database:

```bash
dorkforge list
dorkforge list -c secrets
```

---

## Supported Categories

| Category | Severity | Description |
|---|---|---|
| `configs` | **CRITICAL** | Exposed `.env`, `wp-config.php`, web server configs, `docker-compose.yml` |
| `secrets` | **CRITICAL** | AWS access keys, SSH/RSA private keys, GitHub tokens, database connection URIs |
| `admin` | **HIGH** | Administrative portals, phpMyAdmin, Jenkins, Grafana, Kibana, Portainer |
| `backups` | **HIGH** | Database dumps (`.sql`, `.dump`), compressed source archives (`.tar.gz`, `.zip`) |
| `cloud` | **HIGH / MED** | Public Amazon S3 buckets, Azure Blob containers, Google Cloud Storage |
| `source-code` | **HIGH** | Exposed `.git` folders, code leaks on GitHub / GitLab |
| `errors` | **MEDIUM** | PHP info diagnostics, framework stack traces, application error logs |
| `docs` | **MED / LOW** | Confidential PDF documents, payroll spreadsheets, internal organigrams |
| `api-endpoints` | **HIGH** | Exposed Swagger/OpenAPI specs, GraphQL consoles, Postman collections |
| `subdomains` | **LOW** | Search engine exclusion chains and Shodan SSL certificate recon |
| `network-iot` | **HIGH** | Router/firewall interfaces (pfSense, FortiGate), web terminals |
| `employees-osint` | **LOW** | LinkedIn profiles, employee directories, email footprinting |

---

## Project Structure

```
dorkforge/
├── cmd/
│   └── dorkforge/
│       └── main.go              # CLI Entrypoint & Flag routing
├── internal/
│   ├── models/
│   │   ├── dork.go              # Core data models (Dork, Category, Severity, Engine)
│   │   └── dork_test.go         # Model unit tests
│   ├── dorks/
│   │   ├── catalog.go           # Embedded signatures catalog
│   │   └── custom.go            # Custom JSON dork loader
│   ├── engine/
│   │   ├── builder.go           # Target sanitization & query URL generator
│   │   └── builder_test.go      # Engine unit tests
│   ├── output/
│   │   ├── console.go           # Terminal table formatter with ANSI colors
│   │   ├── exporter.go          # Exporters (Markdown, HTML, JSON, URLs)
│   │   └── exporter_test.go     # Exporter unit tests
│   ├── browser/
│   │   └── opener.go            # Cross-platform browser launcher with batching
│   └── subdomains/
│       ├── enum.go              # Subdomain exclusion query generator
│       └── enum_test.go         # Subdomain unit tests
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated CI test pipeline
├── Makefile                     # Build, test, and install automation
├── go.mod                       # Go module definition
└── README.md                    # Project documentation
```

---

## Running Tests

```bash
make test
# or
go test -v -race ./...
```

---

## License

This project is licensed under the MIT License.
