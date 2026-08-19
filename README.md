# dorkforge

`dorkforge` is a high-performance, modular Command-Line Interface (CLI) tool written in Go for automated search engine dorking, passive reconnaissance, and attack surface exposure assessment.

It generates structured, targeted queries across major search providers (Google, GitHub Code Search, DuckDuckGo, Bing, and Shodan) categorized by risk severity and asset type, inspired by Exploit-DB's Google Hacking Database (GHDB) and modern Cloud/API security standards.

---

## Key Features

- **70+ Built-in Signatures across 12 Specialized Categories**:
  - `configs`: Exposed `.env`, Next.js/Nuxt envs, `wp-config.php`, Terraform `tfstate`, server configs (`nginx`, `apache`), `docker-compose.yml`, Prisma schema.
  - `secrets`: AWS access keys, SSH/RSA private keys, OpenAI API keys, Slack webhooks, Stripe live tokens, Twilio credentials, SendGrid keys.
  - `admin`: Management portals, phpMyAdmin, Jenkins CI, Grafana, Kibana, Kubernetes Dashboard, ArgoCD, SonarQube, Spring Boot Actuator endpoints.
  - `backups`: Database dumps (`.sql`, `.dump`, SQLite `.db`), compressed source archives (`.tar.gz`, `.zip`), Spring Boot heap dumps (`/actuator/heapdump`), open directory index listings.
  - `cloud`: Public Amazon S3 buckets & XML listings, Azure Blob storage, Google Cloud Storage, Firebase realtime databases, public Google Sheets/Drive, Notion workspaces.
  - `source-code`: Exposed `/.git`, `/.svn`, JavaScript/TypeScript `.js.map` source maps, GitLab CI configs, package registry tokens (`.npmrc`).
  - `errors`: Diagnostic pages (`phpinfo()`), Apache `/server-status`, framework debug stack traces (Django, ASP.NET), SQL syntax errors.
  - `docs`: Confidential PDFs, HR/payroll spreadsheets, client billing/invoice records, VPN WireGuard profiles.
  - `api-endpoints`: Swagger / OpenAPI documentation, GraphQL playgrounds & introspection, Postman collections, WSDL files.
  - `subdomains`: Negative exclusion query generator, Bing subdomain indexing, Shodan SSL certificate discovery.
  - `network-iot`: Router/firewall portals (pfSense, FortiGate, Cisco), web shells & terminal emulators, IP cameras & surveillance.
  - `employees-osint`: LinkedIn employee footprinting, corporate staff directories, paste site disclosures.
- **Multi-Engine Adapters**: Native query synthesis and URL generation for **Google**, **GitHub Code Search**, **DuckDuckGo**, **Bing**, and **Shodan**.
- **Shell Autocompletion**: Built-in autocompletion generator for **Bash**, **Zsh**, and **Fish**.
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

## Shell Autocompletion

### Bash
```bash
# Temporarily enable
source <(dorkforge completion bash)

# Persist for user session
dorkforge completion bash > ~/.local/share/bash-completion/completions/dorkforge
```

### Zsh
```bash
dorkforge completion zsh > "${fpath[1]}/_dorkforge"
```

### Fish
```bash
dorkforge completion fish > ~/.config/fish/completions/dorkforge.fish
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

## Project Structure

```
dorkforge/
├── cmd/
│   └── dorkforge/
│       └── main.go                  # CLI Entrypoint, completion & flag routing
├── internal/
│   ├── models/
│   │   ├── dork.go                  # Core data models (Dork, Category, Severity, Engine)
│   │   └── dork_test.go             # Model unit tests
│   ├── dorks/
│   │   ├── catalog.go               # Base embedded signatures catalog
│   │   ├── expanded.go              # Exploit-DB GHDB and modern cloud signatures
│   │   ├── catalog_test.go          # Catalog integrity test suite
│   │   └── custom.go                # Custom JSON dork loader
│   ├── engine/
│   │   ├── builder.go               # Target sanitization & query URL generator
│   │   ├── builder_test.go          # Engine unit tests
│   │   └── benchmark_test.go        # Engine performance benchmarks
│   ├── completion/
│   │   ├── completion.go            # Bash, Zsh, Fish completion script generator
│   │   └── completion_test.go       # Completion unit tests
│   ├── output/
│   │   ├── console.go               # Terminal table formatter with ANSI colors
│   │   ├── exporter.go              # Exporters (Markdown, HTML, JSON, URLs)
│   │   ├── exporter_test.go         # Exporter unit tests
│   │   └── benchmark_test.go        # Exporter performance benchmarks
│   ├── browser/
│   │   └── opener.go                # Cross-platform browser launcher with batching
│   └── subdomains/
│       ├── enum.go                  # Subdomain exclusion query generator
│       └── enum_test.go             # Subdomain unit tests
├── .github/
│   └── workflows/
│       └── ci.yml                   # Automated CI test pipeline
├── Makefile                         # Build, test, and install automation
├── go.mod                           # Go module definition
├── README.md                        # Project documentation
└── commit.txt                       # Git commit change summary
```

---

## Running Tests & Benchmarks

```bash
# Run unit tests
make test
# or
go test -v -race ./...

# Run benchmark suite
go test -bench=. -benchmem ./...
```

---

## License

This project is licensed under the MIT License.
