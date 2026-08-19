# dorkforge (dfg)

`dorkforge` is a high-performance, modular Command-Line Interface (CLI) tool written in Go for automated search engine dorking, passive reconnaissance, historical archive mining, live search results scraping, and attack surface exposure assessment.

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
  - `network-iot`: Router/firewall portals (pfSense, FortiGate), web shells & terminal emulators, IP cameras & surveillance.
  - `employees-osint`: LinkedIn employee footprinting, corporate staff directories, paste site disclosures.
- **Historical Web Archive Mining (`fetch`)**: Interrogates **Wayback Machine (CDX)** and **AlienVault (OTX)** APIs to passively uncover historical, forgotten, or deleted endpoints and sensitive assets.
- **Live Search Results Extraction (`scan --live`)**: Built-in DuckDuckGo HTML parser that queries search engines in the background and prints real target URLs directly in the terminal.
- **Active Endpoint Probing (`probe` & `scan --probe`)**: High-throughput concurrent HTTP prober to test live status codes (`200 OK`, `403 Forbidden`, `401 Unauthorized`) of critical paths.
- **Multi-Engine Adapters**: Native query synthesis and URL generation for **Google**, **GitHub Code Search**, **DuckDuckGo**, **Bing**, and **Shodan**.
- **Shell Autocompletion & Short Alias**: Built-in autocompletion generator for **Bash**, **Zsh**, and **Fish**, plus automatic `./bin/dfg` shortcut generation.
- **Interactive Training Academy**: Complete hands-on course in [docs/TUTORIAL_INTERACTIF.md](docs/TUTORIAL_INTERACTIF.md) and interactive single-page web app in [docs/tutorial.html](docs/tutorial.html).
- **Zero External Dependencies**: Built strictly with standard Go libraries and ANSI formatting for fast, self-contained single binaries.

---

## Installation

### From Source (Requires Go 1.22+)

```bash
git clone https://github.com/Nerd658/dorkforge.git
cd dorkforge
make build
# Binaries placed in ./bin/dorkforge and symlink ./bin/dfg
```

### Install to System

```bash
make install
# or
go install github.com/Nerd658/dorkforge/cmd/dorkforge@latest
```

### Run with Docker / Docker Compose

```bash
# Build the container image
docker compose build

# Run reconnaissance scan and save HTML report locally in ./reports
docker compose run --rm dorkforge scan -d example.com -o /app/reports/audit.html -f html

# Mine historical archive URLs
docker compose run --rm dorkforge fetch -d example.com --subs --sensitive-only -o /app/reports/urls.txt
```

---

## Usage Guide

### 1. Basic & Filtered Reconnaissance Scan
Scan a domain across all default categories or target specific high-risk assets:

```bash
# General scan
dfg scan -d example.com

# Critical configs and leaked credentials
dfg scan -d example.com -c configs,secrets -s high
```

### 2. Live Search Results Scraping (`--live`)
Extract real target links indexed by search engines directly into your terminal without opening a browser:

```bash
dfg scan -d example.com -c configs,secrets --live
```

### 3. Historical Web Archive Mining (`fetch`)
Passively extract all known URLs ever indexed on the target domain from Wayback Machine and AlienVault OTX:

```bash
# Mining sensitive assets across all subdomains
dfg fetch -d example.com --subs --sensitive-only -o archive_urls.txt
```

### 4. Active Endpoint Probing (`probe`)
Concurrently test whether critical endpoints (`/.env`, `/.git/HEAD`, `/actuator/env`, `/swagger.json`) respond `200 OK` on the target server:

```bash
dfg probe -d example.com -t 20 -o live_audit.html -f html
```

### 5. Generate Reports (Markdown, HTML, JSON)
Export findings directly to a formatted Markdown audit report, interactive HTML dashboard, or JSON:

```bash
# Markdown Report
dfg scan -d example.com -o audit-report.md -f markdown

# Interactive HTML Dashboard
dfg scan -d example.com -o dashboard.html -f html

# JSON Export
dfg scan -d example.com -o dorks.json -f json
```

### 6. Subdomain Discovery
Generate negative search engine queries excluding known subdomains:

```bash
dfg subdomains -d example.com --exclude mail,blog,dev,vpn
```

### 7. Safe Browser Launching
Open generated queries in your default browser in controlled batches:

```bash
dfg scan -d example.com -c configs,admin --open --batch-size 3 --delay 2000
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
│   │   └── dork.go                  # Core data models (Dork, Category, Severity, Engine)
│   ├── dorks/
│   │   ├── catalog.go               # Base embedded signatures catalog
│   │   ├── expanded.go              # Exploit-DB GHDB and modern cloud signatures
│   │   └── custom.go                # Custom JSON dork loader
│   ├── fetcher/
│   │   ├── fetcher.go               # Historical archive aggregator & sensitive classifier
│   │   ├── wayback.go               # Wayback Machine CDX API client
│   │   └── alienvault.go            # AlienVault OTX API client
│   ├── prober/
│   │   └── prober.go                # Concurrent HTTP endpoint status prober
│   ├── scraper/
│   │   ├── scraper.go               # Scraper interfaces and config
│   │   └── duckduckgo.go            # DuckDuckGo HTML search results parser
│   ├── engine/
│   │   └── builder.go               # Target sanitization & query URL generator
│   ├── completion/
│   │   └── completion.go            # Bash, Zsh, Fish completion script generator
│   ├── output/
│   │   ├── console.go               # Terminal table formatter with ANSI colors
│   │   └── exporter.go              # Exporters (Markdown, HTML, JSON, URLs)
│   ├── browser/
│   │   └── opener.go                # Cross-platform browser launcher with batching
│   └── subdomains/
│       └── enum.go                  # Subdomain exclusion query generator
├── docs/
│   ├── TUTORIAL_INTERACTIF.md       # Complete hands-on training course and labs
│   └── tutorial.html                # Interactive single-page web academy
├── Makefile                         # Build, test, install automation
├── go.mod                           # Go module definition
├── README.md                        # Project documentation
└── commit.txt                       # Git commit change summary
```

---

## Interactive Training Course

An in-depth training manual with practical labs is provided in the `docs/` folder:
- **Markdown Manual**: [docs/TUTORIAL_INTERACTIF.md](docs/TUTORIAL_INTERACTIF.md)
- **Interactive Web App**: [docs/tutorial.html](docs/tutorial.html) (Open in any browser)

---

## License

This project is licensed under the MIT License.
