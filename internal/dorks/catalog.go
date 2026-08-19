package dorks

import (
	"github.com/Nerd658/dorkforge/internal/models"
)

var DefaultCatalog = []models.Dork{
	// ---------------------------------------------------------
	// 1. CONFIGS & ENVIRONMENT
	// ---------------------------------------------------------
	{
		ID:            "cfg-001",
		Title:         "Exposed .env and Environment Files",
		Description:   "Identifies public .env files potentially exposing secrets, database credentials, and API keys.",
		Category:      models.CategoryConfigs,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:env | ext:yml | ext:ini) (\"DB_PASSWORD\" | \"SECRET_KEY\" | \"JWT_SECRET\")",
		Tags:          []string{"env", "credentials", "config"},
		Remediation:   "Restrict web server access to dotfiles and configuration directories in Nginx/Apache.",
	},
	{
		ID:            "cfg-002",
		Title:         "WordPress wp-config Backup Files",
		Description:   "Searches for unhandled backup copies of wp-config containing raw database passwords.",
		Category:      models.CategoryConfigs,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:wp-config.php.bak | inurl:wp-config.old | inurl:wp-config.txt | inurl:wp-config.save)",
		Tags:          []string{"wordpress", "database", "backup"},
		Remediation:   "Ensure backup files outside the public document root or disable plain-text file extensions.",
	},
	{
		ID:            "cfg-003",
		Title:         "Exposed Web Server Configuration",
		Description:   "Finds web.config, nginx.conf, or httpd.conf files served publicly.",
		Category:      models.CategoryConfigs,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (filename:web.config | filename:nginx.conf | filename:httpd.conf)",
		Tags:          []string{"nginx", "apache", "iis"},
		Remediation:   "Deny HTTP access to server configuration templates and system files.",
	},
	{
		ID:            "cfg-004",
		Title:         "Exposed Docker Compose Configurations",
		Description:   "Detects docker-compose.yml files with container topologies and hardcoded environment values.",
		Category:      models.CategoryConfigs,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} filename:docker-compose.yml (\"services:\" | \"environment:\")",
		Tags:          []string{"docker", "containers"},
		Remediation:   "Never deploy infrastructure repository files to public web roots.",
	},

	// ---------------------------------------------------------
	// 2. SECRETS & CREDENTIALS
	// ---------------------------------------------------------
	{
		ID:            "sec-001",
		Title:         "Exposed AWS Access Keys",
		Description:   "Identifies pages or text files containing Amazon Web Services access keys.",
		Category:      models.CategorySecrets,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} \"AKIA\" (\"aws_secret_access_key\" | \"aws_access_key_id\")",
		Tags:          []string{"aws", "cloud-keys"},
		Remediation:   "Immediately rotate compromised AWS IAM access keys and enable AWS Secrets Manager.",
	},
	{
		ID:            "sec-002",
		Title:         "Exposed Private SSH/RSA Keys",
		Description:   "Searches for leaked private keys (id_rsa, .pem) exposed via web directories.",
		Category:      models.CategorySecrets,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (\"BEGIN RSA PRIVATE KEY\" | \"BEGIN OPENSSH PRIVATE KEY\" | \"BEGIN PRIVATE KEY\")",
		Tags:          []string{"ssh", "pki", "crypto"},
		Remediation:   "Revoke and re-issue all exposed private key pairs across affected hosts.",
	},
	{
		ID:            "sec-003",
		Title:         "GitHub Repository Secret Leakage",
		Description:   "Searches GitHub code search for target domain references alongside common token prefixes.",
		Category:      models.CategorySecrets,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGitHub,
		QueryTemplate: "\"{{TARGET}}\" AND (\"ghp_\" OR \"github_pat_\" OR \"glpat-\" OR \"xoxb-\")",
		Tags:          []string{"github", "tokens", "leaks"},
		Remediation:   "Implement pre-commit secret scanning (git-secrets, trufflehog) in developer workflows.",
	},
	{
		ID:            "sec-004",
		Title:         "Database Connection Strings",
		Description:   "Detects raw MongoDB, PostgreSQL, and MySQL connection URIs with embedded credentials.",
		Category:      models.CategorySecrets,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (\"mongodb://\" | \"postgres://\" | \"mysql://\") (\"password=\" | \"://admin:\")",
		Tags:          []string{"database", "passwords"},
		Remediation:   "Extract connection strings to secure environment variables or vault backends.",
	},

	// ---------------------------------------------------------
	// 3. ADMIN PORTALS & INTERFACES
	// ---------------------------------------------------------
	{
		ID:            "adm-001",
		Title:         "General Admin Login Portals",
		Description:   "Locates management panels and authentication portals exposed on the domain.",
		Category:      models.CategoryAdmin,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:admin | inurl:login | inurl:cpanel | inurl:dashboard | inurl:portal)",
		Tags:          []string{"auth", "admin", "login"},
		Remediation:   "Enforce IP allowlisting, VPN access, and Multi-Factor Authentication on admin routes.",
	},
	{
		ID:            "adm-002",
		Title:         "phpMyAdmin Interfaces",
		Description:   "Finds phpMyAdmin database administration web consoles.",
		Category:      models.CategoryAdmin,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:phpmyadmin | intitle:\"phpMyAdmin\")",
		Tags:          []string{"phpmyadmin", "mysql"},
		Remediation:   "Bind database management consoles strictly to localhost or internal network interfaces.",
	},
	{
		ID:            "adm-003",
		Title:         "CI/CD and Observability Dashboards",
		Description:   "Discovers Jenkins, Grafana, Kibana, and Portainer web dashboards.",
		Category:      models.CategoryAdmin,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (intitle:\"Dashboard [Jenkins]\" | intitle:\"Grafana\" | intitle:\"Kibana\" | intitle:\"Portainer\")",
		Tags:          []string{"jenkins", "grafana", "devops"},
		Remediation:   "Place internal operational tools behind a reverse proxy with single sign-on (SSO).",
	},

	// ---------------------------------------------------------
	// 4. DATABASE & BACKUP ARCHIVES
	// ---------------------------------------------------------
	{
		ID:            "bak-001",
		Title:         "Exposed SQL Database Dumps",
		Description:   "Finds raw database exports (.sql, .dump) containing schema and table contents.",
		Category:      models.CategoryBackups,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:sql | ext:dump | ext:db) (\"INSERT INTO\" | \"CREATE TABLE\" | \"mysqldump\")",
		Tags:          []string{"sql", "database", "dump"},
		Remediation:   "Store database backups in encrypted, non-public cloud buckets with strict IAM policies.",
	},
	{
		ID:            "bak-002",
		Title:         "Compressed Source and Backup Archives",
		Description:   "Detects archive files (.zip, .tar.gz, .bak) forgotten in public web trees.",
		Category:      models.CategoryBackups,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:tar.gz | ext:zip | ext:bak | ext:7z | ext:rar) (\"backup\" | \"site\" | \"db\")",
		Tags:          []string{"archive", "source"},
		Remediation:   "Audit public web server directories and purge manual zip/tar archive files.",
	},

	// ---------------------------------------------------------
	// 5. CLOUD STORAGE BUCKETS
	// ---------------------------------------------------------
	{
		ID:            "cld-001",
		Title:         "Public Amazon S3 Buckets",
		Description:   "Queries Amazon S3 domains for bucket names referencing the target organization.",
		Category:      models.CategoryCloud,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:s3.amazonaws.com \"{{TARGET}}\" | \"{{ORG}}\"",
		Tags:          []string{"aws", "s3", "cloud"},
		Remediation:   "Enable S3 Block Public Access at the account level and review bucket ACLs.",
	},
	{
		ID:            "cld-002",
		Title:         "Public Azure Blob Storage",
		Description:   "Discovers public Azure Blob containers referencing the target.",
		Category:      models.CategoryCloud,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:blob.core.windows.net \"{{TARGET}}\" | \"{{ORG}}\"",
		Tags:          []string{"azure", "blob", "cloud"},
		Remediation:   "Disable anonymous public read access on Azure Storage Accounts.",
	},
	{
		ID:            "cld-003",
		Title:         "Google Cloud Storage Buckets",
		Description:   "Discovers public GCS buckets referencing the target domain.",
		Category:      models.CategoryCloud,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:storage.googleapis.com \"{{TARGET}}\" | \"{{ORG}}\"",
		Tags:          []string{"gcp", "storage", "cloud"},
		Remediation:   "Enforce Uniform bucket-level access and remove allUsers / allAuthenticatedUsers roles.",
	},

	// ---------------------------------------------------------
	// 6. SOURCE CODE & REPOSITORIES
	// ---------------------------------------------------------
	{
		ID:            "src-001",
		Title:         "Exposed .git Repository Folders",
		Description:   "Finds misconfigured web servers exposing .git folder metadata over HTTP.",
		Category:      models.CategorySourceCode,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:/.git/HEAD | inurl:/.git/config | inurl:/.git/index)",
		Tags:          []string{"git", "source-leak"},
		Remediation:   "Configure web server rules to deny access to .git and all hidden directory paths.",
	},
	{
		ID:            "src-002",
		Title:         "GitHub Target Code Exposure",
		Description:   "Searches GitHub for target references inside internal configuration and credential files.",
		Category:      models.CategorySourceCode,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGitHub,
		QueryTemplate: "\"{{TARGET}}\" (filename:.npmrc OR filename:settings.xml OR filename:credentials)",
		Tags:          []string{"github", "code-search"},
		Remediation:   "Ensure internal repositories remain private and enforce strict push-protection rules.",
	},

	// ---------------------------------------------------------
	// 7. ERRORS & DIAGNOSTICS LOGS
	// ---------------------------------------------------------
	{
		ID:            "err-001",
		Title:         "PHP Info Diagnostic Pages",
		Description:   "Finds phpinfo() diagnostic pages displaying server internals, modules, and env vars.",
		Category:      models.CategoryErrors,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:php | ext:html) (intitle:\"phpinfo()\" | \"PHP Version\")",
		Tags:          []string{"php", "info-leak"},
		Remediation:   "Disable and delete testing phpinfo scripts on production environments.",
	},
	{
		ID:            "err-002",
		Title:         "Framework Debug and Stack Traces",
		Description:   "Detects unhandled application errors showing framework debug pages and file paths.",
		Category:      models.CategoryErrors,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (\"Django debug\" | \"Whoops! There was an error\" | \"Traceback (most recent call last)\")",
		Tags:          []string{"debug", "stacktrace"},
		Remediation:   "Disable DEBUG mode in production frameworks and implement custom error pages.",
	},
	{
		ID:            "err-003",
		Title:         "Public Application Log Files",
		Description:   "Finds server log files (.log, .txt) with error traces, IPs, and internal user activity.",
		Category:      models.CategoryErrors,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:log | ext:txt) (\"[error]\" | \"[warning]\" | \"stacktrace\")",
		Tags:          []string{"logs", "diagnostics"},
		Remediation:   "Store logs in dedicated centralized log systems outside the HTTP document tree.",
	},

	// ---------------------------------------------------------
	// 8. SENSITIVE DOCUMENTS & METADATA
	// ---------------------------------------------------------
	{
		ID:            "doc-001",
		Title:         "Confidential PDF Documents",
		Description:   "Searches for PDF documents containing markings such as confidential or internal use only.",
		Category:      models.CategoryDocs,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} ext:pdf (\"confidential\" | \"strictly private\" | \"internal use only\")",
		Tags:          []string{"pdf", "confidential", "docs"},
		Remediation:   "Review public document repositories and sanitize sensitive corporate metadata.",
	},
	{
		ID:            "doc-002",
		Title:         "Financial and HR Spreadsheets",
		Description:   "Detects Excel/CSV files containing payroll, salaries, budgets, or employee lists.",
		Category:      models.CategoryDocs,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:xlsx | ext:xls | ext:csv) (\"salary\" | \"payroll\" | \"budget\" | \"confidential\")",
		Tags:          []string{"excel", "finance", "hr"},
		Remediation:   "Never place financial and HR spreadsheets in publicly indexable web storage.",
	},

	// ---------------------------------------------------------
	// 9. API ENDPOINTS & WEB SERVICES
	// ---------------------------------------------------------
	{
		ID:            "api-001",
		Title:         "Swagger and OpenAPI Documentation",
		Description:   "Locates interactive Swagger UI, OpenAPI JSON/YAML specs, and API documentation.",
		Category:      models.CategoryAPIEndpoints,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:swagger.json | inurl:swagger-ui | inurl:api-docs | inurl:openapi.yaml)",
		Tags:          []string{"swagger", "openapi", "api"},
		Remediation:   "Authenticate or restrict API documentation endpoints if intended solely for internal teams.",
	},
	{
		ID:            "api-002",
		Title:         "GraphQL Console and Endpoints",
		Description:   "Finds public GraphQL introspection interfaces, GraphiQL, and GraphQL Playgrounds.",
		Category:      models.CategoryAPIEndpoints,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:graphql | inurl:graphiql | inurl:playground | inurl:altair)",
		Tags:          []string{"graphql", "api"},
		Remediation:   "Disable GraphQL schema introspection and playground interfaces in production.",
	},
	{
		ID:            "api-003",
		Title:         "Postman Collections and WSDL Definitions",
		Description:   "Searches for published Postman API collections or SOAP WSDL definitions.",
		Category:      models.CategoryAPIEndpoints,
		Severity:      models.SeverityMedium,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (ext:json \"postman_collection\" | ext:wsdl | inurl:\"?wsdl\")",
		Tags:          []string{"postman", "soap", "wsdl"},
		Remediation:   "Avoid hosting raw test collections or unauthenticated service descriptors on public hosts.",
	},

	// ---------------------------------------------------------
	// 10. SUBDOMAIN ENUMERATION (SEARCH SYNTAX)
	// ---------------------------------------------------------
	{
		ID:            "sub-001",
		Title:         "Google Subdomain Exclusion Query",
		Description:   "Uses search engine negation operators to isolate and enumerate exposed subdomains.",
		Category:      models.CategorySubdomains,
		Severity:      models.SeverityLow,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:*.{{TARGET}} -site:www.{{TARGET}} -site:{{TARGET}}",
		Tags:          []string{"subdomains", "recon"},
		Remediation:   "Maintain an accurate inventory of public DNS records and decommission unused subdomains.",
	},
	{
		ID:            "sub-002",
		Title:         "Shodan SSL Certificate Discovery",
		Description:   "Queries Shodan infrastructure for SSL certificates matching the target domain.",
		Category:      models.CategorySubdomains,
		Severity:      models.SeverityLow,
		Engine:        models.EngineShodan,
		QueryTemplate: "ssl.cert.subject.CN:\"{{TARGET}}\"",
		Tags:          []string{"shodan", "ssl", "infra"},
		Remediation:   "Review exposed certificate subjects and ensure internal hostnames are not broadcast.",
	},
	{
		ID:            "sub-003",
		Title:         "Bing Subdomain Reconnaissance",
		Description:   "Identifies subdomains indexed specifically in the Microsoft Bing search catalog.",
		Category:      models.CategorySubdomains,
		Severity:      models.SeverityLow,
		Engine:        models.EngineBing,
		QueryTemplate: "site:*.{{TARGET}} -site:www.{{TARGET}}",
		Tags:          []string{"bing", "subdomains"},
		Remediation:   "Regularly audit external search indexes for lingering development or testing subdomains.",
	},

	// ---------------------------------------------------------
	// 11. NETWORK & IOT DEVICES
	// ---------------------------------------------------------
	{
		ID:            "net-001",
		Title:         "Router and Firewall Management Panels",
		Description:   "Discovers exposed web interfaces for pfSense, FortiGate, and Cisco appliances.",
		Category:      models.CategoryNetworkIoT,
		Severity:      models.SeverityHigh,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (intitle:\"pfSense - Login\" | intitle:\"FortiGate\" | intitle:\"Cisco ASDM\")",
		Tags:          []string{"firewall", "router", "network"},
		Remediation:   "Disable remote web management on WAN interfaces and restrict to dedicated management VLANs.",
	},
	{
		ID:            "net-002",
		Title:         "Web Terminal and SSH Consoles",
		Description:   "Finds browser-based web terminal and shell consoles accessible from the internet.",
		Category:      models.CategoryNetworkIoT,
		Severity:      models.SeverityCritical,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (intitle:\"Web Shell\" | intitle:\"ttyload\" | inurl:webssh | inurl:wetty)",
		Tags:          []string{"webshell", "terminal"},
		Remediation:   "Never expose unauthenticated web terminal emulators to the public internet.",
	},

	// ---------------------------------------------------------
	// 12. EMPLOYEES & OSINT RECON
	// ---------------------------------------------------------
	{
		ID:            "emp-001",
		Title:         "LinkedIn Employee Mapping",
		Description:   "Queries LinkedIn for employees, roles, and profiles associated with the target domain.",
		Category:      models.CategoryEmployeesOSINT,
		Severity:      models.SeverityLow,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:linkedin.com/in/ \"{{TARGET}}\" | \"{{ORG}}\"",
		Tags:          []string{"osint", "linkedin", "social"},
		Remediation:   "Train staff on social engineering awareness and operational security on public profiles.",
	},
	{
		ID:            "emp-002",
		Title:         "Internal Staff Directories and Org Charts",
		Description:   "Discovers public staff directories, phone lists, and organizational hierarchy charts.",
		Category:      models.CategoryEmployeesOSINT,
		Severity:      models.SeverityLow,
		Engine:        models.EngineGoogle,
		QueryTemplate: "site:{{TARGET}} (inurl:directory | inurl:staff | inurl:team | intitle:\"Organization Chart\")",
		Tags:          []string{"directory", "staff"},
		Remediation:   "Restrict internal employee directory access to authenticated internal intranets.",
	},
}
