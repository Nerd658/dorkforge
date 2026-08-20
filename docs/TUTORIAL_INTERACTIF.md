# DorkForge: Advanced Search Dorking, Passive Reconnaissance & Attack Surface Auditing
## Interactive Training Manual & Technical Course

> **Course Level**: Intermediate to Advanced AppSec / Red Team / DevSecOps  
> **Tool**: `dorkforge` (`df`) v1.0.0+  
> **Focus**: Passive OSINT, Search Engine Synthesis, Cloud Footprinting, Token Triage, Subdomain Enumeration, and Enterprise Defensive Hardening.

---

## Course Navigation

- [Module 1: Introduction to Search Dorking & OSINT (Principles, Legality, Scope)](#module-1-introduction-to-search-dorking--osint)
- [Module 2: Understanding Search Operators Across Modern Engines](#module-2-understanding-search-operators-across-modern-engines)
- [Module 3: Hands-on Labs & Scenarios with DorkForge](#module-3-hands-on-labs--scenarios-with-dorkforge)
  - [Lab 1: Cloud & SaaS Footprinting (S3, Firebase, Notion, Drive)](#lab-1-cloud--saas-footprinting)
  - [Lab 2: Leaked Credentials & API Tokens Triage (OpenAI, Stripe, AWS, Slack)](#lab-2-leaked-credentials--api-tokens-triage)
  - [Lab 3: Subdomain Discovery via Negative Operators (`dfg subdomains`)](#lab-3-subdomain-discovery-via-negative-operators)
  - [Lab 4: Mining Historical Web Archives (`dfg fetch`)](#lab-4-mining-historical-web-archives)
  - [Lab 5: Real-time Search Result Scraping (`dfg scan --live`)](#lab-5-real-time-search-result-scraping)
  - [Lab 6: HTTP Status Verification & Non-Intrusive Validation (`dfg probe`)](#lab-6-http-status-verification--non-intrusive-validation)
- [Module 4: Defensive Remediation Playbooks](#module-4-defensive-remediation-playbooks)
- [Module 5: Interactive Cheatsheet and CLI Quick Reference](#module-5-interactive-cheatsheet-and-cli-quick-reference)

---

# Module 1: Introduction to Search Dorking & OSINT

## 1.1 Fundamentals of Search Dorking & Passive Reconnaissance

**Search Engine Dorking** (historically termed *Google Hacking*) is the practice of leveraging advanced search operators to query index caches of search engines for sensitive data, unprotected assets, misconfigured services, and leaked credentials that were inadvertently exposed to internet crawlers.

Reconnaissance in modern offensive and defensive security is divided into two fundamental operational modes:

```
+-------------------------------------------------------------------------------+
|                             RECONNAISSANCE MODES                              |
+------------------------------------+------------------------------------------+
|       PASSIVE RECONNAISSANCE       |           ACTIVE RECONNAISSANCE          |
+------------------------------------+------------------------------------------+
| - Interacts ONLY with third-party  | - Transmits packets directly to target   |
|   caches (Google, GitHub, Shodan). |   infrastructure (Nmap, Burp Suite,     |
| - Target server receives 0 packets |   directory fuzzers like ffuf).          |
|   from the auditor's IP address.   | - Generates firewall, IDS/IPS, WAF, and  |
| - Zero risk of target disruption.  |   application access log events.         |
| - Fully covert; leaves no telemetry| - High risk of alert triggers and IP     |
|   on target network appliances.    |   rate-limiting/blocking.                |
+------------------------------------+------------------------------------------+
```

### The Inadvertent Exposure Pipeline

Search engines continuously traverse the internet through automated web crawlers (e.g., `Googlebot`, `Bingbot`). When an engineering team inadvertently deploys an unindexed file without proper access controls, the following ingestion timeline occurs:

```
[ Developer Mistake ]
  - Leaves .env in /var/www/html
  - Adds staging link to public blog
         |
         v
[ Search Crawler ]
  - Follows link or sitemap
  - Fetches HTTP 200 payload
         |
         v
[ Engine Inverted Index ]
  - Parses tokens, text, & headers
  - Stores cached representation
         |
         v
[ DorkForge Reconnaissance ]
  - Synthesizes targeted boolean dork
  - Extracts asset without contacting target host
```

## 1.2 The History: From Johnny Long's GHDB to Cloud & DevSecOps

In 2002, security researcher **Johnny Long** began cataloging search strings that surfaced vulnerable servers, default configuration screens, and file listings, establishing the **Google Hacking Database (GHDB)** (subsequently maintained by Exploit-DB).

While early dorking focused on LAMP-stack misconfigurations (`intitle:"index of /"`, `filetype:inc intext:mysql_connect`), modern attack surfaces have migrated to distributed architectures:

1. **Cloud & Storage Buckets**: S3, Google Cloud Storage, Azure Blob containers, and Firebase Realtime databases.
2. **DevOps & CI/CD Pipelines**: Exposed `.git` trees, `.env.local` files, ArgoCD portals, Jenkins pipelines, and Terraform state files (`terraform.tfstate`) containing plaintext cloud credentials.
3. **Modern SaaS & Collaboration**: Notion workspaces, Jira dashboards, Airtable shared links, and Google Sheets containing internal customer PII.
4. **Third-Party Code Repositories**: Developer repositories hosting leaked API tokens (`sk-proj-...`, `ghp_...`, `xoxb-...`).

`dorkforge` addresses this evolution by aggregating traditional GHDB intelligence with 70+ modern Cloud, API, and DevSecOps signatures across 12 distinct risk categories.

## 1.3 Legality, Ethics, Scope, and Rules of Engagement (RoE)

Passive reconnaissance occupies a specific position in cybersecurity law. Because you are querying public search engines and third-party data repositories, passive dorking itself does not send hostile packets to the target. However, strict boundaries must be maintained:

### Legal Frameworks Overview

| Jurisdiction | Law / Regulation | Application to Dorking & Passive Recon |
|---|---|---|
| **United States** | **CFAA (18 U.S.C. § 1030)** | Querying search engines is legal. *Accessing* private credentials found via dorking to log into target systems without authorization constitutes "exceeding authorized access" and violates the CFAA. |
| **European Union** | **NIS2 & GDPR (RGPD)** | Processing or exfiltrating personal data (PII) discovered in public spreadsheets/dumps without consent violates GDPR Article 6/9. |
| **France** | **Code Pénal (Art. 323-1 à 323-3-1)** | Fraudulent access or remaining in an automated data processing system (*STAD*) is illegal. Viewing indexed public web pages is permitted; exploiting leaked session cookies or admin tokens is criminalized. |

### Bug Bounty & Rules of Engagement (RoE) Boundaries

When auditing an organization under a Vulnerability Disclosure Program (VDP) or Bug Bounty engagement (HackerOne, Bugcrowd, Intigriti):

> [!IMPORTANT]
> **The Golden Rule of Passive Exposure Triage**:
> If a dork surfaces a live secret (e.g., an AWS access key or database dump):
> 1. **Do not exfiltrate customer data or query private databases.**
> 2. **Document the exact search query and the exposed URL.**
> 3. **Obtain minimal non-destructive proof** (e.g., verifying key identity via `aws sts get-caller-identity` without downloading S3 objects).
> 4. **Report immediately through official triage channels.**

---

# Module 2: Understanding Search Operators Across Modern Engines

Search engines process queries using specialized syntax operators. To build effective dork strings, security practitioners must understand engine-specific tokenization, boolean evaluation rules, and indexing boundaries.

```
                           +------------------------+
                           | DORKFORGE QUERY ENGINE |
                           +-----------+------------+
                                       |
       +-------------------------------+-------------------------------+
       |               |               |               |               |
       v               v               v               v               v
  +----------+   +----------+   +----------+   +----------+   +----------+
  |  Google  |   |  GitHub  |   |  Shodan  |   | DuckDuck |   |   Bing   |
  | GHDB/Web |   | Code/API |   | Banners  |   | Privacy  |   | Subdoms  |
  +----------+   +----------+   +----------+   +----------+   +----------+
```

## 2.1 Google Search Engine Directives

Google's inverted index allows surgical extraction based on URL paths, page titles, body text, and file extensions:

| Operator | Syntax Example | Behavioral Mechanism |
|---|---|---|
| `site:` | `site:example.com` | Restricts results strictly to the given domain or host prefix. |
| `inurl:` | `inurl:admin.php` | Matches tokens appearing anywhere within the URL path or query string. |
| `intitle:` | `intitle:"phpinfo()"` | Matches tokens appearing within the HTML `<title>` tag. |
| `allintitle:`| `allintitle: index of backup` | Requires all following terms to appear inside the `<title>` tag. |
| `intext:` | `intext:"DB_PASSWORD"` | Matches terms located strictly in the page body text. |
| `filetype:` / `ext:` | `ext:env` or `filetype:sql` | Filters by indexed document file extension. |
| `-` (Negation) | `-site:www.example.com` | Excludes results matching the negated expression. |
| `\|` or `OR` | `"secret" \| "password"` | Logical OR evaluation between clauses. |
| `()` (Grouping)| `(ext:sql \| ext:bak)` | Enforces evaluation precedence across boolean operators. |
| `""` (Literal) | `"BEGIN RSA PRIVATE KEY"`| Enforces exact phrase matching without stemming. |
| `AROUND(n)` | `"AWS" AROUND(3) "AKIA"` | Finds terms occurring within `n` words of each other. |

## 2.2 GitHub Code Search Directives

GitHub Code Search indexes billions of lines of code across public repositories. It is the premier engine for token and credential auditing:

| Operator | Syntax Example | Behavioral Mechanism |
|---|---|---|
| `path:` | `path:.env` or `path:.github/workflows` | Matches repository file system paths. |
| `filename:` | `filename:wp-config.php` | Matches exact base file names. |
| `extension:`| `extension:tfstate` | Matches source file extensions. |
| `language:` | `language:yaml` | Filters by GitHub Linguist detected languages. |
| `org:` / `user:` | `org:target-organization` | Limits code search to public repos of an organization. |
| `NOT` / `AND` / `OR` | `"target.com" AND "sk_live_"` | Case-sensitive boolean operators in GitHub search syntax. |

## 2.3 Shodan Infrastructure Directives

Shodan indexes device banners, TLS certificates, and open ports rather than web page contents:

| Filter | Syntax Example | Behavioral Mechanism |
|---|---|---|
| `ssl.cert.subject.CN:` | `ssl.cert.subject.CN:"example.com"` | Matches Common Name in TLS certificate subject lines. |
| `hostname:` | `hostname:"*.example.com"` | Finds IPs with DNS PTR records matching the pattern. |
| `http.title:` | `http.title:"Dashboard [Jenkins]"` | Matches the HTTP response title in web banner grabs. |
| `http.component:` | `http.component:"Swagger"` | Matches detected web technology frameworks. |
| `port:` | `port:8080` or `port:9200` | Filters hosts by listening TCP/UDP port. |
| `asn:` | `asn:AS15169` | Restricts queries to an Autonomous System Number. |

## 2.4 Microsoft Bing & DuckDuckGo Directives

- **Bing**: Uses `site:`, `ip:`, `contains:`, and `filetype:`. Bing's crawler crawls unlinked subdomains and documents differently than Google, making it vital for secondary asset verification.
- **DuckDuckGo**: Relies on independent crawlers and partner indexes. It does not personalize search results, eliminating algorithmic bubble distortion during reconnaissance.

## 2.5 Multi-Engine Comparative Matrix

| Target Asset | Google Dork Syntax | GitHub Code Syntax | Shodan Query Syntax |
|---|---|---|---|
| **Environment Secrets** | `site:target.com (ext:env \| ext:ini) "DB_PASSWORD"` | `"target.com" filename:.env "SECRET_KEY"` | `http.html:"DB_PASSWORD" hostname:"target.com"` |
| **Admin Dashboards** | `site:target.com (intitle:"Grafana" \| inurl:admin)` | `"target.com" filename:docker-compose.yml "grafana"` | `http.title:"Grafana" hostname:"target.com"` |
| **AWS S3 Buckets** | `site:s3.amazonaws.com intext:"target"` | `"s3.amazonaws.com/target"` | `http.title:"Index of" "s3.amazonaws.com"` |
| **Subdomain Recon** | `site:*.target.com -site:www.target.com` | N/A | `ssl.cert.subject.CN:"target.com"` |
| **OpenAPI / Swagger**| `site:target.com (inurl:swagger.json \| inurl:api-docs)` | `"target.com" filename:swagger.json` | `http.component:"Swagger" hostname:"target.com"` |

---

# Module 3: Hands-on Labs & Scenarios with DorkForge

In this module, you will work through 6 realistic security auditing labs using `dorkforge` (`df`). 

```
                               DORKFORGE LAB MATRIX
  +-------------------------------------------------------------------------+
  | Lab 1: Cloud & SaaS Footprinting (S3, Firebase, Notion, Drive)          |
  | Lab 2: Leaked Credentials & API Tokens Triage (OpenAI, Stripe, AWS)     |
  | Lab 3: Subdomain Discovery via Negative Operators (dfg subdomains)      |
  | Lab 4: Mining Historical Web Archives (dfg fetch / Wayback)             |
  | Lab 5: Real-time Search Result Scraping (dfg scan --live)               |
  | Lab 6: HTTP Status Verification & Non-Intrusive Validation (dfg probe)  |
  | Lab 7: Full Automated Recon Pipeline (dfg recon - scan+fetch+probe)     |
  +-------------------------------------------------------------------------+
```

---

## Lab 1: Cloud & SaaS Footprinting

### Context & Threat Scenario
Organizations frequently share assets across decentralized cloud storage and SaaS platforms. Development teams create public Amazon S3 buckets, Firebase Realtime databases without security rules, open Notion SOP pages, and unprotected Google Drive folders containing internal client data.

### Objective
Execute a multi-engine cloud reconnaissance scan against `megacorp-logistics.com` to isolate leaked cloud storage buckets and SaaS workspaces.

### Terminal Execution
Run the following command to filter specifically for the `cloud` category:

```bash
# Run cloud reconnaissance audit and output to Markdown
./bin/dorkforge scan -d megacorp-logistics.com -c cloud -f markdown -o lab1-cloud-report.md --no-color
```

### Expected Output
```text
================================================================================
 DORKFORGE RECONNAISSANCE AUDIT
 Target       : megacorp-logistics.com
 Generated At : 2026-08-19T18:46:00Z
 Total Dorks  : 10
 Severity     : [CRIT: 0] [HIGH: 4] [MED: 6] [LOW: 0]
================================================================================

01. [HIGH]     Public Amazon S3 Buckets (cloud / google)
    Description : Queries Amazon S3 domains for bucket names referencing the target organization.
    Query       : site:s3.amazonaws.com "megacorp-logistics.com" | "megacorp-logistics"
    Search URL  : https://www.google.com/search?q=site%3As3.amazonaws.com+%22megacorp-logistics.com%22+%7C+%22megacorp-logistics%22
    Remediation : Enable S3 Block Public Access at the account level and review bucket ACLs.

02. [HIGH]     Exposed AWS S3 Bucket XML Directory Listings (cloud / google)
    Description : Detects open S3 buckets returning public ListBucketResult XML directories exposing file paths.
    Query       : site:s3.amazonaws.com intext:"ListBucketResult" "megacorp-logistics.com" | "megacorp-logistics"
    Search URL  : https://www.google.com/search?q=site%3As3.amazonaws.com+intext%3A%22ListBucketResult%22+%22megacorp-logistics.com%22+%7C+%22megacorp-logistics%22
    Remediation : Enable 'Block public access' and remove s3:ListBucket permissions for anonymous users.

03. [HIGH]     Exposed Firebase Realtime Databases (cloud / google)
    Description : Discovers public Firebase Realtime Database instances with insecure read/write permissions.
    Query       : site:firebaseio.com "megacorp-logistics.com" | "megacorp-logistics"
    Search URL  : https://www.google.com/search?q=site%3Afirebaseio.com+%22megacorp-logistics.com%22+%7C+%22megacorp-logistics%22
    Remediation : Enforce strict Firebase Security Rules (.read != true) and restrict access using Firebase Authentication.

04. [HIGH]     Public Google Sheets and Drive Documents (cloud / google)
    Description : Searches for public Google Spreadsheets and Drive documents referencing the target organization.
    Query       : site:docs.google.com/spreadsheets/d/ "megacorp-logistics.com" | "megacorp-logistics"
    Search URL  : https://www.google.com/search?q=site%3Adocs.google.com%2Fspreadsheets%2Fd%2F+%22megacorp-logistics.com%22+%7C+%22megacorp-logistics%22
    Remediation : Audit Google Workspace sharing permissions and enforce domain-only sharing for sensitive sheets.

05. [MEDIUM]   Public Notion Workspaces and Knowledge Bases (cloud / google)
    Description : Locates publicly shared Notion workspace pages containing internal standard operating procedures.
    Query       : site:notion.site "megacorp-logistics.com" | site:notion.so "megacorp-logistics.com"
    Search URL  : https://www.google.com/search?q=site%3Anotion.site+%22megacorp-logistics.com%22+%7C+site%3Anotion.so+%22megacorp-logistics.com%22
    Remediation : Review public share settings on Notion team workspaces and disable 'Share to Web' on internal pages.

Report successfully exported to lab1-cloud-report.md (format: markdown)
```

### Analysis & Technical Validation
1. **S3 ListBucketResult**: An S3 bucket returning `<ListBucketResult>` allows an unauthenticated visitor to traverse the entire folder structure and file names without knowing them in advance.
2. **Firebase Database Insecurity**: If a discovered database endpoint `https://megacorp-db.firebaseio.com/.json` returns JSON without an authentication error, the `.read` rule is set to `true`.

---

## Lab 2: Leaked Credentials & API Tokens Triage

### Context & Threat Scenario
Engineers frequently commit production keys to public GitHub repositories or leave `.env` files exposed on test web servers. Finding an exposed token requires swift, non-destructive triage to assess blast radius.

### Objective
Audit `fintech-payments.io` for high-severity credential leaks (AWS IAM keys, Stripe secret keys, OpenAI API tokens, Slack webhooks) across Google and GitHub Code Search.

### Terminal Execution
```bash
# Filter for configs and secrets with minimum severity 'high'
./bin/dorkforge scan -d fintech-payments.io -c configs,secrets -s high --no-color
```

### Expected Output
```text
================================================================================
 DORKFORGE RECONNAISSANCE AUDIT
 Target       : fintech-payments.io
 Generated At : 2026-08-19T18:46:00Z
 Total Dorks  : 16
 Severity     : [CRIT: 14] [HIGH: 2] [MED: 0] [LOW: 0]
================================================================================

01. [CRITICAL] Exposed .env and Environment Files (configs / google)
    Description : Identifies public .env files potentially exposing secrets, database credentials, and API keys.
    Query       : site:fintech-payments.io (ext:env | ext:yml | ext:ini) ("DB_PASSWORD" | "SECRET_KEY" | "JWT_SECRET")
    Search URL  : https://www.google.com/search?q=site%3Afintech-payments.io+%28ext%3Aenv+%7C+ext%3Ayml+%7C+ext%3Aini%29+%28%22DB_PASSWORD%22+%7C+%22SECRET_KEY%22+%7C+%22JWT_SECRET%22%29
    Remediation : Restrict web server access to dotfiles and configuration directories in Nginx/Apache.

02. [CRITICAL] Exposed AWS Access Keys (secrets / google)
    Description : Identifies pages or text files containing Amazon Web Services access keys.
    Query       : site:fintech-payments.io "AKIA" ("aws_secret_access_key" | "aws_access_key_id")
    Search URL  : https://www.google.com/search?q=site%3Afintech-payments.io+%22AKIA%22+%28%22aws_secret_access_key%22+%7C+%22aws_access_key_id%22%29
    Remediation : Immediately rotate compromised AWS IAM access keys and enable AWS Secrets Manager.

03. [CRITICAL] GitHub Repository Secret Leakage (secrets / github)
    Description : Searches GitHub code search for target domain references alongside common token prefixes.
    Query       : "fintech-payments.io" AND ("ghp_" OR "github_pat_" OR "glpat-" OR "xoxb-")
    Search URL  : https://github.com/search?q=%22fintech-payments.io%22+AND+%28%22ghp_%22+OR+%22github_pat_%22+OR+%22glpat-%22+OR+%22xoxb-%22%29&type=code
    Remediation : Implement pre-commit secret scanning (git-secrets, trufflehog) in developer workflows.

04. [CRITICAL] OpenAI and LLM API Key Leaks (secrets / github)
    Description : Searches GitHub code search for exposed OpenAI API keys associated with the target domain.
    Query       : "fintech-payments.io" AND ("sk-proj-" OR "sk-live-" OR "OPENAI_API_KEY")
    Search URL  : https://github.com/search?q=%22fintech-payments.io%22+AND+%28%22sk-proj-%22+OR+%22sk-live-%22+OR+%22OPENAI_API_KEY%22%29&type=code
    Remediation : Revoke exposed OpenAI API keys immediately in the OpenAI platform dashboard.

05. [CRITICAL] Stripe Live Secret and Restricted API Keys (secrets / github)
    Description : Searches GitHub for live production Stripe secret keys and webhook signing secrets.
    Query       : "fintech-payments.io" AND ("sk_live_" OR "rk_live_" OR "whsec_")
    Search URL  : https://github.com/search?q=%22fintech-payments.io%22+AND+%28%22sk_live_%22+OR+%22rk_live_%22+OR+%22whsec_%22%29&type=code
    Remediation : Roll the compromised Stripe secret keys in the Stripe Developer Dashboard.
```

### Safe Triage Matrix
When a live token is identified, triage safely using vendor-provided zero-privilege validation APIs:

```bash
# 1. AWS IAM Access Key (Check identity without data access)
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...

# 2. GitHub Personal Access Token (Check rate limit & associated scopes)
curl -H "Authorization: token ghp_..." https://api.github.com/rate_limit

# 3. Slack Webhook (NEVER send test spam to general channels; verify format only)
# Format: https://hooks.slack.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}
```

---

## Lab 3: Subdomain Discovery via Negative Operators

### Context & Threat Scenario
Standard subdomain enumeration relies on active DNS brute-forcing. However, active brute-forcing triggers SIEM alerts. Search engine exclusion dorking allows auditors to peel back known layers of an organization's domain hierarchy purely through search index negations.

### Mathematical Principle of Exclusion Chains

```
Let S = All indexed hosts under *.target.com
Let K = {www, mail, blog} (Known hosts)
Exclusion Query: S \ K => "site:*.target.com -site:www.target.com -site:mail.target.com -site:blog.target.com"
```

### Terminal Execution
Run the dedicated `subdomains` command with known subdomains excluded:

```bash
./bin/dorkforge subdomains -d healthcare-corp.org --exclude www,mail,blog,portal,app --no-color
```

### Expected Output
```text
================================================================================
 DORKFORGE RECONNAISSANCE AUDIT
 Target       : healthcare-corp.org
 Generated At : 2026-08-19T18:46:00Z
 Total Dorks  : 4
 Severity     : [CRIT: 0] [HIGH: 0] [MED: 0] [LOW: 4]
================================================================================

01. [LOW]      Google Subdomain Exclusion Query (subdomains / google)
    Description : Enumerates unmapped subdomains by excluding known domains.
    Query       : site:*.healthcare-corp.org -site:www.healthcare-corp.org -site:healthcare-corp.org -site:mail.healthcare-corp.org -site:blog.healthcare-corp.org -site:portal.healthcare-corp.org -site:app.healthcare-corp.org
    Search URL  : https://www.google.com/search?q=site%3A%2A.healthcare-corp.org+-site%3Awww.healthcare-corp.org+-site%3Ahealthcare-corp.org+-site%3Amail.healthcare-corp.org+-site%3Ablog.healthcare-corp.org+-site%3Aportal.healthcare-corp.org+-site%3Aapp.healthcare-corp.org

02. [LOW]      Bing Subdomain Reconnaissance (subdomains / bing)
    Description : Discovers indexed subdomains across Microsoft Bing engine.
    Query       : site:*.healthcare-corp.org -site:www.healthcare-corp.org -site:healthcare-corp.org
    Search URL  : https://www.bing.com/search?q=site%3A%2A.healthcare-corp.org+-site%3Awww.healthcare-corp.org+-site%3Ahealthcare-corp.org

03. [LOW]      Shodan SSL Subject CN Search (subdomains / shodan)
    Description : Searches Shodan database for hosts presenting matching TLS certificates.
    Query       : ssl.cert.subject.CN:"healthcare-corp.org"
    Search URL  : https://www.shodan.io/search?query=ssl.cert.subject.CN%3A%22healthcare-corp.org%22

04. [LOW]      Shodan Hostname Wildcard (subdomains / shodan)
    Description : Discovers internet-facing servers resolving to target hostnames.
    Query       : hostname:"healthcare-corp.org"
    Search URL  : https://www.shodan.io/search?query=hostname%3A%22healthcare-corp.org%22
```

### Iterative Discovery Loop
1. Launch Query 01 in the browser.
2. Suppose Google returns `staging-api.healthcare-corp.org` and `vpn-gw.healthcare-corp.org`.
3. Add these new subdomains to `--exclude`:
   ```bash
   ./bin/dorkforge subdomains -d healthcare-corp.org --exclude www,mail,blog,portal,app,staging-api,vpn-gw
   ```
4. Repeat until Google reports **"Your search did not match any documents"**. The passive subdomain perimeter is now completely mapped!

---

## Lab 4: Mining Historical Web Archives

### Context & Threat Scenario
Organizations frequently delete vulnerable scripts or sensitive files from production, but web archive repositories (Internet Archive Wayback Machine, Common Crawl) maintain immutable historical snapshots. Attackers mine these archives to uncover decommissioned API endpoints, old credentials, and forgotten documentation.

### Pipeline Architecture

```
[ Target Domain ]
        |
        v
[ Wayback CDX API / Common Crawl ]
        |
        v
[ JSON/URL Stream Parsing ] (Filter extensions: .env, .sql, .bak, .json)
        |
        v
[ DorkForge Historical Triage ]
```

### Terminal Commands & Workflow

Query the Wayback Machine CDX API to fetch indexed files with sensitive extensions without sending a single request to the target:

```bash
# Fetch all indexed .env, .sql, .json, and .bak endpoints for the target domain
curl -s "http://web.archive.org/cdx/search/cdx?url=*.fintech-payments.io/*&output=json&collapse=urlkey&fl=original,timestamp,statuscode" \
  | jq -r '.[] | select(.[0] | test("\\.(env|sql|bak|json|config|yml)$")) | "[\(.[1])] (HTTP \(.[2])) \(.[0])"'
```

### Expected Output
```text
[20230412142011] (HTTP 200) https://fintech-payments.io/api/v1/swagger.json
[20220915100344] (HTTP 200) https://dev.fintech-payments.io/dump-2022.sql
[20240108182210] (HTTP 200) https://staging.fintech-payments.io/.env.local
```

### Historical Retrieval
Using the timestamp, retrieve the exact snapshot from the archive:
```bash
curl -s "https://web.archive.org/web/20240108182210if_/https://staging.fintech-payments.io/.env.local"
```

---

## Lab 5: Real-time Search Result Scraping

### Context & Threat Scenario
Manual dork verification via a web browser can be slow when managing hundreds of scope targets. However, high-velocity automated scraping triggers Google and Bing anti-bot systems (HTTP 429 Too Many Requests / reCAPTCHA challenges).

### Rate-Limiting & Jitter Architecture

To ensure stealth and avoid bot detection:
1. **Batching**: Group search queries into small batches (e.g., 3–5 tabs/requests).
2. **Jitter Delay**: Enforce non-deterministic delays between requests (e.g., 2000ms–4500ms).
3. **Controlled Browser Spawning**: Leverage `dorkforge --open` mode.

```
[ DorkForge Engine ]
        |
        v
  +-----------+  Batch 1 (3 Queries)   +-----------------+
  | Rate      | ---------------------> | Browser / SERP  |
  | Limiter   | <--------------------- | Success (200 OK)|
  | & Jitter  |      Delay 2500ms      +-----------------+
  | Scheduler |  Batch 2 (3 Queries)   +-----------------+
  |           | ---------------------> | Browser / SERP  |
  +-----------+                        +-----------------+
```

### Terminal Execution
Run `dorkforge` in safe batched browser launch mode:

```bash
# Open admin and api-endpoints queries in batches of 3 with a 2500ms delay
./bin/dorkforge scan -d mytarget.com -c admin,api-endpoints --open --batch-size 3 --delay 2500
```

### Headless CLI Export Workflow
For CI/CD and scripted environments, export results directly to structured JSON or URL lists for downstream processing:

```bash
# Export direct search URLs for custom automation
./bin/dorkforge scan -d mytarget.com -c secrets,configs -f urls -o search-urls.txt

# Export complete scan metadata for automated triage
./bin/dorkforge scan -d mytarget.com -s high -f json -o scan-results.json
```

---

## Lab 6: HTTP Status Verification & Non-Intrusive Validation

### Context & Threat Scenario
Search engine dorks identify *potential* exposures based on index history. An auditor needs to confirm if an indexed asset is currently live, returns a `403 Forbidden` (mitigated), or returns a `404 Not Found` (purged), without performing invasive exploitation.

`dorkforge` includes an HTTP prober engine (`internal/prober`) designed for lightweight, concurrent verification.

### Probing Engine Architecture

```
[ Target Domain ]
        |
        v
[ Derive High-Value Paths ] (/.env, /.git/HEAD, /actuator/env, /swagger.json, etc.)
        |
        v
[ Worker Pool (Concurrency: 15) ]
  ├── Worker 1: GET https://target/.env      --> [200 OK] (Exposed!)
  ├── Worker 2: GET https://target/admin     --> [403 Forbidden] (Protected)
  ├── Worker 3: GET https://target/backup.sql--> [404 Not Found] (Clean)
        |
        v
[ Heuristic Classifier ] (Filters fake 200s, checks body signatures)
        |
        v
[ Final Exposure Report ]
```

### Automated Probe Execution
The prober evaluates key status attributes:

```bash
# Example Go invocation of DorkForge Prober test suite
go test -v ./internal/prober/ -run TestProbeSingle
```

### Expected Output
```text
=== RUN   TestProbeSingle
--- PASS: TestProbeSingle (0.00s)
=== RUN   TestProbeBatch
--- PASS: TestProbeBatch (0.00s)
=== RUN   TestDeriveProbeURLs
--- PASS: TestDeriveProbeURLs (0.00s)
PASS
ok      github.com/Nerd658/dorkforge/internal/prober    0.004s
```

### Prober Response Classification Matrix

| Status Code | Content-Type / Heuristics | Classification | Severity Action |
|---|---|---|---|
| `200 OK` | `text/plain` containing `DB_PASSWORD` or `=` | **CRITICAL EXPOSURE** | Immediate P1 incident alert & token rotation. |
| `200 OK` | `application/json` containing `paths:` | **HIGH (API Disclosed)** | Restrict OpenAPI endpoint to internal VPN. |
| `200 OK` | `text/html` with `<title>Page Not Found</title>` | **FALSE POSITIVE** | SPA Soft-404; mark as non-exploitable. |
| `401 / 403`| `text/html` with standard auth challenge | **SECURED (Mitigated)** | Asset is protected by access control. |
| `404` | Standard error page | **CLEAN** | Asset does not exist. |

---

## Lab 7: Full Automated Reconnaissance Pipeline (`dfg recon`)

### Context & Threat Scenario
During a red team engagement or comprehensive AppSec audit, running individual subcommands sequentially (`scan`, `fetch`, `probe`) requires manual effort. The `dfg recon` command automates all 4 phases sequentially and generates a consolidated risk score alongside an interactive multi-tab HTML report.

### Pipeline Execution Architecture

```
                       dfg recon -d example.com
                                  │
  ┌───────────────────────────────┼───────────────────────────────┐
  ▼                               ▼                               ▼
[PHASE 1: SCAN DORKS]     [PHASE 2: ARCHIVES]         [PHASE 3: LIVE SCRAPING]
Synthesizes 70+ dorks     Wayback + AlienVault        Scrapes DuckDuckGo for
across 12 categories      Extracts sensitive URLs     live indexed targets
  │                               │                               │
  └───────────────────────────────┼───────────────────────────────┘
                                  ▼
                     [PHASE 4: HTTP PROBING]
                     Worker pool checks 200/403/401
                     Status codes on sensitive paths
                                  │
                                  ▼
                 [MULTI-TAB HTML AUDIT DASHBOARD]
                 - Overview & Circular Risk Score Gauge
                 - Dork Signatures & "Launch All" Button
                 - Live SERP Findings & Snippets
                 - Confirmed Active Exposed Endpoints
```

### Terminal Commands & Workflow

Run the complete all-in-one pipeline and export an interactive dashboard:

```bash
# 1. Full automated audit with multi-tab HTML dashboard
./bin/dorkforge recon -d target-app.net -o /tmp/recon-report.html -f html

# 2. Open queries directly in browser tabs from terminal
./bin/dorkforge recon -d target-app.net -c configs,secrets --open --batch-size 5

# 3. Fast passive-only audit (skip live scraping and active probing)
./bin/dorkforge recon -d target-app.net --no-live --no-probe -o /tmp/passive-recon.html
```

---

## Lab 8: False-Positive Noise Reduction (`.dfgignore`)

### Context & Threat Scenario
Security audits against large enterprises frequently uncover known, authorized public resources (e.g. intentional public sitemaps, developer documentation). Without exclusion rules, these known items appear in every audit report, wasting analyst triage time.

### Rules Engine Syntax
Create a `.dfgignore` file in your workspace:

```text
# Ignore a specific dork signature by ID
dork_id: google-s3-public-bucket

# Ignore an entire category
category: employees-osint

# Ignore URL patterns matching sitemaps or documentation
url: *known-sitemap.xml*
url: *public-apidocs*
```

### Terminal Commands
```bash
# Execute scan applying exclusion rules
./bin/dorkforge scan -d example.com --ignore .dfgignore -o clean-audit.html -f html
```

---

## Lab 9: Continuous Audit Delta Comparison (`--diff`)

### Context & Threat Scenario
In a DevSecOps environment, running weekly dorking audits generates hundreds of data points. Security engineers require a delta view showing only newly introduced exposures since the last audit baseline.

### Workflow Execution
```bash
# Step 1: Export baseline audit JSON
./bin/dorkforge scan -d example.com -o baseline.json -f json

# Step 2: One week later, run scan with --diff against baseline
./bin/dorkforge scan -d example.com --diff baseline.json -o weekly-delta.html -f html
```

### Terminal Delta Output
```text
[DIFF REPORT] New Signatures Matched: 2 | Resolved Signatures: 1
```

---

## Lab 10: CIDR Subnet & ASN Infrastructure Dorking

### Context & Threat Scenario
Red teams and auditors frequently target entire IP ranges (CIDR blocks) or Autonomous System Numbers (ASNs) rather than single domain names.

### Terminal Commands
```bash
# Audit an IPv4 CIDR range on Shodan (converts target to net:"198.51.100.0/24")
./bin/dorkforge scan -d 198.51.100.0/24 -e shodan

# Audit an ASN on Shodan (converts target to asn:"AS15169")
./bin/dorkforge scan -d AS15169 -e shodan
```

---

## Lab 11: WAF Origin Server Discovery via Certificate Intelligence (`dfg origin`)

### Context & Threat Scenario
Modern web applications sit behind Reverse Proxies & WAFs (such as Cloudflare, Fastly, Akamai) that mask the backend Origin Server IP address. However, historical DNS records and Certificate Transparency (CT) logs frequently expose the real Origin Server IP where TLS handshakes present matching Subject Common Names (CN).

### Multi-Stage Correlation Chain
```text
Domain -> Passive CT Logs (crt.sh) -> Historical DNS IPs -> Direct TLS Handshake -> HTTP Host Verification -> Confidence Rating
```

### Terminal Commands
```bash
# Execute WAF Origin Server discovery
./bin/dorkforge origin -d example.com -o origin_report.html

# Include Origin Bypass discovery in full automated reconnaissance pipeline
./bin/dorkforge recon -d example.com -o full_audit.html
```

---

# Module 4: Defensive Remediation Playbooks

Identifying exposures is only half the battle. A security engineer must provide clear, actionable configuration fixes.

```
                         DEFENSE-IN-DEPTH REMEDIATION
  +-------------------------------------------------------------------------+
  | 1. Web Server Layer : Deny dotfiles, .git, backups in Nginx/Apache     |
  | 2. Search Index Layer: X-Robots-Tag: noindex (Avoid robots.txt traps!)  |
  | 3. Cloud Storage    : S3 Block Public Access & IAM Policies             |
  | 4. WAF & Edge CDN   : Cloudflare / AWS WAF custom rule blocks           |
  | 5. DevSecOps Layer  : Pre-commit git hooks & automated secret rotation  |
  +-------------------------------------------------------------------------+
```

## 4.1 Web Server Hardening

### Nginx (`nginx.conf`)
Place these directives inside the primary `server` block to block dotfiles, version control directories, and backup archives:

```nginx
# 1. Block all hidden dotfiles (.env, .git, .htaccess, .DS_Store)
location ~ /\.(?!well-known) {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}

# 2. Block sensitive backup and database file extensions
location ~* \.(sql|bak|dump|old|temp|tmp|save|swp|sqlite|sqlite3|tfstate|tfvars)$ {
    deny all;
    return 404;
}

# 3. Restrict Spring Boot Actuator and Prometheus metrics to internal IPs
location /actuator/ {
    allow 10.0.0.0/8;
    allow 127.0.0.1;
    deny all;
}

# 4. Disable directory listings
autoindex off;
```

### Apache (`.htaccess` / `httpd.conf`)

```apache
# Disable directory indexing
Options -Indexes

# Deny access to dotfiles (.env, .git, etc.)
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# Block configuration, backup, and state files
<FilesMatch "\.(env|sql|bak|dump|tfstate|tfvars|config|ini|log)$">
    Require all denied
</FilesMatch>
```

## 4.2 The `robots.txt` Fallacy vs `X-Robots-Tag`

> [!WARNING]
> **The `robots.txt` Disallow Trap**:
> Placing sensitive endpoints in `robots.txt` under `Disallow:` (e.g., `Disallow: /super-secret-admin-portal/`) **does not hide them**. Search engines will not crawl the contents, but `robots.txt` itself is public, and engines will still index the URL if linked externally!

### Correct Solution: `X-Robots-Tag` HTTP Header
Instruct search engines not to index pages by returning the `X-Robots-Tag` HTTP response header:

```nginx
# Nginx directive for internal administration and staging routes
location /internal-admin/ {
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet" always;
}
```

## 4.3 Cloud Storage & SaaS Bucket Policies

### Amazon Web Services (AWS S3)
Enforce **S3 Block Public Access** across the entire AWS account via AWS CLI:

```bash
# Enable Account-Level Block Public Access
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### Google Cloud Storage (GCS)
Enable **Uniform Bucket-Level Access** to prevent object-level ACL leaks:

```bash
gcloud storage buckets update gs://my-company-bucket --uniform-bucket-level-access
```

### Firebase Realtime Database
Update `database.rules.json` to require authentication:

```json
{
  "rules": {
    ".read": "auth != null",
    ".write": "auth != null"
  }
}
```

## 4.4 WAF & Edge CDN Rules (Cloudflare & AWS WAF)

### Cloudflare Custom WAF Rule (Expression Language)
Create a firewall rule to block common dork targets at the edge:

```text
(http.request.uri.path contains "/.env" or
 http.request.uri.path contains "/.git" or
 http.request.uri.path contains "/actuator" or
 http.request.uri.path contains "/wp-config" or
 http.request.uri.path contains "/terraform.tfstate" or
 http.request.uri.path ends_with ".sql" or
 http.request.uri.path ends_with ".bak")
=> Action: Block (403 Forbidden)
```

## 4.5 Secrets Management & Pre-Commit Git Protection

Install **Gitleaks** or **TruffleHog** as a pre-commit hook to prevent developers from committing credentials:

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.2
    hooks:
      - id: gitleaks
```

---

# Module 5: Interactive Cheatsheet and CLI Quick Reference

## 5.1 DorkForge CLI Command Reference

| Subcommand | Key Flags | Description |
|---|---|---|
| `dfg scan -d <domain>` | `-c <cats>`, `-s <sev>`, `-e <engine>`, `-o <file>`, `-f <fmt>`, `--open` | Primary passive dorking reconnaissance engine. |
| `dfg subdomains -d <domain>` | `--exclude <list>`, `-o <file>`, `-f <fmt>`, `--open` | Synthesizes negative search exclusion chains for subdomain discovery. |
| `dfg list` | `-c <cat>`, `--custom <file.json>` | Lists all 70+ built-in and custom dork signatures. |
| `dfg categories` | None | Displays descriptions and severities for all 12 categories. |
| `dfg completion <shell>` | `bash`, `zsh`, `fish` | Generates fast shell autocompletion scripts. |
| `dfg version` | None | Displays version, Go build toolchain, and architecture. |

## 5.2 Category Reference Matrix

```text
+-------------------+----------+-----------------------------------------------------------+
| Category Name     | Severity | Representative Assets                                    |
+-------------------+----------+-----------------------------------------------------------+
| configs           | CRITICAL | .env, wp-config.php, nginx.conf, terraform.tfstate       |
| secrets           | CRITICAL | AWS keys (AKIA), RSA private keys, Stripe, OpenAI tokens  |
| admin             | HIGH     | phpMyAdmin, Jenkins CI, Grafana, ArgoCD, Kubernetes Dash  |
| backups           | HIGH     | Database dumps (.sql), archive (.tar.gz), Spring heapdump |
| cloud             | HIGH/MED | AWS S3 ListBucketResult, Firebase, Notion, Google Drive   |
| source-code       | HIGH     | Exposed /.git, /.svn, source maps (.js.map), .npmrc       |
| errors            | MEDIUM   | phpinfo(), Django debug stack traces, /server-status      |
| docs              | MED/LOW  | Confidential PDFs, HR payroll spreadsheets, invoices      |
| api-endpoints     | HIGH     | Swagger / OpenAPI UI, GraphQL Playgrounds, WSDL           |
| subdomains        | LOW      | Google negative exclusion, Bing recon, Shodan SSL certs   |
| network-iot       | HIGH     | pfSense, FortiGate, Cisco ASDM, Web Shells, IP cameras    |
| employees-osint   | LOW      | LinkedIn employee mapping, internal staff directories     |
+-------------------+----------+-----------------------------------------------------------+
```

## 5.3 Shell Completion Setup

```bash
# Bash (Persistent)
dorkforge completion bash > ~/.local/share/bash-completion/completions/dorkforge

# Zsh (Persistent)
dorkforge completion zsh > "${fpath[1]}/_dorkforge"

# Fish (Persistent)
dorkforge completion fish > ~/.config/fish/completions/dorkforge.fish
```

## 5.4 Automated CI/CD Attack Surface Audit Workflow

Integrate `dorkforge` into GitHub Actions for weekly automated exposure assessments:

```yaml
name: Weekly Attack Surface Audit

on:
  schedule:
    - cron: '0 4 * * 1' # Every Monday at 04:00 UTC
  workflow_dispatch:

jobs:
  dork-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build DorkForge
        run: make build

      - name: Execute Security Reconnaissance
        run: |
          ./bin/dorkforge scan -d mycompany.com -s high -f markdown -o audit-report.md --no-color

      - name: Upload Audit Deliverable
        uses: actions/upload-artifact@v4
        with:
          name: attack-surface-report
          path: audit-report.md
```

---

## Conclusion & Next Steps

Search Dorking remains one of the most effective, non-intrusive methodologies in an AppSec engineer's toolkit. By incorporating `dorkforge` into your continuous reconnaissance and DevSecOps pipelines, you ensure that unintended exposures are identified and mitigated before malicious actors can exploit them.

For the interactive web edition of this tutorial featuring a live query simulator, visual cheatsheets, and interactive scenario quizzes, open [tutorial.html](file:///home/bikienga/dorkforge/docs/tutorial.html) in any web browser.
