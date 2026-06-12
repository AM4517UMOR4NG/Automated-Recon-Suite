# Automated Recon Suite

> **A high-performance, asynchronous security auditing and defensive engineering suite built entirely in pure Node.js with zero external dependencies.**

---

## 📂 Repository Structure

```
Automated-Recon-Suite/
│
├── README.md
│
├── scanners/                          # All offensive scanning tools
│   ├── crt-harvester.js               # CT log subdomain enumerator (passive recon)
│   ├── ghost-engine.js                # Directory & config leak scanner
│   ├── specter-cors.js                # Multi-vector CORS misconfiguration detector
│   ├── echo-takeover.js               # Subdomain takeover analyzer (DNS-first)
│   └── vanguard-dns.js                # DNS brute-forcing & wildcard filter engine
│
├── wordlists/                         # Input data files for scanners
│   ├── paths.txt                      # 200+ sensitive file/directory paths
│   ├── domains.txt                    # 500 sample target domains
│   └── subdomains.txt                 # 500+ common subdomain prefixes
│
└── detection/                         # Defensive configs & middleware
    ├── fail2ban_scanner_protection.conf
    ├── modsecurity_waf_rules.conf
    └── rate_limiter.js
```

---

## ⚔️ Offensive Scanners

All scanners share the same architectural foundation:
- **Zero external dependencies** — only Node.js built-in modules
- **TCP connection pooling** via `Keep-Alive` agents
- **Controlled concurrency** — semaphore-based queue prevents RAM exhaustion
- **Exponential backoff retry** on timeout/connection errors
- **Streamed I/O** — wordlists are read line-by-line, never loaded into memory
- **Dual output** — real-time console + optional JSON/TXT file (`-o`)

---

### 0. CRT Harvester v1.0 (Passive Recon)

**File:** `scanners/crt-harvester.js`
**Purpose:** Passively enumerate subdomains from public Certificate Transparency logs via crt.sh. This tool **never contacts the target** — all data comes from publicly logged SSL certificates.

**Built-in presets:**
| Preset | Domains | Description |
|---|---|---|
| `google` | 37 root domains | Full Google/Alphabet portfolio including acquisitions (Fitbit, Waze, Mandiant, Kaggle, etc.) |

**Usage:**
```bash
node scanners/crt-harvester.js -d target.com -o target_subs.txt
node scanners/crt-harvester.js --preset google -o google_all_subs.txt
node scanners/crt-harvester.js -d example.com,sub.example.com --delay 5000
```

**All flags:**
| Flag | Description | Default |
|---|---|---|
| `-d, --domains` | Comma-separated root domains | *(required unless using preset)* |
| `--preset` | Use built-in domain set | *available: `google`* |
| `-o, --output` | Save subdomains to text file | *console only* |
| `--delay` | Delay between API calls (ms) | `3000` |
| `-h, --help` | Show help | — |

---

### 1. Ghost Engine v2.0

**File:** `scanners/ghost-engine.js`
**Purpose:** Fuzz target URLs with a wordlist to discover hidden files, exposed configurations, and leaked credentials.

**Matchers (8 built-in):**
| Severity | Detects |
|---|---|
| CRITICAL | `.env` secrets, AWS keys, database credentials, Git config |
| HIGH | Directory listings, stack traces, Spring Actuator, PHPInfo |
| MEDIUM | Swagger/OpenAPI documentation |
| LOW | Login/admin panels |

**Usage:**
```bash
node scanners/ghost-engine.js -u https://target.com -w wordlists/paths.txt
node scanners/ghost-engine.js -u https://target.com -w wordlists/paths.txt -c 100 -o results.json
node scanners/ghost-engine.js -u https://target.com -w wordlists/paths.txt -fs 1234  # filter custom 404 by size
```

**All flags:**
| Flag | Description | Default |
|---|---|---|
| `-u, --url` | Target base URL | *(required)* |
| `-w, --wordlist` | Wordlist file path | `./wordlists/paths.txt` |
| `-c, --concurrency` | Parallel requests | `50` |
| `-t, --timeout` | Timeout per request (ms) | `8000` |
| `-r, --retries` | Max retries per request | `2` |
| `-fs, --filter-size` | Ignore responses of this exact byte size | *disabled* |
| `-o, --output` | Save findings to JSON file | *disabled* |

---

### 2. Specter CORS Scanner v2.0

**File:** `scanners/specter-cors.js`
**Purpose:** Detect Cross-Origin Resource Sharing misconfigurations that allow cross-domain data theft.

**Test vectors (per domain):**
1. Reflected arbitrary origin (`https://evil-attacker.com`)
2. Subdomain trust (`https://evil.target.com`)
3. Null origin injection (`null`)
4. Preflight `OPTIONS` with `Access-Control-Request-Method: PUT`

**Severity classification:**
| Severity | Condition |
|---|---|
| CRITICAL | Reflected origin + `Access-Control-Allow-Credentials: true` |
| CRITICAL | Null origin + credentials |
| HIGH | Reflected origin without credentials |
| HIGH | Wildcard `*` + credentials (misconfigured) |

**Usage:**
```bash
node scanners/specter-cors.js -l wordlists/domains.txt
node scanners/specter-cors.js -l wordlists/domains.txt -c 50 -o cors_results.json
```

**All flags:**
| Flag | Description | Default |
|---|---|---|
| `-l, --list` | Domain list file | `./wordlists/domains.txt` |
| `-c, --concurrency` | Parallel requests | `30` |
| `-t, --timeout` | Timeout per request (ms) | `8000` |
| `-o, --output` | Save findings to JSON file | *disabled* |

---

### 3. Echo Takeover Scanner v2.0

**File:** `scanners/echo-takeover.js`
**Purpose:** Identify subdomains with dangling CNAME records pointing to deprovisioned cloud services.

**How it works:**
1. Resolves DNS CNAME record for each domain
2. Matches CNAME against known cloud provider patterns
3. Only sends HTTP requests if CNAME matches — drastically reduces noise
4. Checks response body for takeover-confirming error messages

**Fingerprint database (21 providers):**
AWS S3, CloudFront, Elastic Beanstalk · Azure Websites, Traffic Manager, Blob · Google Cloud Storage · Heroku · GitHub Pages · GitLab Pages · Shopify · Tumblr · WordPress.com · Pantheon · Surge.sh · Fastly · Fly.io · Netlify · Vercel · Render · Zendesk

**Usage:**
```bash
node scanners/echo-takeover.js -l wordlists/domains.txt
node scanners/echo-takeover.js -l wordlists/domains.txt -c 50 -o takeover_results.json
```

**All flags:**
| Flag | Description | Default |
|---|---|---|
| `-l, --list` | Domain list file | `./wordlists/domains.txt` |
| `-c, --concurrency` | Parallel checks | `30` |
| `-t, --timeout` | Timeout per request (ms) | `8000` |
| `-o, --output` | Save findings to JSON file | *disabled* |

---

### 4. Vanguard DNS Resolver v2.0

**File:** `scanners/vanguard-dns.js`
**Purpose:** Enumerate active subdomains via high-speed DNS brute-forcing with automatic false-positive filtering.

**Key feature — Wildcard Detection:**
Before scanning begins, the tool queries 3 random non-existent subdomains. If they all resolve to the same IP, that IP is flagged as a wildcard and automatically filtered from results.

**Record types resolved:**
| Record | Always | With `-a` flag |
|---|---|---|
| A (IPv4) | ✅ | ✅ |
| CNAME | ✅ | ✅ |
| AAAA (IPv6) | ❌ | ✅ |
| MX | ❌ | ✅ |
| TXT | ❌ | ✅ |

**Usage:**
```bash
node scanners/vanguard-dns.js -d target.com -w wordlists/subdomains.txt
node scanners/vanguard-dns.js -d target.com -w wordlists/subdomains.txt -c 200 -a -o dns_results.json
```

**All flags:**
| Flag | Description | Default |
|---|---|---|
| `-d, --domain` | Target domain | *(required)* |
| `-w, --wordlist` | Subdomain wordlist | `./wordlists/subdomains.txt` |
| `-c, --concurrency` | Parallel DNS queries | `100` |
| `-a, --all-records` | Also resolve AAAA, MX, TXT | *disabled* |
| `--dns` | Custom DNS servers (comma-separated) | `1.1.1.1,8.8.8.8,9.9.9.9` |
| `-o, --output` | Save results to JSON file | *disabled* |

---

## 🛡️ Defensive Engineering

Configurations to detect and block the exact scanning techniques implemented above.

### 1. Fail2ban (`detection/fail2ban_scanner_protection.conf`)
Monitors Nginx/Apache access logs for repeated requests to sensitive paths (`.env`, `.git`, `.sql`, `.zip`, `actuator/*`, `swagger*`). Bans offending IPs via `iptables` after 3 hits within 60 seconds.

### 2. ModSecurity WAF (`detection/modsecurity_waf_rules.conf`)
Three rules:
- **Rule 1000001:** Blocks requests with known scanner User-Agent strings (`sqlmap`, `nuclei`, `nikto`, `ffuf`)
- **Rule 1000002:** Blocks direct access to sensitive file extensions (`.env`, `.git`, `.bak`, `.sql`, `.zip`)
- **Rule 1000003:** Blocks SSRF attempts targeting cloud metadata endpoints (`/latest/meta-data/`)

### 3. Rate Limiter (`detection/rate_limiter.js`)
In-memory Node.js/Express middleware using the Token Bucket algorithm.
- 20 tokens per IP, refills 2 tokens/second
- Auto-purges inactive IPs after 5 minutes (prevents memory leaks)
- Returns `429 Too Many Requests` with `Retry-After` header

```javascript
const rateLimiter = require('./detection/rate_limiter');
app.use(rateLimiter);
```

---

## 🔄 Recommended Workflow

```
Phase 1 — Discover subdomains:
  $ node scanners/vanguard-dns.js -d target.com -w wordlists/subdomains.txt -o found.json

Phase 2 — Check for subdomain takeover:
  $ node scanners/echo-takeover.js -l active_domains.txt -o takeover.json

Phase 3 — Audit CORS policies:
  $ node scanners/specter-cors.js -l active_domains.txt -o cors.json

Phase 4 — Fuzz for hidden files and leaks:
  $ node scanners/ghost-engine.js -u https://api.target.com -w wordlists/paths.txt -o leaks.json
```

---

*Disclaimer: This repository is for educational purposes and authorized security testing only. Do not use against targets without explicit written permission.*
