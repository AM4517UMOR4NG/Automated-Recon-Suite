# Automated Recon Suite

> **A high-performance, asynchronous security auditing and defensive engineering suite built entirely in pure Node.js with zero external dependencies.**

This repository contains a comprehensive set of advanced tools designed for scanning hidden endpoints, identifying CORS misconfigurations, detecting subdomain takeovers, and performing fast DNS enumeration, alongside robust configurations to defend against these scan techniques.

---

## 📂 Project Directory Structure

```
Automated-Recon-Suite/
│
├── README.md                           # Main documentation (this file)
│
├── GHOST_ENGINE_ADVANCED.js           # Directory and API endpoint scanner
├── SPECTER_CORS_SCANNER.js             # Multi-vector CORS vulnerability detector
├── ECHO_TAKEOVER_SCANNER.js            # Subdomain takeover analyzer (DNS-first)
├── VANGUARD_DNS_RESOLVER.js            # DNS brute-forcing & wildcard filter engine
│
├── wordlist.txt                        # Fuzzing wordlist (200+ sensitive paths)
├── domains.txt                         # Target lists for CORS/Takeover scanners (500+ dummy domains)
├── subdomains.txt                      # Subdomain enumeration wordlist (~500+ entries)
│
└── detection/                          # Defensive engineering & protection rules
    ├── fail2ban_scanner_protection.conf # Log analysis & automatic firewall ban rule
    ├── modsecurity_waf_rules.conf      # ModSecurity WAF rules (User-Agent & path blocks)
    └── rate_limiter.js                 # In-memory Token Bucket rate limiting middleware
```

---

## ⚔️ Offensive Scanners

All offensive tools leverage connection pooling (`Keep-Alive`), concurrent execution tracking (semaphores), exponential backoff on retry, and non-blocking streaming I/O.

### 1. Ghost Engine v2.0 (`GHOST_ENGINE_ADVANCED.js`)
An advanced directory fuzzer and configuration leak scanner with intelligent response matchers.
- **Features:** Matches headers/bodies for exposed database credentials, config files, AWS keys, git directories, stack traces, and Spring Boot Actuator endpoints.
- **Usage:**
  ```bash
  node GHOST_ENGINE_ADVANCED.js -u https://example.com -w wordlist.txt -c 50 -o results.json
  ```
- **CLI Options:**
  - `-u, --url` : Base target URL (required)
  - `-w, --wordlist` : Path to paths wordlist
  - `-c, --concurrency` : Max parallel requests
  - `-fs, --filter-size` : Skip responses of a specific byte length (bypasses custom 404s)

### 2. Specter CORS Scanner v2.0 (`SPECTER_CORS_SCANNER.js`)
An active scanner targeting Cross-Origin Resource Sharing (CORS) misconfigurations.
- **Features:** Tests domains against reflected origin injection, subdomain trusts, and null origin vectors. Validates preflight responses with `OPTIONS` queries.
- **Usage:**
  ```bash
  node SPECTER_CORS_SCANNER.js -l domains.txt -c 30 -o cors_results.json
  ```

### 3. Echo Takeover Scanner v2.0 (`ECHO_TAKEOVER_SCANNER.js`)
A subdomain takeover detection tool relying on DNS-first validation.
- **Features:** Performs DNS resolution of CNAME records *before* sending HTTP requests to minimize noise. Checks responses against a database of 21 known cloud providers.
- **Usage:**
  ```bash
  node ECHO_TAKEOVER_SCANNER.js -l domains.txt -c 30 -o takeover_results.json
  ```

### 4. Vanguard DNS Resolver v2.0 (`VANGUARD_DNS_RESOLVER.js`)
A high-speed subdomain mapper utilizing DNS brute-forcing.
- **Features:** Automatically detects wildcard DNS records and filters them out to prevent false positives. Resolves multiple record types (A, CNAME, AAAA, MX, TXT).
- **Usage:**
  ```bash
  node VANGUARD_DNS_RESOLVER.js -d example.com -w subdomains.txt -c 100 -a -o dns_results.json
  ```

---

## 🛡️ Defensive Engineering & Detection

Located inside the `detection/` directory, these configurations mitigate automated reconnaissance scans.

### 1. Fail2ban Rule (`detection/fail2ban_scanner_protection.conf`)
- **Vulnerability Blocked:** Directory scanning / Fuzzing.
- **Mechanics:** Monitors web server access logs (like Nginx) via regex. Identifies repeated attempts to access configuration paths (like `.env` or `.git`) and instructs `iptables` to issue a temporary or permanent IP ban.

### 2. ModSecurity WAF Rules (`detection/modsecurity_waf_rules.conf`)
- **Vulnerability Blocked:** Scanning tools, directory traversal, Cloud SSRF attempts.
- **Mechanics:** Checks incoming HTTP request headers and URIs. Rejects traffic displaying signatures of fuzzing tools or matching known SSRF targets (such as AWS Instance Metadata endpoints).

### 3. In-Memory Token Bucket Rate Limiter (`detection/rate_limiter.js`)
- **Vulnerability Blocked:** High-frequency automated attacks / Denial of Service.
- **Mechanics:** An in-memory middleware that throttles IP addresses based on the Token Bucket algorithm. 
- **Setup:** Import directly into Express.js:
  ```javascript
  const rateLimiter = require('./detection/rate_limiter');
  app.use(rateLimiter);
  ```

---

## 🔄 Recommended Auditing Workflow

1. **Phase 1: Subdomain Discovery**
   ```bash
   node VANGUARD_DNS_RESOLVER.js -d target.com -w subdomains.txt -o active_subs.json
   ```
2. **Phase 2: Subdomain Takeover Analysis**
   Extract domain list from output and check for takeover:
   ```bash
   node ECHO_TAKEOVER_SCANNER.js -l resolved_domains.txt -o takeover_vulns.json
   ```
3. **Phase 3: CORS Configuration Auditing**
   ```bash
   node SPECTER_CORS_SCANNER.js -l resolved_domains.txt -o cors_vulns.json
   ```
4. **Phase 4: Endpoint and Configuration Fuzzing**
   ```bash
   node GHOST_ENGINE_ADVANCED.js -u https://api.target.com -w wordlist.txt -o leaks.json
   ```

---
*Disclaimer: This repository is created for educational purposes and authorized auditing only. Unauthorized scanning of external targets is strictly prohibited.*
