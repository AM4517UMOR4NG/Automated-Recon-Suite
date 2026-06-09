# Automated Recon Suite

> **A suite of advanced automated scanners focusing on hidden API endpoints, configuration leaks, CORS misconfigurations, subdomain takeover, and DNS enumeration — built for modern bug bounty hunting.**

All tools are written in pure Node.js with **zero external dependencies**. They use industrial-grade patterns: TCP connection pooling, semaphore-based concurrency control, exponential backoff retry, streamed I/O, and structured JSON output.

---

## Offensive Tools

### 1. Ghost Engine v2.0 (`GHOST_ENGINE_ADVANCED.js`)
High-performance directory and file scanner with smart vulnerability detection.

| Feature | Detail |
|---|---|
| Connection Pooling | TCP Keep-Alive with configurable socket limits |
| Smart Matchers | 8 regex-based signatures (secrets, git, swagger, phpinfo, stack traces) |
| Redirect Following | Follows 301/302/307/308 with configurable depth |
| Response Filtering | Filter out custom 404 pages by exact body size (`-fs`) |
| Retry Logic | Exponential backoff on timeout/connection errors |
| Output | Console + JSON file (`-o results.json`) |

```bash
node GHOST_ENGINE_ADVANCED.js -u https://target.com -w wordlist.txt -c 100 -o results.json
```

### 2. Specter CORS Scanner v2.0 (`SPECTER_CORS_SCANNER.js`)
Multi-vector CORS misconfiguration detector.

| Feature | Detail |
|---|---|
| Test Vectors | Reflected origin, null origin, wildcard + credentials |
| Preflight Validation | Sends OPTIONS requests with custom `Access-Control-Request-*` headers |
| Severity Classification | CRITICAL / HIGH / MEDIUM based on ACAO + ACAC combination |
| Output | Console + JSON file |

```bash
node SPECTER_CORS_SCANNER.js -l domains.txt -c 50 -o cors_results.json
```

### 3. Echo Takeover Scanner v2.0 (`ECHO_TAKEOVER_SCANNER.js`)
Subdomain takeover detector with DNS-first validation.

| Feature | Detail |
|---|---|
| DNS-First Approach | Resolves CNAME before HTTP check — reduces false positives |
| Fingerprint Database | 21 cloud providers (AWS, Azure, GCP, Heroku, Netlify, Vercel, etc.) |
| Protocol Fallback | Tries HTTPS first, falls back to HTTP |
| Evidence Capture | Stores first 200 chars of matching response body |
| Output | Console + JSON file |

```bash
node ECHO_TAKEOVER_SCANNER.js -l domains.txt -c 30 -o takeover_results.json
```

### 4. Vanguard DNS Resolver v2.0 (`VANGUARD_DNS_RESOLVER.js`)
High-speed subdomain enumeration engine.

| Feature | Detail |
|---|---|
| Wildcard Detection | Auto-detects and filters catch-all DNS records |
| Multi-Record | Resolves A, AAAA, CNAME, MX, TXT (with `-a` flag) |
| Custom DNS Servers | Bypass local cache via Cloudflare/Google/Quad9 |
| Output | Console + JSON file |

```bash
node VANGUARD_DNS_RESOLVER.js -d target.com -w subdomains.txt -c 200 -a -o dns_results.json
```

---

## Recommended Workflow

```
1. Enumerate subdomains     →  node VANGUARD_DNS_RESOLVER.js -d target.com -w subdomains.txt -o found.json
2. Check for takeover       →  node ECHO_TAKEOVER_SCANNER.js -l active_domains.txt -o takeover.json
3. Scan for CORS misconfig  →  node SPECTER_CORS_SCANNER.js -l active_domains.txt -o cors.json
4. Fuzz for hidden files    →  node GHOST_ENGINE_ADVANCED.js -u https://sub.target.com -w wordlist.txt -o ghost.json
```

---

## Defensive Engineering & Detection

Configurations to detect and block automated scanning at the server/firewall level.

| Tool | File | Purpose |
|---|---|---|
| Fail2ban | `detection/fail2ban_scanner_protection.conf` | Auto-ban IPs triggering sensitive path patterns |
| ModSecurity WAF | `detection/modsecurity_waf_rules.conf` | Block scanner User-Agents and config file access |
| Rate Limiter | `detection/rate_limiter.js` | In-memory Token Bucket middleware for Node.js/Express |

---

## Quick Reference

| Flag | Ghost Engine | Specter CORS | Echo Takeover | Vanguard DNS |
|---|---|---|---|---|
| Target | `-u <url>` | `-l <file>` | `-l <file>` | `-d <domain>` |
| Wordlist | `-w <file>` | — | — | `-w <file>` |
| Concurrency | `-c <n>` | `-c <n>` | `-c <n>` | `-c <n>` |
| Output | `-o <file>` | `-o <file>` | `-o <file>` | `-o <file>` |
| Timeout | `-t <ms>` | `-t <ms>` | `-t <ms>` | — |
| Help | `-h` | `-h` | `-h` | `-h` |

---

*Disclaimer: This repository is for educational purposes and authorized bug bounty hunting only. Do not use against targets without explicit permission.*
