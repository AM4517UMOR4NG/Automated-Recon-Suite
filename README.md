# Automated Recon Suite

> **A suite of advanced automated scanners focusing on hidden API endpoints, configuration leaks, and cloud misconfigurations.**

## Tools Included

### 1. Ghost Engine (`GHOST_ENGINE_ADVANCED.js`)
A high-performance, asynchronous vulnerability scanner built in Node.js. Designed to replicate the concurrency and connection pooling capabilities of industry-standard tools (like Nuclei and FFUF).
- **Features**: Detects sensitive secrets in response bodies using Smart Matchers, TCP Connection Pooling.
- **Usage**: `node GHOST_ENGINE_ADVANCED.js` (Requires `wordlist.txt`)

### 2. Specter CORS Scanner (`SPECTER_CORS_SCANNER.js`)
An asynchronous scanner designed to detect Cross-Origin Resource Sharing (CORS) misconfigurations across hundreds of subdomains.
- **Features**: Injects arbitrary origins and validates if `Access-Control-Allow-Credentials: true` is reflected, indicating a critical data theft vulnerability.
- **Usage**: `node SPECTER_CORS_SCANNER.js` (Requires `domains.txt`)

### 3. Echo Takeover Scanner (`ECHO_TAKEOVER_SCANNER.js`)
A fast reconnaissance tool for detecting Subdomain Takeover vulnerabilities. 
- **Features**: Analyzes HTTP response bodies against a signature database (fingerprints) of known cloud providers (AWS S3, GitHub Pages, Heroku, etc.) to detect dangling DNS records.
- **Usage**: `node ECHO_TAKEOVER_SCANNER.js` (Requires `domains.txt`)

### 4. Vanguard DNS Resolver (`VANGUARD_DNS_RESOLVER.js`)
An advanced, asynchronous DNS brute-forcing engine designed to map active subdomains and resolve IP/CNAME metadata.
- **Features**: Queries external DNS resolvers (Cloudflare/Google) in parallel without using local OS cache. Exposes CNAME mappings for Subdomain Takeover checks.
- **Usage**: `node VANGUARD_DNS_RESOLVER.js` (Requires `subdomains.txt`)

---

## Defensive Engineering & Detection

To counter automated reconnaissance and scanning, you should implement defensive measures at the server and firewall levels. This repository provides boilerplate configurations under the `detection/` directory:

### 1. Fail2ban Rule (`detection/fail2ban_scanner_protection.conf`)
An automated log analyzer configuration that monitors web access logs and issues a firewall ban (IP tables) when aggressive directory scanning behavior is detected.

### 2. ModSecurity WAF Rules (`detection/modsecurity_waf_rules.conf`)
Web Application Firewall (WAF) rule definitions designed to drop requests with automated scanner User-Agent signatures and access attempts targeting configuration files.

---
*Disclaimer: This repository is for educational purposes and authorized bug bounty hunting only. Do not use against targets without explicit permission.*
