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

---
*Disclaimer: This repository is for educational purposes and authorized bug bounty hunting only. Do not use against targets without explicit permission.*
