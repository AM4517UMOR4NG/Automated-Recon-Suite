# Automated Recon Suite

> **A suite of advanced automated scanners focusing on hidden API endpoints, configuration leaks, and cloud misconfigurations.**

## Tools Included

### 1. Ghost Engine (`GHOST_ENGINE_ADVANCED.js`)
A high-performance, asynchronous vulnerability scanner built in Node.js. Designed to replicate the concurrency and connection pooling capabilities of industry-standard tools (like Nuclei and FFUF) but fully customizable in JavaScript.

**Features:**
- **TCP Connection Pooling:** Uses `keepAlive` for extreme speed.
- **Concurrency Limiting:** Safely executes dozens of requests simultaneously without memory leaks.
- **Smart Matchers:** Uses Regex to detect sensitive secrets in response bodies (e.g., AWS Keys, DB Passwords, JWTs).
- **Asynchronous Streaming:** Reads massive wordlists without loading them entirely into RAM.

**Usage:**
```bash
node GHOST_ENGINE_ADVANCED.js
```
*Note: Make sure to edit the `CONFIG` block inside the script to point to your target and specify your wordlist.*

---
*Disclaimer: This repository is for educational purposes and authorized bug bounty hunting only. Do not use against targets without explicit permission.*
