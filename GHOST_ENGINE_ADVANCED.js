/**
 * GHOST ENGINE v2.0 — High-Performance Asynchronous Vulnerability Scanner
 * ========================================================================
 * Architecture modeled after Nuclei/FFUF core engines.
 *
 * Features:
 *  - CLI argument parsing (no hardcoded config)
 *  - TCP connection pooling with Keep-Alive
 *  - Controlled concurrency via semaphore pattern
 *  - Smart regex matchers with severity classification
 *  - Auto-retry with exponential backoff
 *  - JSON + Console dual output
 *  - Streamed wordlist reading (constant memory)
 *  - Follow redirects support
 *  - Response size filtering (avoid false positives on custom 404 pages)
 *
 * Usage:
 *   node GHOST_ENGINE_ADVANCED.js -u https://target.com -w wordlist.txt
 *   node GHOST_ENGINE_ADVANCED.js -u https://target.com -w wordlist.txt -c 100 -o results.json
 */

const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');
const path = require('path');
const { URL } = require('url');

// ============================================================================
// 1. CLI ARGUMENT PARSER
// ============================================================================
function parseArgs() {
    const args = process.argv.slice(2);
    const config = {
        targetUrl: '',
        wordlistPath: './wordlist.txt',
        concurrency: 50,
        timeoutMs: 8000,
        maxRetries: 2,
        outputFile: '',
        filterSize: -1, // Filter out responses of this exact size (custom 404 detection)
        followRedirects: true,
        maxRedirects: 3,
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '-u': case '--url':       config.targetUrl = args[++i]; break;
            case '-w': case '--wordlist':  config.wordlistPath = args[++i]; break;
            case '-c': case '--concurrency': config.concurrency = parseInt(args[++i], 10); break;
            case '-t': case '--timeout':   config.timeoutMs = parseInt(args[++i], 10); break;
            case '-r': case '--retries':   config.maxRetries = parseInt(args[++i], 10); break;
            case '-o': case '--output':    config.outputFile = args[++i]; break;
            case '-fs': case '--filter-size': config.filterSize = parseInt(args[++i], 10); break;
            case '-h': case '--help':      printUsage(); process.exit(0);
            default: break;
        }
    }

    if (!config.targetUrl) {
        printUsage();
        process.exit(1);
    }
    return config;
}

function printUsage() {
    console.log(`
  GHOST ENGINE v2.0 — Vulnerability Scanner

  Usage:
    node GHOST_ENGINE_ADVANCED.js -u <target_url> [options]

  Required:
    -u, --url          Target base URL (e.g., https://example.com)

  Optional:
    -w, --wordlist     Path to wordlist file (default: ./wordlist.txt)
    -c, --concurrency  Number of parallel requests (default: 50)
    -t, --timeout      Request timeout in ms (default: 8000)
    -r, --retries      Max retries per request (default: 2)
    -o, --output       Save results to JSON file
    -fs, --filter-size Filter out responses with this exact body size
    -h, --help         Show this help message

  Examples:
    node GHOST_ENGINE_ADVANCED.js -u https://target.com -w wordlist.txt
    node GHOST_ENGINE_ADVANCED.js -u https://target.com -w big_list.txt -c 100 -o results.json
`);
}

// ============================================================================
// 2. MATCHERS — Pattern-based vulnerability detection
// ============================================================================
const MATCHERS = [
    {
        name: 'Secrets / Credentials Exposed',
        statusCodes: [200],
        bodyRegex: /(DB_PASSWORD|DB_HOST|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|JWT_SECRET|API_KEY|PRIVATE_KEY|SECRET_KEY|DATABASE_URL|MONGO_URI|REDIS_URL)\s*[=:]/i,
        severity: 'CRITICAL',
    },
    {
        name: 'Git Configuration Exposed',
        statusCodes: [200],
        bodyRegex: /\[core\]\s*\n\s*repositoryformatversion|\[remote "origin"\]/i,
        severity: 'CRITICAL',
    },
    {
        name: 'Directory Listing Enabled',
        statusCodes: [200],
        bodyRegex: /<title>Index of \//i,
        severity: 'HIGH',
    },
    {
        name: 'Stack Trace / Debug Information',
        statusCodes: [200, 500, 502, 503],
        bodyRegex: /stack\s*trace|Traceback \(most recent call last\)|SQLSTATE\[|mysql_query\(|pg_query\(|at\s+[\w.]+\([\w/]+\.java:\d+\)/i,
        severity: 'HIGH',
    },
    {
        name: 'Swagger / API Documentation Exposed',
        statusCodes: [200],
        bodyRegex: /"swagger"\s*:\s*"[23]\.|"openapi"\s*:\s*"3\./i,
        severity: 'MEDIUM',
    },
    {
        name: 'Admin / Login Panel Found',
        statusCodes: [200],
        bodyRegex: /<form[\s\S]*?(type="password"|name="password")/i,
        severity: 'LOW',
    },
    {
        name: 'Spring Boot Actuator Exposed',
        statusCodes: [200],
        bodyRegex: /"_links"\s*:\s*\{[\s\S]*?"self"/i,
        severity: 'HIGH',
    },
    {
        name: 'PHP Info Page Exposed',
        statusCodes: [200],
        bodyRegex: /<title>phpinfo\(\)<\/title>|PHP Version \d+\.\d+/i,
        severity: 'HIGH',
    },
];

// ============================================================================
// 3. HTTP ENGINE — Connection Pooling, Retry, Redirect Handling
// ============================================================================
const USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
];

function createAgents(concurrency) {
    return {
        http: new http.Agent({ keepAlive: true, maxSockets: concurrency, maxFreeSockets: 10 }),
        https: new https.Agent({ keepAlive: true, maxSockets: concurrency, maxFreeSockets: 10, rejectUnauthorized: false }),
    };
}

function makeRequest(fullUrl, config, agents, retries = 0, redirectCount = 0) {
    return new Promise((resolve) => {
        let parsed;
        try {
            parsed = new URL(fullUrl);
        } catch {
            return resolve({ url: fullUrl, status: 0, body: '', headers: {}, error: 'INVALID_URL' });
        }

        const isHttps = parsed.protocol === 'https:';
        const client = isHttps ? https : http;
        const agent = isHttps ? agents.https : agents.http;
        const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

        const reqOptions = {
            hostname: parsed.hostname,
            port: parsed.port || (isHttps ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'GET',
            agent: agent,
            headers: {
                'User-Agent': ua,
                'Accept': 'text/html,application/json,*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
            },
            timeout: config.timeoutMs,
        };

        const req = client.request(reqOptions, (res) => {
            // Handle redirects
            if (config.followRedirects && [301, 302, 307, 308].includes(res.statusCode) && redirectCount < config.maxRedirects) {
                const location = res.headers['location'];
                if (location) {
                    const redirectUrl = location.startsWith('http') ? location : new URL(location, fullUrl).href;
                    res.resume(); // Drain the response
                    return resolve(makeRequest(redirectUrl, config, agents, 0, redirectCount + 1));
                }
            }

            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                resolve({
                    url: fullUrl,
                    status: res.statusCode,
                    body: body,
                    headers: res.headers,
                    size: Buffer.byteLength(body, 'utf8'),
                    error: null,
                });
            });
        });

        req.on('timeout', () => {
            req.destroy();
            if (retries < config.maxRetries) {
                const delay = Math.pow(2, retries) * 200; // Exponential backoff
                setTimeout(() => resolve(makeRequest(fullUrl, config, agents, retries + 1, redirectCount)), delay);
            } else {
                resolve({ url: fullUrl, status: 0, body: '', headers: {}, size: 0, error: 'TIMEOUT' });
            }
        });

        req.on('error', (err) => {
            if (retries < config.maxRetries) {
                const delay = Math.pow(2, retries) * 200;
                setTimeout(() => resolve(makeRequest(fullUrl, config, agents, retries + 1, redirectCount)), delay);
            } else {
                resolve({ url: fullUrl, status: 0, body: '', headers: {}, size: 0, error: err.code || err.message });
            }
        });

        req.end();
    });
}

// ============================================================================
// 4. ANALYZER — Match responses against vulnerability signatures
// ============================================================================
function analyzeResponse(response, config) {
    if (response.error) return null;
    if (response.status === 404 || response.status === 403 || response.status === 401) return null;
    if (config.filterSize >= 0 && response.size === config.filterSize) return null;

    for (const matcher of MATCHERS) {
        if (matcher.statusCodes.includes(response.status) && matcher.bodyRegex.test(response.body)) {
            return {
                type: 'vulnerability',
                name: matcher.name,
                severity: matcher.severity,
                url: response.url,
                status: response.status,
                size: response.size,
            };
        }
    }

    if (response.status === 200) {
        return {
            type: 'interesting',
            name: 'Valid Path',
            severity: 'INFO',
            url: response.url,
            status: response.status,
            size: response.size,
        };
    }
    return null;
}

// ============================================================================
// 5. CORE ENGINE — Semaphore-based concurrency control
// ============================================================================
async function startEngine() {
    const config = parseArgs();
    const agents = createAgents(config.concurrency);
    const results = [];

    const startTime = Date.now();

    console.log(`\n  ╔══════════════════════════════════════════════╗`);
    console.log(`  ║   👻 GHOST ENGINE v2.0                       ║`);
    console.log(`  ╠══════════════════════════════════════════════╣`);
    console.log(`  ║  Target      : ${config.targetUrl.padEnd(29)}║`);
    console.log(`  ║  Wordlist    : ${config.wordlistPath.padEnd(29)}║`);
    console.log(`  ║  Concurrency : ${String(config.concurrency).padEnd(29)}║`);
    console.log(`  ║  Timeout     : ${(config.timeoutMs + 'ms').padEnd(29)}║`);
    console.log(`  ╚══════════════════════════════════════════════╝\n`);

    if (!fs.existsSync(config.wordlistPath)) {
        console.error(`  [!] Wordlist not found: ${config.wordlistPath}`);
        process.exit(1);
    }

    const fileStream = fs.createReadStream(config.wordlistPath);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    let activeRequests = 0;
    let isEOF = false;
    let queue = [];
    let totalProcessed = 0;
    let totalFound = 0;

    return new Promise((resolve) => {
        const processQueue = () => {
            while (queue.length > 0 && activeRequests < config.concurrency) {
                const wordPath = queue.shift();
                activeRequests++;

                const baseUrl = config.targetUrl.replace(/\/+$/, '');
                const cleanPath = wordPath.replace(/^\/+/, '');
                const fullUrl = `${baseUrl}/${cleanPath}`;

                makeRequest(fullUrl, config, agents).then((response) => {
                    const finding = analyzeResponse(response, config);
                    if (finding) {
                        results.push(finding);
                        totalFound++;
                        const icon = finding.severity === 'CRITICAL' ? '🔥' :
                                     finding.severity === 'HIGH' ? '🟠' :
                                     finding.severity === 'MEDIUM' ? '🟡' :
                                     finding.severity === 'LOW' ? '🔵' : '⚪';
                        console.log(`  ${icon} [${finding.severity}] ${finding.name}`);
                        console.log(`     └─ ${finding.url} (${finding.status}, ${finding.size}b)`);
                    }

                    activeRequests--;
                    totalProcessed++;

                    if (totalProcessed % 200 === 0) {
                        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                        const rps = (totalProcessed / (elapsed || 1)).toFixed(0);
                        process.stdout.write(`\r  [*] ${totalProcessed} requests | ${totalFound} findings | ${rps} req/s | ${elapsed}s elapsed`);
                    }

                    processQueue();
                });
            }

            if (isEOF && activeRequests === 0 && queue.length === 0) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const rps = (totalProcessed / (elapsed || 1)).toFixed(0);
                console.log(`\n\n  ✅ Scan complete: ${totalProcessed} requests | ${totalFound} findings | ${rps} req/s | ${elapsed}s`);

                if (config.outputFile && results.length > 0) {
                    fs.writeFileSync(config.outputFile, JSON.stringify(results, null, 2));
                    console.log(`  📄 Results saved to: ${config.outputFile}`);
                }

                agents.http.destroy();
                agents.https.destroy();
                resolve();
            }
        };

        rl.on('line', (line) => {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                queue.push(trimmed);
                processQueue();
            }
        });

        rl.on('close', () => {
            isEOF = true;
            processQueue();
        });
    });
}

startEngine();
