/**
 * SPECTER CORS SCANNER v2.0 — Cross-Origin Misconfiguration Detector
 * ====================================================================
 * Detects dangerous CORS misconfigurations that enable cross-domain data theft.
 *
 * Features:
 *  - CLI argument parsing
 *  - Multi-vector CORS testing (reflected origin, wildcard, null origin)
 *  - Preflight OPTIONS request validation
 *  - Connection pooling with Keep-Alive
 *  - Controlled concurrency
 *  - JSON + Console dual output
 *  - Retry with exponential backoff
 *
 * Usage:
 *   node SPECTER_CORS_SCANNER.js -l domains.txt
 *   node SPECTER_CORS_SCANNER.js -l domains.txt -c 50 -o cors_results.json
 */

const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');
const { URL } = require('url');

// ============================================================================
// 1. CLI ARGUMENT PARSER
// ============================================================================
function parseArgs() {
    const args = process.argv.slice(2);
    const config = {
        domainList: './domains.txt',
        concurrency: 30,
        timeoutMs: 8000,
        maxRetries: 2,
        outputFile: '',
        evilOrigins: [
            'https://evil-attacker.com',
            'https://evil.target.com',  // Subdomain trust test
            'null',                      // null origin test
        ],
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '-l': case '--list':        config.domainList = args[++i]; break;
            case '-c': case '--concurrency': config.concurrency = parseInt(args[++i], 10); break;
            case '-t': case '--timeout':     config.timeoutMs = parseInt(args[++i], 10); break;
            case '-o': case '--output':      config.outputFile = args[++i]; break;
            case '-h': case '--help':        printUsage(); process.exit(0);
            default: break;
        }
    }
    return config;
}

function printUsage() {
    console.log(`
  SPECTER CORS SCANNER v2.0

  Usage:
    node SPECTER_CORS_SCANNER.js -l <domain_list> [options]

  Options:
    -l, --list         Path to domain list file (default: ./domains.txt)
    -c, --concurrency  Parallel requests (default: 30)
    -t, --timeout      Request timeout in ms (default: 8000)
    -o, --output       Save results to JSON file
    -h, --help         Show this help message
`);
}

// ============================================================================
// 2. HTTP ENGINE
// ============================================================================
function createAgents(concurrency) {
    return {
        http: new http.Agent({ keepAlive: true, maxSockets: concurrency }),
        https: new https.Agent({ keepAlive: true, maxSockets: concurrency, rejectUnauthorized: false }),
    };
}

function sendRequest(url, method, headers, config, agents, retries = 0) {
    return new Promise((resolve) => {
        let parsed;
        try {
            parsed = new URL(url);
        } catch {
            return resolve({ url, status: 0, headers: {}, error: 'INVALID_URL' });
        }

        const isHttps = parsed.protocol === 'https:';
        const client = isHttps ? https : http;
        const agent = isHttps ? agents.https : agents.http;

        const reqOptions = {
            hostname: parsed.hostname,
            port: parsed.port || (isHttps ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: method,
            agent: agent,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Connection': 'keep-alive',
                ...headers,
            },
            timeout: config.timeoutMs,
        };

        const req = client.request(reqOptions, (res) => {
            res.resume(); // Drain body — we only need headers
            res.on('end', () => {
                resolve({ url, status: res.statusCode, headers: res.headers, error: null });
            });
        });

        req.on('timeout', () => {
            req.destroy();
            if (retries < config.maxRetries) {
                setTimeout(() => resolve(sendRequest(url, method, headers, config, agents, retries + 1)), Math.pow(2, retries) * 200);
            } else {
                resolve({ url, status: 0, headers: {}, error: 'TIMEOUT' });
            }
        });

        req.on('error', (err) => {
            if (retries < config.maxRetries) {
                setTimeout(() => resolve(sendRequest(url, method, headers, config, agents, retries + 1)), Math.pow(2, retries) * 200);
            } else {
                resolve({ url, status: 0, headers: {}, error: err.code || err.message });
            }
        });

        req.end();
    });
}

// ============================================================================
// 3. CORS ANALYSIS ENGINE
// ============================================================================
function classifyCORS(response, injectedOrigin) {
    const acao = response.headers['access-control-allow-origin'];
    const acac = response.headers['access-control-allow-credentials'];

    if (!acao) return null;

    const findings = [];

    // Critical: Reflected arbitrary origin + credentials
    if (acao === injectedOrigin && acac === 'true') {
        findings.push({
            severity: 'CRITICAL',
            type: 'Reflected Origin with Credentials',
            detail: `ACAO: ${acao} | ACAC: true`,
        });
    }
    // High: Reflected arbitrary origin without credentials
    else if (acao === injectedOrigin && acac !== 'true') {
        findings.push({
            severity: 'HIGH',
            type: 'Reflected Origin (No Credentials)',
            detail: `ACAO: ${acao} | ACAC: ${acac || 'absent'}`,
        });
    }
    // High: Wildcard with credentials (browser ignores this, but indicates bad config)
    else if (acao === '*' && acac === 'true') {
        findings.push({
            severity: 'HIGH',
            type: 'Wildcard with Credentials (Misconfigured)',
            detail: `ACAO: * | ACAC: true`,
        });
    }
    // Medium: Null origin reflected + credentials
    else if (acao === 'null' && acac === 'true') {
        findings.push({
            severity: 'CRITICAL',
            type: 'Null Origin Reflected with Credentials',
            detail: `ACAO: null | ACAC: true (exploitable via sandboxed iframe)`,
        });
    }

    return findings.length > 0 ? findings : null;
}

async function checkDomain(domain, config, agents) {
    let url = domain.startsWith('http') ? domain : `https://${domain}`;
    const allFindings = [];

    for (const origin of config.evilOrigins) {
        // Test 1: Standard GET with injected Origin
        const getResponse = await sendRequest(url, 'GET', { 'Origin': origin }, config, agents);
        if (!getResponse.error) {
            const findings = classifyCORS(getResponse, origin);
            if (findings) {
                findings.forEach(f => allFindings.push({ ...f, url, origin, method: 'GET' }));
            }
        }

        // Test 2: Preflight OPTIONS request
        const optResponse = await sendRequest(url, 'OPTIONS', {
            'Origin': origin,
            'Access-Control-Request-Method': 'PUT',
            'Access-Control-Request-Headers': 'Authorization',
        }, config, agents);
        if (!optResponse.error) {
            const findings = classifyCORS(optResponse, origin);
            if (findings) {
                findings.forEach(f => allFindings.push({ ...f, url, origin, method: 'OPTIONS' }));
            }
        }
    }
    return allFindings;
}

// ============================================================================
// 4. CORE ENGINE
// ============================================================================
async function startScanner() {
    const config = parseArgs();
    const agents = createAgents(config.concurrency);
    const results = [];
    const startTime = Date.now();

    console.log(`\n  ╔══════════════════════════════════════════════╗`);
    console.log(`  ║   👁️  SPECTER CORS SCANNER v2.0              ║`);
    console.log(`  ╠══════════════════════════════════════════════╣`);
    console.log(`  ║  Domain List : ${config.domainList.padEnd(29)}║`);
    console.log(`  ║  Concurrency : ${String(config.concurrency).padEnd(29)}║`);
    console.log(`  ║  Origins     : ${String(config.evilOrigins.length + ' vectors').padEnd(29)}║`);
    console.log(`  ╚══════════════════════════════════════════════╝\n`);

    if (!fs.existsSync(config.domainList)) {
        console.error(`  [!] Domain list not found: ${config.domainList}`);
        process.exit(1);
    }

    const rl = readline.createInterface({ input: fs.createReadStream(config.domainList), crlfDelay: Infinity });
    let activeRequests = 0;
    let isEOF = false;
    let queue = [];
    let totalProcessed = 0;
    let totalVulnerable = 0;

    return new Promise((resolve) => {
        const processQueue = () => {
            while (queue.length > 0 && activeRequests < config.concurrency) {
                const domain = queue.shift();
                activeRequests++;

                checkDomain(domain, config, agents).then((findings) => {
                    if (findings.length > 0) {
                        totalVulnerable++;
                        findings.forEach(f => {
                            results.push(f);
                            const icon = f.severity === 'CRITICAL' ? '🔥' : f.severity === 'HIGH' ? '🟠' : '🟡';
                            console.log(`  ${icon} [${f.severity}] ${f.type}`);
                            console.log(`     └─ ${f.url} | Origin: ${f.origin} | ${f.method}`);
                            console.log(`     └─ ${f.detail}`);
                        });
                    }

                    activeRequests--;
                    totalProcessed++;

                    if (totalProcessed % 50 === 0) {
                        process.stdout.write(`\r  [*] ${totalProcessed} domains scanned | ${totalVulnerable} vulnerable`);
                    }

                    processQueue();
                });
            }

            if (isEOF && activeRequests === 0 && queue.length === 0) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                console.log(`\n\n  ✅ Scan complete: ${totalProcessed} domains | ${totalVulnerable} vulnerable | ${elapsed}s`);

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

startScanner();
