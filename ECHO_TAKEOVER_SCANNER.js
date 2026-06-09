/**
 * ECHO TAKEOVER SCANNER v2.0 — Subdomain Takeover Detector
 * ==========================================================
 * Detects dangling DNS records pointing to deprovisioned cloud services.
 *
 * Features:
 *  - CLI argument parsing
 *  - DNS CNAME resolution before HTTP fingerprinting (reduces false positives)
 *  - Expanded fingerprint database (20+ cloud providers)
 *  - HTTP + HTTPS fallback (tries both protocols)
 *  - Connection pooling and controlled concurrency
 *  - JSON + Console dual output
 *  - Retry with exponential backoff
 *
 * Usage:
 *   node ECHO_TAKEOVER_SCANNER.js -l domains.txt
 *   node ECHO_TAKEOVER_SCANNER.js -l domains.txt -c 50 -o takeover_results.json
 */

const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
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
  ECHO TAKEOVER SCANNER v2.0

  Usage:
    node ECHO_TAKEOVER_SCANNER.js -l <domain_list> [options]

  Options:
    -l, --list         Path to domain list file (default: ./domains.txt)
    -c, --concurrency  Parallel requests (default: 30)
    -t, --timeout      Request timeout in ms (default: 8000)
    -o, --output       Save results to JSON file
    -h, --help         Show this help message
`);
}

// ============================================================================
// 2. FINGERPRINT DATABASE — Cloud provider error signatures
// ============================================================================
const FINGERPRINTS = [
    // AWS
    { provider: 'AWS S3',             cname: /\.s3[-.].*amazonaws\.com/i,          body: /NoSuchBucket|The specified bucket does not exist/i },
    { provider: 'AWS CloudFront',     cname: /\.cloudfront\.net/i,                 body: /Bad request|The request could not be satisfied/i },
    { provider: 'AWS Elastic Beanstalk', cname: /\.elasticbeanstalk\.com/i,        body: /404 Not Found/i },
    // Azure
    { provider: 'Azure',              cname: /\.azurewebsites\.net/i,              body: /404 Web Site not found|Error 404 - Web app not found/i },
    { provider: 'Azure Traffic Mgr',  cname: /\.trafficmanager\.net/i,             body: /404 Not Found/i },
    { provider: 'Azure Blob',         cname: /\.blob\.core\.windows\.net/i,        body: /BlobNotFound|The specified blob does not exist/i },
    // Google Cloud
    { provider: 'Google Cloud Storage', cname: /\.storage\.googleapis\.com/i,      body: /NoSuchBucket|The specified bucket does not exist/i },
    // Heroku
    { provider: 'Heroku',             cname: /\.herokuapp\.com|\.herokussl\.com/i,  body: /No such app|no-such-app|There is no app configured/i },
    // GitHub
    { provider: 'GitHub Pages',       cname: /\.github\.io/i,                      body: /There isn't a GitHub Pages site here/i },
    // GitLab
    { provider: 'GitLab Pages',       cname: /\.gitlab\.io/i,                      body: /The page you're looking for could not be found/i },
    // Shopify
    { provider: 'Shopify',            cname: /\.myshopify\.com/i,                  body: /Sorry, this shop is currently unavailable/i },
    // Tumblr
    { provider: 'Tumblr',             cname: /\.tumblr\.com/i,                     body: /Whatever you were looking for doesn't currently exist at this address/i },
    // WordPress
    { provider: 'WordPress.com',      cname: /\.wordpress\.com/i,                  body: /Do you want to register/i },
    // Pantheon
    { provider: 'Pantheon',           cname: /\.pantheonsite\.io/i,                body: /404 error unknown site/i },
    // Surge.sh
    { provider: 'Surge.sh',           cname: /\.surge\.sh/i,                       body: /project not found/i },
    // Fastly
    { provider: 'Fastly',             cname: /\.fastly\.net|\.fastlylb\.net/i,     body: /Fastly error: unknown domain/i },
    // Fly.io
    { provider: 'Fly.io',             cname: /\.fly\.dev/i,                        body: /404 Not Found/i },
    // Netlify
    { provider: 'Netlify',            cname: /\.netlify\.app|\.netlify\.com/i,     body: /Not Found - Request ID/i },
    // Vercel
    { provider: 'Vercel',             cname: /\.vercel\.app|\.now\.sh/i,           body: /The deployment could not be found/i },
    // Render
    { provider: 'Render',             cname: /\.onrender\.com/i,                   body: /not found/i },
    // Zendesk
    { provider: 'Zendesk',            cname: /\.zendesk\.com/i,                    body: /Help Center Closed/i },
];

// ============================================================================
// 3. DNS RESOLVER
// ============================================================================
const resolver = new dns.Resolver();
resolver.setServers(['1.1.1.1', '8.8.8.8']);

async function getCNAME(domain) {
    try {
        const cnames = await resolver.resolveCname(domain);
        return cnames.length > 0 ? cnames[0] : null;
    } catch {
        return null;
    }
}

// ============================================================================
// 4. HTTP ENGINE
// ============================================================================
function createAgents(concurrency) {
    return {
        http: new http.Agent({ keepAlive: true, maxSockets: concurrency }),
        https: new https.Agent({ keepAlive: true, maxSockets: concurrency, rejectUnauthorized: false }),
    };
}

function fetchBody(url, config, agents, retries = 0) {
    return new Promise((resolve) => {
        let parsed;
        try {
            parsed = new URL(url);
        } catch {
            return resolve({ url, status: 0, body: '', error: 'INVALID_URL' });
        }

        const isHttps = parsed.protocol === 'https:';
        const client = isHttps ? https : http;
        const agent = isHttps ? agents.https : agents.http;

        const req = client.get(url, {
            agent: agent,
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; EchoTakeover/2.0)', 'Connection': 'keep-alive' },
            timeout: config.timeoutMs,
        }, (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => resolve({ url, status: res.statusCode, body, error: null }));
        });

        req.on('timeout', () => {
            req.destroy();
            if (retries < config.maxRetries) {
                setTimeout(() => resolve(fetchBody(url, config, agents, retries + 1)), Math.pow(2, retries) * 200);
            } else {
                resolve({ url, status: 0, body: '', error: 'TIMEOUT' });
            }
        });

        req.on('error', (err) => {
            if (retries < config.maxRetries) {
                setTimeout(() => resolve(fetchBody(url, config, agents, retries + 1)), Math.pow(2, retries) * 200);
            } else {
                resolve({ url, status: 0, body: '', error: err.code || err.message });
            }
        });
    });
}

// ============================================================================
// 5. TAKEOVER CHECK — DNS-first, then HTTP fingerprint
// ============================================================================
async function checkTakeover(domain, config, agents) {
    // Step 1: Resolve CNAME
    const cname = await getCNAME(domain);

    // Step 2: Match CNAME against known providers
    let matchedProviders = [];
    if (cname) {
        matchedProviders = FINGERPRINTS.filter(fp => fp.cname.test(cname));
    }

    // If no CNAME match, skip HTTP check (reduces noise significantly)
    if (matchedProviders.length === 0 && cname) {
        return null; // Has CNAME but not to a known takeover-prone service
    }

    // Step 3: HTTP fingerprinting (try HTTPS first, fallback to HTTP)
    let response = await fetchBody(`https://${domain}`, config, agents);
    if (response.error) {
        response = await fetchBody(`http://${domain}`, config, agents);
    }
    if (response.error) return null;

    // Step 4: Match response body against fingerprints
    const fingerprintsToCheck = matchedProviders.length > 0 ? matchedProviders : FINGERPRINTS;
    for (const fp of fingerprintsToCheck) {
        if (fp.body.test(response.body)) {
            return {
                domain: domain,
                provider: fp.provider,
                cname: cname || 'N/A',
                status: response.status,
                evidence: response.body.substring(0, 200).trim(),
            };
        }
    }
    return null;
}

// ============================================================================
// 6. CORE ENGINE
// ============================================================================
async function startScanner() {
    const config = parseArgs();
    const agents = createAgents(config.concurrency);
    const results = [];
    const startTime = Date.now();

    console.log(`\n  ╔══════════════════════════════════════════════╗`);
    console.log(`  ║   ☠️  ECHO TAKEOVER SCANNER v2.0              ║`);
    console.log(`  ╠══════════════════════════════════════════════╣`);
    console.log(`  ║  Domain List  : ${config.domainList.padEnd(28)}║`);
    console.log(`  ║  Concurrency  : ${String(config.concurrency).padEnd(28)}║`);
    console.log(`  ║  Fingerprints : ${String(FINGERPRINTS.length + ' providers').padEnd(28)}║`);
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

                checkTakeover(domain, config, agents).then((finding) => {
                    if (finding) {
                        totalVulnerable++;
                        results.push(finding);
                        console.log(`  🔥 [CRITICAL] Subdomain Takeover Possible!`);
                        console.log(`     └─ Domain   : ${finding.domain}`);
                        console.log(`     └─ Provider : ${finding.provider}`);
                        console.log(`     └─ CNAME    : ${finding.cname}`);
                        console.log(`     └─ Evidence : ${finding.evidence.substring(0, 80)}...`);
                    }

                    activeRequests--;
                    totalProcessed++;

                    if (totalProcessed % 50 === 0) {
                        process.stdout.write(`\r  [*] ${totalProcessed} domains checked | ${totalVulnerable} vulnerable`);
                    }

                    processQueue();
                });
            }

            if (isEOF && activeRequests === 0 && queue.length === 0) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                console.log(`\n\n  ✅ Scan complete: ${totalProcessed} domains | ${totalVulnerable} takeover candidates | ${elapsed}s`);

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
