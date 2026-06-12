/**
 * CRT HARVESTER v1.0 — Certificate Transparency Subdomain Enumerator
 * ====================================================================
 * Passive reconnaissance tool that extracts subdomains from public
 * Certificate Transparency (CT) logs via crt.sh API.
 *
 * This is 100% stealth — it never touches the target server directly.
 * All data comes from publicly logged SSL certificates.
 *
 * Features:
 *  - Queries crt.sh JSON API for multiple root domains
 *  - Deduplicates and normalizes all discovered subdomains
 *  - Filters out wildcard entries and invalid hostnames
 *  - Rate-limited requests to avoid crt.sh throttling
 *  - Outputs clean domain list ready for scanner pipeline
 *  - CLI argument parsing
 *
 * Usage:
 *   node scanners/crt-harvester.js -d google.com
 *   node scanners/crt-harvester.js -d google.com,googleapis.com,withgoogle.com -o google_subs.txt
 *   node scanners/crt-harvester.js --preset google -o google_all_subs.txt
 */

const https = require('https');
const fs = require('fs');
const { URL } = require('url');

// ============================================================================
// 1. CLI ARGUMENT PARSER
// ============================================================================
const PRESETS = {
    google: [
        'google.com',
        'googleapis.com',
        'gstatic.com',
        'withgoogle.com',
        'google.co.id',
        'google.co.jp',
        'google.co.uk',
        'google.com.br',
        'google.de',
        'google.fr',
        'googlesource.com',
        'googleusercontent.com',
        'googlevideo.com',
        'googleadservices.com',
        'googlesyndication.com',
        'googletagmanager.com',
        'doubleclick.net',
        'youtube.com',
        'ytimg.com',
        'ggpht.com',
        'abc.xyz',
        'about.google',
        'domains.google',
        'blog.google',
        'store.google.com',
        'cloud.google.com',
        'firebase.google.com',
        'web.dev',
        'chromium.org',
        'android.com',
        'waze.com',
        'fitbit.com',
        'mandiant.com',
        'looker.com',
        'area120.google.com',
        'deepmind.com',
        'kaggle.com',
    ],
};

function parseArgs() {
    const args = process.argv.slice(2);
    const config = {
        domains: [],
        outputFile: '',
        delayMs: 3000, // Delay between crt.sh requests (rate limiting)
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '-d': case '--domains':
                config.domains = args[++i].split(',').map(d => d.trim());
                break;
            case '--preset':
                const presetName = args[++i];
                if (PRESETS[presetName]) {
                    config.domains = PRESETS[presetName];
                } else {
                    console.error(`  [!] Unknown preset: ${presetName}. Available: ${Object.keys(PRESETS).join(', ')}`);
                    process.exit(1);
                }
                break;
            case '-o': case '--output':
                config.outputFile = args[++i];
                break;
            case '--delay':
                config.delayMs = parseInt(args[++i], 10);
                break;
            case '-h': case '--help':
                printUsage();
                process.exit(0);
            default: break;
        }
    }

    if (config.domains.length === 0) {
        printUsage();
        process.exit(1);
    }
    return config;
}

function printUsage() {
    console.log(`
  CRT HARVESTER v1.0 — CT Log Subdomain Enumerator

  Usage:
    node scanners/crt-harvester.js -d <domain1,domain2,...> [options]
    node scanners/crt-harvester.js --preset google [options]

  Required (one of):
    -d, --domains    Comma-separated list of root domains to query
    --preset         Use a built-in domain set (available: google)

  Optional:
    -o, --output     Save unique subdomains to a text file
    --delay          Delay between API requests in ms (default: 3000)
    -h, --help       Show this help message

  Examples:
    node scanners/crt-harvester.js -d google.com -o google_subs.txt
    node scanners/crt-harvester.js --preset google -o google_all_subs.txt
    node scanners/crt-harvester.js -d example.com,sub.example.com --delay 5000
`);
}

// ============================================================================
// 2. CRT.SH API CLIENT
// ============================================================================
function queryCrtSh(domain) {
    return new Promise((resolve) => {
        const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

        const req = https.get(url, {
            headers: {
                'User-Agent': 'CRT-Harvester/1.0 (Security Research)',
                'Accept': 'application/json',
            },
            timeout: 30000,
        }, (res) => {
            // Handle redirects
            if ([301, 302].includes(res.statusCode) && res.headers.location) {
                res.resume();
                return resolve(queryCrtSh(domain)); // Retry on redirect
            }

            if (res.statusCode !== 200) {
                res.resume();
                return resolve({ domain, subdomains: [], error: `HTTP ${res.statusCode}` });
            }

            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => {
                try {
                    const entries = JSON.parse(body);
                    const subdomains = new Set();

                    for (const entry of entries) {
                        if (entry.name_value) {
                            // name_value can contain multiple domains separated by newlines
                            const names = entry.name_value.split('\n');
                            for (let name of names) {
                                name = name.trim().toLowerCase();
                                // Filter out wildcards and invalid entries
                                if (name && !name.startsWith('*') && isValidHostname(name)) {
                                    subdomains.add(name);
                                }
                            }
                        }
                    }

                    resolve({ domain, subdomains: [...subdomains], error: null });
                } catch (e) {
                    resolve({ domain, subdomains: [], error: `JSON parse failed: ${e.message}` });
                }
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ domain, subdomains: [], error: 'TIMEOUT (30s)' });
        });

        req.on('error', (err) => {
            resolve({ domain, subdomains: [], error: err.code || err.message });
        });
    });
}

// ============================================================================
// 3. UTILITIES
// ============================================================================
function isValidHostname(str) {
    // Basic hostname validation: alphanumeric, dots, hyphens
    return /^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$/.test(str);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// 4. CORE ENGINE
// ============================================================================
async function startHarvester() {
    const config = parseArgs();
    const allSubdomains = new Set();
    const startTime = Date.now();

    console.log(`\n  ╔══════════════════════════════════════════════╗`);
    console.log(`  ║   🌐 CRT HARVESTER v1.0                     ║`);
    console.log(`  ╠══════════════════════════════════════════════╣`);
    console.log(`  ║  Root Domains : ${String(config.domains.length).padEnd(29)}║`);
    console.log(`  ║  API Delay    : ${(config.delayMs + 'ms').padEnd(29)}║`);
    console.log(`  ║  Output       : ${(config.outputFile || 'console only').padEnd(29)}║`);
    console.log(`  ╚══════════════════════════════════════════════╝\n`);

    for (let i = 0; i < config.domains.length; i++) {
        const domain = config.domains[i];
        const progress = `[${i + 1}/${config.domains.length}]`;

        process.stdout.write(`  ${progress} Querying crt.sh for *.${domain} ...`);

        const result = await queryCrtSh(domain);

        if (result.error) {
            console.log(` ❌ Error: ${result.error}`);
        } else {
            result.subdomains.forEach(s => allSubdomains.add(s));
            console.log(` ✅ ${result.subdomains.length} unique entries`);
        }

        // Rate limiting — don't hammer crt.sh
        if (i < config.domains.length - 1) {
            await sleep(config.delayMs);
        }
    }

    // Sort alphabetically for clean output
    const sorted = [...allSubdomains].sort();

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\n  ══════════════════════════════════════════════`);
    console.log(`  📊 Total unique subdomains discovered: ${sorted.length}`);
    console.log(`  ⏱️  Time elapsed: ${elapsed}s`);
    console.log(`  ══════════════════════════════════════════════`);

    // Save to file
    if (config.outputFile) {
        fs.writeFileSync(config.outputFile, sorted.join('\n') + '\n');
        console.log(`\n  📄 Saved to: ${config.outputFile}`);
        console.log(`  💡 Next step: Feed this into your scanners:`);
        console.log(`     node scanners/vanguard-dns.js -d google.com -w ${config.outputFile}`);
        console.log(`     node scanners/echo-takeover.js -l ${config.outputFile}`);
        console.log(`     node scanners/specter-cors.js -l ${config.outputFile}`);
    } else {
        // Print first 30 to console as preview
        console.log(`\n  Preview (first 30):`);
        sorted.slice(0, 30).forEach(s => console.log(`    ${s}`));
        if (sorted.length > 30) {
            console.log(`    ... and ${sorted.length - 30} more. Use -o to save all.`);
        }
    }
}

startHarvester();
