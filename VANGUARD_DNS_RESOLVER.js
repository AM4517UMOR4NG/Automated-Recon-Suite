/**
 * VANGUARD DNS RESOLVER v2.0 — Asynchronous Subdomain Enumeration Engine
 * ========================================================================
 * Maps active subdomains via high-speed DNS brute-forcing.
 *
 * Features:
 *  - CLI argument parsing
 *  - Wildcard DNS detection (avoids false positives from catch-all records)
 *  - Multi-record resolution (A, AAAA, CNAME, MX, TXT)
 *  - Custom DNS resolver selection (bypass local cache)
 *  - Controlled concurrency
 *  - JSON + Console dual output
 *  - Progress tracking with req/s metrics
 *
 * Usage:
 *   node VANGUARD_DNS_RESOLVER.js -d example.com -w subdomains.txt
 *   node VANGUARD_DNS_RESOLVER.js -d example.com -w subdomains.txt -c 200 -o dns_results.json
 */

const fs = require('fs');
const readline = require('readline');
const dns = require('dns').promises;

// ============================================================================
// 1. CLI ARGUMENT PARSER
// ============================================================================
function parseArgs() {
    const args = process.argv.slice(2);
    const config = {
        targetDomain: '',
        wordlistPath: './subdomains.txt',
        concurrency: 100,
        dnsServers: ['1.1.1.1', '8.8.8.8', '9.9.9.9'],
        outputFile: '',
        resolveAll: false, // Also resolve AAAA, MX, TXT
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '-d': case '--domain':      config.targetDomain = args[++i]; break;
            case '-w': case '--wordlist':    config.wordlistPath = args[++i]; break;
            case '-c': case '--concurrency': config.concurrency = parseInt(args[++i], 10); break;
            case '-o': case '--output':      config.outputFile = args[++i]; break;
            case '-a': case '--all-records': config.resolveAll = true; break;
            case '--dns':                    config.dnsServers = args[++i].split(','); break;
            case '-h': case '--help':        printUsage(); process.exit(0);
            default: break;
        }
    }

    if (!config.targetDomain) {
        printUsage();
        process.exit(1);
    }
    return config;
}

function printUsage() {
    console.log(`
  VANGUARD DNS RESOLVER v2.0

  Usage:
    node VANGUARD_DNS_RESOLVER.js -d <target_domain> [options]

  Required:
    -d, --domain       Target domain to enumerate (e.g., example.com)

  Optional:
    -w, --wordlist     Path to subdomain wordlist (default: ./subdomains.txt)
    -c, --concurrency  Parallel DNS queries (default: 100)
    -o, --output       Save results to JSON file
    -a, --all-records  Also resolve AAAA, MX, TXT records
    --dns              Custom DNS servers, comma-separated (default: 1.1.1.1,8.8.8.8,9.9.9.9)
    -h, --help         Show this help message

  Examples:
    node VANGUARD_DNS_RESOLVER.js -d target.com -w subdomains.txt
    node VANGUARD_DNS_RESOLVER.js -d target.com -w big_list.txt -c 200 -a -o results.json
`);
}

// ============================================================================
// 2. DNS ENGINE — Custom resolver with multi-record support
// ============================================================================
const resolver = new dns.Resolver();

async function resolveRecord(fqdn, type) {
    try {
        switch (type) {
            case 'A':     return await resolver.resolve4(fqdn);
            case 'AAAA':  return await resolver.resolve6(fqdn);
            case 'CNAME': return await resolver.resolveCname(fqdn);
            case 'MX':    return (await resolver.resolveMx(fqdn)).map(r => `${r.exchange}:${r.priority}`);
            case 'TXT':   return (await resolver.resolveTxt(fqdn)).map(r => r.join(''));
            default:      return [];
        }
    } catch {
        return [];
    }
}

async function resolveSubdomain(subdomain, targetDomain, config, wildcardIPs) {
    const fqdn = `${subdomain}.${targetDomain}`;

    // Primary: Resolve A record
    const ipv4 = await resolveRecord(fqdn, 'A');
    if (ipv4.length === 0) return null;

    // Wildcard filter: If all IPs match wildcard, it's a false positive
    if (wildcardIPs.size > 0) {
        const allWildcard = ipv4.every(ip => wildcardIPs.has(ip));
        if (allWildcard) return null;
    }

    const result = {
        subdomain: fqdn,
        A: ipv4,
    };

    // CNAME (always useful for takeover analysis)
    const cnames = await resolveRecord(fqdn, 'CNAME');
    if (cnames.length > 0) result.CNAME = cnames;

    // Extended records (if requested)
    if (config.resolveAll) {
        const ipv6 = await resolveRecord(fqdn, 'AAAA');
        if (ipv6.length > 0) result.AAAA = ipv6;

        const mx = await resolveRecord(fqdn, 'MX');
        if (mx.length > 0) result.MX = mx;

        const txt = await resolveRecord(fqdn, 'TXT');
        if (txt.length > 0) result.TXT = txt;
    }

    return result;
}

// ============================================================================
// 3. WILDCARD DETECTION — Prevents false positives
// ============================================================================
async function detectWildcard(targetDomain) {
    const randomSubs = [
        `zzz-nonexistent-${Date.now()}-aaa`,
        `xxx-ghost-${Date.now()}-bbb`,
        `qqq-phantom-${Date.now()}-ccc`,
    ];

    const wildcardIPs = new Set();

    for (const sub of randomSubs) {
        const ips = await resolveRecord(`${sub}.${targetDomain}`, 'A');
        ips.forEach(ip => wildcardIPs.add(ip));
    }

    return wildcardIPs;
}

// ============================================================================
// 4. CORE ENGINE
// ============================================================================
async function startResolver() {
    const config = parseArgs();
    resolver.setServers(config.dnsServers);

    const results = [];
    const startTime = Date.now();

    console.log(`\n  ╔══════════════════════════════════════════════╗`);
    console.log(`  ║   ⚡ VANGUARD DNS RESOLVER v2.0              ║`);
    console.log(`  ╠══════════════════════════════════════════════╣`);
    console.log(`  ║  Target      : ${config.targetDomain.padEnd(29)}║`);
    console.log(`  ║  Wordlist    : ${config.wordlistPath.padEnd(29)}║`);
    console.log(`  ║  Concurrency : ${String(config.concurrency).padEnd(29)}║`);
    console.log(`  ║  DNS Servers : ${config.dnsServers.join(', ').padEnd(29)}║`);
    console.log(`  ╚══════════════════════════════════════════════╝\n`);

    if (!fs.existsSync(config.wordlistPath)) {
        console.error(`  [!] Wordlist not found: ${config.wordlistPath}`);
        process.exit(1);
    }

    // Step 1: Wildcard detection
    console.log(`  [*] Detecting wildcard DNS records...`);
    const wildcardIPs = await detectWildcard(config.targetDomain);
    if (wildcardIPs.size > 0) {
        console.log(`  [!] Wildcard DNS detected: ${[...wildcardIPs].join(', ')}`);
        console.log(`  [*] These IPs will be filtered from results to avoid false positives.\n`);
    } else {
        console.log(`  [✓] No wildcard DNS detected. Proceeding with clean resolution.\n`);
    }

    // Step 2: Stream wordlist and resolve
    const rl = readline.createInterface({ input: fs.createReadStream(config.wordlistPath), crlfDelay: Infinity });
    let activeQueries = 0;
    let isEOF = false;
    let queue = [];
    let totalProcessed = 0;
    let totalFound = 0;

    return new Promise((resolve) => {
        const processQueue = () => {
            while (queue.length > 0 && activeQueries < config.concurrency) {
                const sub = queue.shift();
                activeQueries++;

                resolveSubdomain(sub, config.targetDomain, config, wildcardIPs).then((result) => {
                    if (result) {
                        totalFound++;
                        results.push(result);

                        console.log(`  [+] ${result.subdomain}`);
                        console.log(`      └─ A     : ${result.A.join(', ')}`);
                        if (result.CNAME) console.log(`      └─ CNAME : ${result.CNAME.join(', ')}`);
                        if (result.AAAA)  console.log(`      └─ AAAA  : ${result.AAAA.join(', ')}`);
                        if (result.MX)    console.log(`      └─ MX    : ${result.MX.join(', ')}`);
                        if (result.TXT)   console.log(`      └─ TXT   : ${result.TXT.join(' | ').substring(0, 80)}`);
                    }

                    activeQueries--;
                    totalProcessed++;

                    if (totalProcessed % 200 === 0) {
                        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                        const qps = (totalProcessed / (elapsed || 1)).toFixed(0);
                        process.stdout.write(`\r  [*] ${totalProcessed} queried | ${totalFound} found | ${qps} q/s | ${elapsed}s`);
                    }

                    processQueue();
                });
            }

            if (isEOF && activeQueries === 0 && queue.length === 0) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const qps = (totalProcessed / (elapsed || 1)).toFixed(0);
                console.log(`\n\n  ✅ Resolution complete: ${totalProcessed} queried | ${totalFound} active subdomains | ${qps} q/s | ${elapsed}s`);

                if (config.outputFile && results.length > 0) {
                    fs.writeFileSync(config.outputFile, JSON.stringify(results, null, 2));
                    console.log(`  📄 Results saved to: ${config.outputFile}`);
                }

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

startResolver();
