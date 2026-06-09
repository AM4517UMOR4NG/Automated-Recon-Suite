/**
 * SPECTER CORS SCANNER v1.0
 * --------------------------------------------------------------
 * Alat pemindai Asynchronous untuk mendeteksi kerentanan 
 * Cross-Origin Resource Sharing (CORS) Misconfiguration.
 * 
 * Mekanisme:
 * Mengirim request dengan header 'Origin: https://evil.com'
 * Jika target memantulkan origin tersebut dan memberikan izin
 * akses kredensial (Access-Control-Allow-Credentials: true),
 * maka target rentan terhadap pencurian data lintas domain.
 */

const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');

const CONFIG = {
    DOMAIN_LIST: './domains.txt',
    EVIL_ORIGIN: 'https://evil-hacker.com',
    CONCURRENCY: 30,
    TIMEOUT_MS: 5000
};

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: CONFIG.CONCURRENCY });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: CONFIG.CONCURRENCY, rejectUnauthorized: false });

async function checkCORS(domain) {
    let url = domain.startsWith('http') ? domain : `https://${domain}`;
    const client = url.startsWith('https') ? https : http;
    const agent = url.startsWith('https') ? httpsAgent : httpAgent;

    return new Promise((resolve) => {
        const req = client.get(url, {
            agent: agent,
            headers: {
                'User-Agent': 'SpecterCORS-Scanner/1.0',
                'Origin': CONFIG.EVIL_ORIGIN,
                'Connection': 'keep-alive'
            },
            timeout: CONFIG.TIMEOUT_MS
        }, (res) => {
            const allowOrigin = res.headers['access-control-allow-origin'];
            const allowCredentials = res.headers['access-control-allow-credentials'];

            if (allowOrigin === CONFIG.EVIL_ORIGIN || allowOrigin === 'null') {
                if (allowCredentials === 'true') {
                    console.log(`\n[🔥 CRITICAL CORS VULNERABILITY!]`);
                    console.log(`[!] Target : ${url}`);
                    console.log(`[!] ACAO   : ${allowOrigin}`);
                    console.log(`[!] ACAC   : ${allowCredentials}`);
                } else {
                    console.log(`\n[⚠️ HIGH CORS VULNERABILITY (No Credentials)]`);
                    console.log(`[!] Target : ${url}`);
                    console.log(`[!] ACAO   : ${allowOrigin}`);
                }
            }
            resolve();
        });

        req.on('timeout', () => { req.destroy(); resolve(); });
        req.on('error', () => { resolve(); });
    });
}

async function startScanner() {
    console.log(`🚀 SPECTER CORS SCANNER INITIALIZED`);
    console.log(`⚙️  Injecting Origin: ${CONFIG.EVIL_ORIGIN}\n`);

    if (!fs.existsSync(CONFIG.DOMAIN_LIST)) return console.error(`[-] File ${CONFIG.DOMAIN_LIST} tidak ditemukan.`);

    const rl = readline.createInterface({ input: fs.createReadStream(CONFIG.DOMAIN_LIST) });
    let activeRequests = 0;
    let pathsQueue = [];

    return new Promise((resolve) => {
        const processQueue = async () => {
            while (pathsQueue.length > 0 && activeRequests < CONFIG.CONCURRENCY) {
                activeRequests++;
                checkCORS(pathsQueue.shift()).then(() => {
                    activeRequests--;
                    processQueue();
                });
            }
            if (activeRequests === 0 && pathsQueue.length === 0) resolve();
        };

        rl.on('line', (line) => {
            if (line.trim() !== '') {
                pathsQueue.push(line.trim());
                if (activeRequests < CONFIG.CONCURRENCY) processQueue();
            }
        });
        rl.on('close', processQueue);
    });
}

startScanner().then(() => console.log('\n✅ Specter CORS Scan Completed.'));
