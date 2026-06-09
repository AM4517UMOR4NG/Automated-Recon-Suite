/**
 * ECHO TAKEOVER SCANNER v1.0
 * --------------------------------------------------------------
 * Alat pemindai Asynchronous untuk mendeteksi kerentanan
 * Subdomain Takeover.
 * 
 * Mekanisme:
 * Mengecek daftar subdomain yang mengarah (CNAME) ke layanan cloud
 * pihak ketiga (S3, GitHub Pages, Heroku, dll) namun layanannya
 * sudah dihapus/tidak aktif. Jika "Fingerprint" error khas layanan
 * tersebut terdeteksi di body response, subdomain rentan diambil alih.
 */

const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');

const CONFIG = {
    DOMAIN_LIST: './domains.txt',
    CONCURRENCY: 30,
    TIMEOUT_MS: 5000
};

// Pola (Fingerprint) error dari cloud provider
const FINGERPRINTS = [
    { provider: 'AWS S3', regex: /The specified bucket does not exist/i },
    { provider: 'GitHub Pages', regex: /There isn't a GitHub Pages site here/i },
    { provider: 'Heroku', regex: /No such app/i },
    { provider: 'Tumblr', regex: /Whatever you were looking for doesn't currently exist at this address/i },
    { provider: 'Pantheon', regex: /The lack of a trailing slash in the URL/i },
    { provider: 'WordPress', regex: /Do you want to register /i }
];

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: CONFIG.CONCURRENCY });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: CONFIG.CONCURRENCY, rejectUnauthorized: false });

async function checkTakeover(domain) {
    let url = domain.startsWith('http') ? domain : `https://${domain}`;
    const client = url.startsWith('https') ? https : http;
    const agent = url.startsWith('https') ? httpsAgent : httpAgent;

    return new Promise((resolve) => {
        const req = client.get(url, {
            agent: agent,
            headers: { 'User-Agent': 'EchoTakeover-Scanner/1.0', 'Connection': 'keep-alive' },
            timeout: CONFIG.TIMEOUT_MS
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                for (let fp of FINGERPRINTS) {
                    if (fp.regex.test(body)) {
                        console.log(`\n[☠️ CRITICAL SUBDOMAIN TAKEOVER!]`);
                        console.log(`[!] Target   : ${url}`);
                        console.log(`[!] Provider : ${fp.provider}`);
                    }
                }
                resolve();
            });
        });

        req.on('timeout', () => { req.destroy(); resolve(); });
        req.on('error', () => { resolve(); });
    });
}

async function startScanner() {
    console.log(`🚀 ECHO TAKEOVER SCANNER INITIALIZED\n`);

    if (!fs.existsSync(CONFIG.DOMAIN_LIST)) return console.error(`[-] File ${CONFIG.DOMAIN_LIST} tidak ditemukan.`);

    const rl = readline.createInterface({ input: fs.createReadStream(CONFIG.DOMAIN_LIST) });
    let activeRequests = 0;
    let pathsQueue = [];

    return new Promise((resolve) => {
        const processQueue = async () => {
            while (pathsQueue.length > 0 && activeRequests < CONFIG.CONCURRENCY) {
                activeRequests++;
                checkTakeover(pathsQueue.shift()).then(() => {
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

startScanner().then(() => console.log('\n✅ Echo Takeover Scan Completed.'));
