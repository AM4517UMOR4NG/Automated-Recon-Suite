/**
 * GHOST ENGINE v1.0 - Advanced Asynchronous Vulnerability Scanner
 * --------------------------------------------------------------
 * Ini adalah kerangka dasar (Engine) berskala industri.
 * Meskipun ditulis dalam Node.js, ia menggunakan arsitektur yang 
 * serupa dengan tools Go-based (seperti ffuf atau Nuclei):
 * 
 * 1. Connection Pooling: Menggunakan ulang koneksi TCP (Keep-Alive) agar secepat kilat.
 * 2. Concurrency Control: Membatasi eksekusi asinkron agar RAM tidak bocor/crash.
 * 3. Smart Matchers: Tidak hanya mengecek HTTP 200, tapi menganalisis isi body (Regex).
 * 4. Stream Reading: Membaca wordlist tanpa memuat seluruh file ke RAM.
 */

const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');

// ============================================================================
// 1. ENGINE CONFIGURATION (Konfigurasi Mesin)
// ============================================================================
const CONFIG = {
    TARGET_URL: 'https://www.vidio.com', // Ganti dengan target Anda
    WORDLIST_PATH: './wordlist.txt',   // File berisi daftar path yang akan di-fuzz
    CONCURRENCY: 50,                   // Jumlah request paralel (Makin tinggi makin cepat, tapi rawan blokir WAF)
    TIMEOUT_MS: 5000,                  // Waktu maksimal menunggu respons
    MAX_RETRIES: 2,
    USER_AGENTS: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'GhostEngine-Security-Scanner/1.0'
    ]
};

// ============================================================================
// 2. MATCHERS (Mata Analisis - Seperti Nuclei)
// ============================================================================
// Kita mendefinisikan apa yang membuat sebuah temuan dianggap "Vulnerable"
const MATCHERS = [
    {
        name: "Config File Exposed",
        statusCodes: [200],
        // Regex untuk mendeteksi isi file .env atau config
        bodyRegex: /(DB_PASSWORD|AWS_SECRET_ACCESS_KEY|JWT_SECRET|API_KEY)\s*=/i, 
        severity: "CRITICAL"
    },
    {
        name: "Admin Panel Found",
        statusCodes: [200, 302],
        bodyRegex: /login|admin dashboard|sign in/i,
        severity: "MEDIUM"
    },
    {
        name: "Directory Listing / Internal Server Error",
        statusCodes: [500, 200],
        bodyRegex: /Index of \/|stack trace|mysql_query/i,
        severity: "HIGH"
    }
];

// Connection pooling untuk performa ekstrem (menghindari TCP handshake berulang)
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: CONFIG.CONCURRENCY });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: CONFIG.CONCURRENCY, rejectUnauthorized: false }); // rejectUnauthorized: false untuk bypass error SSL/TLS target

// ============================================================================
// 3. CORE ENGINE (Sistem Antrean dan Eksekusi)
// ============================================================================

// Fungsi untuk mengirim HTTP Request mentah
async function makeRequest(path, retries = 0) {
    const fullUrl = `${CONFIG.TARGET_URL}/${path.replace(/^\//, '')}`;
    const isHttps = fullUrl.startsWith('https');
    const agent = isHttps ? httpsAgent : httpAgent;
    const client = isHttps ? https : http;

    const randomUA = CONFIG.USER_AGENTS[Math.floor(Math.random() * CONFIG.USER_AGENTS.length)];

    return new Promise((resolve) => {
        const req = client.get(fullUrl, {
            agent: agent,
            headers: {
                'User-Agent': randomUA,
                'Accept': '*/*',
                'Connection': 'keep-alive'
            },
            timeout: CONFIG.TIMEOUT_MS
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => resolve({ url: fullUrl, status: res.statusCode, body: body, error: null }));
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ url: fullUrl, status: 0, body: '', error: 'TIMEOUT' });
        });

        req.on('error', (err) => {
            if (retries < CONFIG.MAX_RETRIES) {
                // Retry logic jika koneksi terputus
                resolve(makeRequest(path, retries + 1));
            } else {
                resolve({ url: fullUrl, status: 0, body: '', error: err.message });
            }
        });
    });
}

// Analisator Respons (Mencocokkan respons dengan MATCHERS)
function analyzeResponse(response) {
    if (response.error || response.status === 404 || response.status === 403) return; // Abaikan error umum dan Not Found

    for (const matcher of MATCHERS) {
        if (matcher.statusCodes.includes(response.status)) {
            if (matcher.bodyRegex.test(response.body)) {
                console.log(`\n[🔥 VULNERABILITY FOUND!]`);
                console.log(`[!] Type     : ${matcher.name}`);
                console.log(`[!] Severity : ${matcher.severity}`);
                console.log(`[!] URL      : ${response.url}`);
                console.log(`[!] Status   : ${response.status}`);
                console.log(`[!] Body Size: ${response.body.length} bytes`);
                return;
            }
        }
    }
    
    // Fallback: Jika status 200 tapi tidak masuk regex (mungkin file menarik)
    if (response.status === 200) {
         console.log(`[+] Valid Path (200 OK): ${response.url} (Size: ${response.body.length}b)`);
    }
}

// Sistem Concurrency (Antrean Paralel)
async function startEngine() {
    console.log(`=========================================`);
    console.log(`🚀 GHOST ENGINE v1.0 INITIALIZED`);
    console.log(`🎯 Target      : ${CONFIG.TARGET_URL}`);
    console.log(`⚙️  Concurrency : ${CONFIG.CONCURRENCY} parallel requests`);
    console.log(`=========================================\n`);

    if (!fs.existsSync(CONFIG.WORDLIST_PATH)) {
        console.error(`[-] File wordlist tidak ditemukan di: ${CONFIG.WORDLIST_PATH}`);
        console.log(`[!] Buat file wordlist.txt terlebih dahulu. Contoh isinya:\n.env\napi/v1/users\nadmin\nconfig.php`);
        return;
    }

    const fileStream = fs.createReadStream(CONFIG.WORDLIST_PATH);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    let activeRequests = 0;
    let isEOF = false;
    let pathsQueue = [];
    
    let totalProcessed = 0;

    return new Promise((resolve) => {
        // Fungsi untuk mengambil antrean dan mengeksekusi
        const processQueue = async () => {
            while (pathsQueue.length > 0 && activeRequests < CONFIG.CONCURRENCY) {
                const path = pathsQueue.shift();
                activeRequests++;
                
                makeRequest(path).then((response) => {
                    analyzeResponse(response);
                    activeRequests--;
                    totalProcessed++;
                    
                    if (totalProcessed % 100 === 0) {
                        process.stdout.write(`\r[*] Progress: ${totalProcessed} requests processed...`);
                    }
                    
                    processQueue(); // Panggil ulang saat selesai
                });
            }

            if (isEOF && activeRequests === 0 && pathsQueue.length === 0) {
                console.log(`\n\n✅ Scan Completed. Total requests: ${totalProcessed}`);
                resolve();
            }
        };

        // Membaca file baris demi baris secara asinkron
        rl.on('line', (line) => {
            if (line.trim() !== '') {
                pathsQueue.push(line.trim());
                if (activeRequests < CONFIG.CONCURRENCY) {
                    processQueue();
                }
            }
        });

        rl.on('close', () => {
            isEOF = true;
            processQueue(); // Pastikan antrean terakhir diproses
        });
    });
}

// ============================================================================
// 4. EKSEKUSI
// ============================================================================
startEngine();
