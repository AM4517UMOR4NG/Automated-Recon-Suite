/**
 * VANGUARD DNS RESOLVER v1.0
 * --------------------------------------------------------------
 * Alat pengintai Asynchronous untuk memetakan subdomain aktif 
 * melalui teknik DNS Brute-forcing secara lokal.
 * 
 * Mekanisme:
 * Menggabungkan nama domain target dengan daftar subdomain (wordlist).
 * Menggunakan resolver DNS kustom secara asinkron untuk mencocokkan
 * alamat IP (A Record) dan melihat rekaman alias (CNAME Record).
 * 
 * Sangat berguna untuk:
 * 1. Mengidentifikasi mesin/server yang aktif secara diam-diam.
 * 2. Menemukan alias CNAME untuk analisis Subdomain Takeover lebih lanjut.
 */

const fs = require('fs');
const readline = require('readline');
const dns = require('dns').promises;

const CONFIG = {
    TARGET_DOMAIN: 'example.com', // Ganti dengan domain target Anda
    SUBDOMAINS_WORDLIST: './subdomains.txt',
    CONCURRENCY: 100, // Jumlah DNS query paralel
    DNS_SERVERS: ['1.1.1.1', '8.8.8.8'], // Menggunakan DNS Cloudflare & Google untuk menghindari cache lokal
    TIMEOUT_MS: 3000
};

// Konfigurasi Resolver DNS kustom
const resolver = new dns.Resolver();
resolver.setServers(CONFIG.DNS_SERVERS);

async function resolveSubdomain(subdomain) {
    const target = `${subdomain}.${CONFIG.TARGET_DOMAIN}`;
    
    try {
        // Cek CNAME Record terlebih dahulu (penting untuk deteksi Subdomain Takeover)
        let cnames = [];
        try {
            cnames = await resolver.resolveCname(target);
        } catch (e) {
            // Abaikan jika tidak ada record CNAME
        }

        // Cek A Record (IP Address)
        const addresses = await resolver.resolve4(target);
        
        if (addresses && addresses.length > 0) {
            console.log(`\n[+] Active Subdomain: ${target}`);
            console.log(`    └─ IP Address(es) : ${addresses.join(', ')}`);
            if (cnames.length > 0) {
                console.log(`    └─ CNAME Alias    : ${cnames.join(', ')}`);
            }
        }
    } catch (err) {
        // Gagal resolve berarti subdomain tidak aktif/tidak ada
    }
}

async function startDNSResolver() {
    console.log(`=========================================`);
    console.log(`🚀 VANGUARD DNS RESOLVER INITIALIZED`);
    console.log(`🎯 Target Domain : ${CONFIG.TARGET_DOMAIN}`);
    console.log(`⚙️  DNS Servers   : ${CONFIG.DNS_SERVERS.join(', ')}`);
    console.log(`⚡ Concurrency   : ${CONFIG.CONCURRENCY} parallel queries`);
    console.log(`=========================================\n`);

    if (!fs.existsSync(CONFIG.SUBDOMAINS_WORDLIST)) {
        console.error(`[-] File ${CONFIG.SUBDOMAINS_WORDLIST} tidak ditemukan.`);
        console.log(`[!] Silakan buat file subdomains.txt yang berisi daftar kata (contoh: dev, staging, api, admin).`);
        return;
    }

    const rl = readline.createInterface({ input: fs.createReadStream(CONFIG.SUBDOMAINS_WORDLIST) });
    let activeQueries = 0;
    let queue = [];
    let isEOF = false;
    let totalProcessed = 0;

    return new Promise((resolve) => {
        const processQueue = async () => {
            while (queue.length > 0 && activeQueries < CONFIG.CONCURRENCY) {
                const sub = queue.shift();
                activeQueries++;
                
                resolveSubdomain(sub).then(() => {
                    activeQueries--;
                    totalProcessed++;
                    
                    if (totalProcessed % 100 === 0) {
                        process.stdout.write(`\r[*] Processed: ${totalProcessed} subdomains...`);
                    }
                    
                    processQueue();
                });
            }

            if (isEOF && activeQueries === 0 && queue.length === 0) {
                console.log(`\n\n✅ DNS Resolution Completed. Total queried: ${totalProcessed}`);
                resolve();
            }
        };

        rl.on('line', (line) => {
            if (line.trim() !== '') {
                queue.push(line.trim());
                if (activeQueries < CONFIG.CONCURRENCY) {
                    processQueue();
                }
            }
        });

        rl.on('close', () => {
            isEOF = true;
            processQueue();
        });
    });
}

startDNSResolver();
