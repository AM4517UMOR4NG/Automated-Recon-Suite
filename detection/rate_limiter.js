/**
 * Node.js Rate Limiter Middleware (Token Bucket Algorithm)
 * --------------------------------------------------------------
 * A clean, robust, and in-memory rate limiting mechanism.
 * 
 * Why this is advanced yet clean (No Over-engineering):
 * 1. Zero external dependencies (No Redis or external DB required).
 * 2. Automatic Memory Garbage Collection (Prevents memory leaks from stale IPs).
 * 3. Fast-Fail Mechanism: Rejects requests at the entry point to preserve resources.
 */

const ipBuckets = new Map();

const LIMITS = {
    MAX_TOKENS: 20,       // Max burst requests allowed per IP
    REFILL_RATE_MS: 1000, // Interval for token replenishment (1 second)
    REFILL_AMOUNT: 2      // Tokens to restore per interval
};

// Periodic Cleanup to prevent memory leaks from inactive IPs
setInterval(() => {
    const now = Date.now();
    for (const [ip, bucket] of ipBuckets.entries()) {
        if (now - bucket.lastRefilled > 300000) { // Cleanup if inactive for 5+ minutes
            ipBuckets.delete(ip);
        }
    }
}, 60000); // Run cleanup every 1 minute

function rateLimiter(req, res, next) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = Date.now();

    if (!ipBuckets.has(ip)) {
        ipBuckets.set(ip, {
            tokens: LIMITS.MAX_TOKENS,
            lastRefilled: now
        });
    }

    const bucket = ipBuckets.get(ip);

    // Calculate elapsed time and replenish tokens
    const elapsedTime = now - bucket.lastRefilled;
    if (elapsedTime > LIMITS.REFILL_RATE_MS) {
        const refillIntervals = Math.floor(elapsedTime / LIMITS.REFILL_RATE_MS);
        const tokensToAdd = refillIntervals * LIMITS.REFILL_AMOUNT;
        
        bucket.tokens = Math.min(LIMITS.MAX_TOKENS, bucket.tokens + tokensToAdd);
        bucket.lastRefilled = now;
    }

    // Evaluate token availability
    if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        
        // Express.js middleware style: If 'next' function is provided, call it.
        // Otherwise, fall back to standard HTTP writing.
        if (typeof next === 'function') {
            next();
        } else {
            return true;
        }
    } else {
        if (res && typeof res.writeHead === 'function') {
            res.writeHead(429, {
                'Content-Type': 'application/json',
                'Retry-After': Math.ceil(LIMITS.REFILL_RATE_MS / 1000)
            });
            res.end(JSON.stringify({ 
                error: "Too many requests. Temporary rate limit exceeded." 
            }));
        }
        return false;
    }
}

module.exports = rateLimiter;
