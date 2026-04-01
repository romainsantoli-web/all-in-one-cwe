/**
 * Vectorized PBKDF2 Decryptor — V2 High-Performance Engine
 *
 * Key optimizations over V1:
 * 1. Concurrent async PBKDF2: fires N parallel crypto.pbkdf2() calls per worker
 * 2. Worker threads: distributes across all CPU cores (10 on Apple M4)
 * 3. UV_THREADPOOL_SIZE maximized: more libuv threads for async crypto ops
 * 4. Pre-computed salt/iv buffers: avoid re-parsing base64 per attempt
 * 5. Batch pipelining: next batch prepared while current one runs
 * 6. Zero-copy buffer reuse where possible
 *
 * Expected speedup: 8-15x over single-threaded V1
 */
import crypto from 'node:crypto';
// Pre-parsed vault buffers (computed once, reused for every attempt)
let cachedSalt = null;
let cachedIv = null;
let cachedCiphertext = null;
let cachedEncrypted = null;
let cachedAuthTag = null;
let cachedIterations = 0;
function initVaultBuffers(vault) {
    if (cachedIterations === vault.iterations && cachedSalt)
        return;
    cachedSalt = Buffer.from(vault.salt, 'base64');
    cachedIv = Buffer.from(vault.iv, 'base64');
    cachedCiphertext = Buffer.from(vault.data, 'base64');
    const authTagLength = 16;
    cachedEncrypted = cachedCiphertext.subarray(0, cachedCiphertext.length - authTagLength);
    cachedAuthTag = cachedCiphertext.subarray(cachedCiphertext.length - authTagLength);
    cachedIterations = vault.iterations;
}
/**
 * Try a single password — async, non-blocking.
 * Uses pre-cached buffers to avoid repeated base64 decoding.
 */
function tryPasswordAsync(password) {
    if (password.length < 8)
        return Promise.resolve({ success: false });
    return new Promise((resolve) => {
        crypto.pbkdf2(password, cachedSalt, cachedIterations, 32, 'sha256', (err, key) => {
            if (err) {
                resolve({ success: false });
                return;
            }
            try {
                const decipher = crypto.createDecipheriv('aes-256-gcm', key, cachedIv);
                decipher.setAuthTag(cachedAuthTag);
                const decrypted = Buffer.concat([
                    decipher.update(cachedEncrypted),
                    decipher.final(),
                ]);
                resolve({ success: true, raw: decrypted.toString('utf-8') });
            }
            catch {
                resolve({ success: false });
            }
        });
    });
}
/**
 * VECTORIZED BATCH: Try N passwords CONCURRENTLY.
 *
 * This is the core speedup — fires all PBKDF2 calls at once.
 * Node's crypto.pbkdf2 is async and runs on libuv's thread pool.
 * With UV_THREADPOOL_SIZE set high, all calls run in parallel on separate OS threads.
 */
async function tryBatchConcurrent(passwords) {
    const promises = passwords.map(async (password) => {
        const result = await tryPasswordAsync(password);
        if (result.success) {
            return { found: true, password, raw: result.raw };
        }
        return null;
    });
    // Use Promise.all for maximum concurrency — all PBKDF2 calls fire simultaneously
    const results = await Promise.all(promises);
    for (const r of results) {
        if (r?.found) {
            return { found: true, password: r.password, raw: r.raw, tried: passwords.length };
        }
    }
    return { found: false, tried: passwords.length };
}
export { initVaultBuffers, tryPasswordAsync, tryBatchConcurrent };
//# sourceMappingURL=vectorized-decryptor.js.map