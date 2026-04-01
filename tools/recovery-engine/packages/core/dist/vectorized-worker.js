/**
 * V2 Vectorized Worker Thread
 *
 * Each worker thread has its own libuv thread pool.
 * Inside each worker, we fire CONCURRENT_PER_WORKER parallel PBKDF2 calls.
 * This means: 10 workers × 8 concurrent = 80 parallel PBKDF2 operations.
 *
 * The libuv pool is sized via UV_THREADPOOL_SIZE (set by parent).
 */
import { parentPort, workerData } from 'node:worker_threads';
import crypto from 'node:crypto';
// Pre-parse vault buffers once per worker lifetime
const vault = workerData.vault;
const salt = Buffer.from(vault.salt, 'base64');
const iv = Buffer.from(vault.iv, 'base64');
const ciphertext = Buffer.from(vault.data, 'base64');
const authTagLength = 16;
const encrypted = ciphertext.subarray(0, ciphertext.length - authTagLength);
const authTag = ciphertext.subarray(ciphertext.length - authTagLength);
const iterations = vault.iterations;
function tryPassword(password) {
    if (password.length < 8)
        return Promise.resolve({ success: false });
    return new Promise((resolve) => {
        crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (err, key) => {
            if (err) {
                resolve({ success: false });
                return;
            }
            try {
                const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
                decipher.setAuthTag(authTag);
                const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
                resolve({ success: true, raw: decrypted.toString('utf-8') });
            }
            catch {
                resolve({ success: false });
            }
        });
    });
}
/**
 * VECTORIZED: Fire ALL passwords in this batch concurrently.
 * Each PBKDF2 call goes to a different libuv thread.
 */
async function processBatch(passwords) {
    // Fire all concurrently
    const promises = passwords.map(async (pw) => {
        const r = await tryPassword(pw);
        return r.success ? { password: pw, raw: r.raw } : null;
    });
    const results = await Promise.all(promises);
    for (const r of results) {
        if (r) {
            return { type: 'result', found: true, password: r.password, raw: r.raw, tried: passwords.length };
        }
    }
    return { type: 'result', found: false, tried: passwords.length };
}
parentPort?.on('message', async (msg) => {
    if (msg.type !== 'crack')
        return;
    const response = await processBatch(msg.passwords);
    parentPort?.postMessage(response);
});
//# sourceMappingURL=vectorized-worker.js.map