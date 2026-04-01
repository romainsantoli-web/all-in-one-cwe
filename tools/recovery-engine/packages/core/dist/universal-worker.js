/**
 * Universal Worker Thread
 *
 * Generic worker that handles ANY format via the crackers registry.
 * Each worker thread runs concurrent password attempts using the
 * appropriate cracker module based on the format type.
 */
import { parentPort, workerData } from 'node:worker_threads';
// Dynamic import to avoid circular dependency at build time
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let tryPasswordFn;
const crackersPkg = '@metamask-recovery/crackers';
const mod = await import(crackersPkg);
tryPasswordFn = mod.tryPassword;
const { params } = workerData;
/**
 * VECTORIZED: Fire ALL passwords in this batch concurrently.
 * Each KDF call (PBKDF2/scrypt/Argon2) goes to a different libuv thread.
 */
async function processBatch(passwords) {
    const promises = passwords.map(async (pw) => {
        try {
            const result = await tryPasswordFn(pw, params);
            return result.success ? { password: pw, raw: result.raw } : null;
        }
        catch {
            return null;
        }
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
//# sourceMappingURL=universal-worker.js.map