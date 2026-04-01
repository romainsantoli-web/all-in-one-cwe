/**
 * Worker Thread — Runs inside a Node.js worker_thread.
 *
 * Receives batches of password candidates, attempts decryption,
 * and reports results back to the main thread.
 */
import { parentPort } from 'node:worker_threads';
import crypto from 'node:crypto';
function base64ToBuffer(b64) {
    return Buffer.from(b64, 'base64');
}
async function tryPassword(password, vault) {
    const salt = base64ToBuffer(vault.salt);
    const iv = base64ToBuffer(vault.iv);
    const ciphertext = base64ToBuffer(vault.data);
    const key = await new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, vault.iterations, 32, 'sha256', (err, derivedKey) => {
            if (err)
                reject(err);
            else
                resolve(derivedKey);
        });
    });
    const authTagLength = 16;
    const encrypted = ciphertext.subarray(0, ciphertext.length - authTagLength);
    const authTag = ciphertext.subarray(ciphertext.length - authTagLength);
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return { success: true, decrypted: decrypted.toString('utf-8') };
    }
    catch {
        return { success: false };
    }
}
function parseDecryptedContent(raw) {
    try {
        const keyrings = JSON.parse(raw);
        const hdKeyring = Array.isArray(keyrings)
            ? keyrings.find((k) => k.type === 'HD Key Tree')
            : null;
        if (hdKeyring?.data) {
            let mnemonic;
            if (typeof hdKeyring.data.mnemonic === 'string') {
                mnemonic = hdKeyring.data.mnemonic;
            }
            else if (Array.isArray(hdKeyring.data.mnemonic)) {
                mnemonic = Buffer.from(hdKeyring.data.mnemonic).toString('utf-8');
            }
            else if (hdKeyring.data.mnemonic?.type === 'Buffer') {
                mnemonic = Buffer.from(hdKeyring.data.mnemonic.data).toString('utf-8');
            }
            else {
                mnemonic = String(hdKeyring.data.mnemonic);
            }
            return {
                mnemonic: mnemonic.trim(),
                numberOfAccounts: hdKeyring.data.numberOfAccounts || 1,
                hdPath: hdKeyring.data.hdPath || "m/44'/60'/0'/0",
                raw,
            };
        }
    }
    catch {
        // fallthrough
    }
    return { mnemonic: '[parse error]', numberOfAccounts: 0, hdPath: '', raw };
}
// ---------- Main loop ----------
parentPort?.on('message', async (msg) => {
    if (msg.type !== 'crack')
        return;
    let tried = 0;
    for (const password of msg.passwords) {
        if (password.length < 8) {
            tried++;
            continue;
        }
        tried++;
        const result = await tryPassword(password, msg.vault);
        if (result.success && result.decrypted) {
            const response = {
                type: 'result',
                found: true,
                password,
                vault: parseDecryptedContent(result.decrypted),
                tried,
            };
            parentPort?.postMessage(response);
            return;
        }
    }
    const response = {
        type: 'result',
        found: false,
        tried,
    };
    parentPort?.postMessage(response);
});
//# sourceMappingURL=worker-thread.js.map