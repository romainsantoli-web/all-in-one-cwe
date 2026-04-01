/**
 * Vault Decryptor — Attempts to decrypt a MetaMask vault with a given password.
 *
 * Pipeline: password → PBKDF2-SHA256(salt, iterations) → AES-256-GCM decrypt
 *
 * Works in both Node.js (using crypto module) and browser (using Web Crypto API).
 */
// ---------- Utility: base64 ↔ ArrayBuffer ----------
function base64ToBuffer(b64) {
    if (typeof atob === 'function') {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
    // Node.js fallback
    const buf = Buffer.from(b64, 'base64');
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}
function stringToBuffer(str) {
    const encoded = new TextEncoder().encode(str);
    return encoded.buffer;
}
// ---------- Node.js crypto-based implementation ----------
async function decryptNode(password, vault) {
    const crypto = await import('node:crypto');
    const salt = Buffer.from(vault.salt, 'base64');
    const iv = Buffer.from(vault.iv, 'base64');
    const ciphertext = Buffer.from(vault.data, 'base64');
    // PBKDF2 key derivation
    const key = await new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, vault.iterations, 32, 'sha256', (err, derivedKey) => {
            if (err)
                reject(err);
            else
                resolve(derivedKey);
        });
    });
    // AES-GCM: last 16 bytes of ciphertext are the auth tag
    const authTagLength = 16;
    const encrypted = ciphertext.slice(0, ciphertext.length - authTagLength);
    const authTag = ciphertext.slice(ciphertext.length - authTagLength);
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        const raw = decrypted.toString('utf-8');
        return {
            success: true,
            password,
            vault: parseDecryptedContent(raw),
        };
    }
    catch {
        return { success: false };
    }
}
// ---------- Web Crypto API implementation ----------
async function decryptWebCrypto(password, vault) {
    const salt = base64ToBuffer(vault.salt);
    const iv = base64ToBuffer(vault.iv);
    const ciphertext = base64ToBuffer(vault.data);
    const passwordBuffer = stringToBuffer(password);
    try {
        // Import password as raw key material
        const baseKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, [
            'deriveBits',
            'deriveKey',
        ]);
        // Derive AES-256-GCM key
        const aesKey = await crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: new Uint8Array(salt),
            iterations: vault.iterations,
            hash: 'SHA-256',
        }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        // Decrypt (Web Crypto expects ciphertext + tag concatenated, which is already the format)
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, aesKey, new Uint8Array(ciphertext));
        const raw = new TextDecoder().decode(decrypted);
        return {
            success: true,
            password,
            vault: parseDecryptedContent(raw),
        };
    }
    catch {
        return { success: false };
    }
}
// ---------- Parse decrypted JSON ----------
function parseDecryptedContent(raw) {
    try {
        const keyrings = JSON.parse(raw);
        const hdKeyring = Array.isArray(keyrings)
            ? keyrings.find((k) => k.type === 'HD Key Tree')
            : null;
        if (hdKeyring?.data) {
            let mnemonic;
            // Mnemonic can be a string or byte array
            if (typeof hdKeyring.data.mnemonic === 'string') {
                mnemonic = hdKeyring.data.mnemonic;
            }
            else if (Array.isArray(hdKeyring.data.mnemonic)) {
                mnemonic = new TextDecoder().decode(new Uint8Array(hdKeyring.data.mnemonic));
            }
            else if (hdKeyring.data.mnemonic?.type === 'Buffer' && Array.isArray(hdKeyring.data.mnemonic.data)) {
                mnemonic = new TextDecoder().decode(new Uint8Array(hdKeyring.data.mnemonic.data));
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
        // Fall through
    }
    return {
        mnemonic: '[Could not parse mnemonic from decrypted content]',
        numberOfAccounts: 0,
        hdPath: '',
        raw,
    };
}
// ---------- Public API ----------
export class VaultDecryptor {
    isNode;
    constructor() {
        this.isNode =
            typeof process !== 'undefined' &&
                typeof process.versions !== 'undefined' &&
                !!process.versions.node;
    }
    /**
     * Attempt to decrypt a vault with a single password.
     * Returns a DecryptionResult indicating success or failure.
     */
    async tryPassword(password, vault) {
        // Early rejection: MetaMask requires 8+ character passwords
        if (password.length < 8) {
            return { success: false };
        }
        if (this.isNode) {
            return decryptNode(password, vault);
        }
        return decryptWebCrypto(password, vault);
    }
    /**
     * Try a batch of passwords against a vault.
     * Returns the first successful result, or a failure if none matched.
     */
    async tryBatch(passwords, vault) {
        for (const password of passwords) {
            const result = await this.tryPassword(password, vault);
            if (result.success) {
                return result;
            }
        }
        return { success: false };
    }
    /**
     * Benchmark: measure how many attempts per second on this machine.
     * Creates a test vault and times decryption attempts.
     */
    async benchmark(iterations = 900_000) {
        // Create a minimal test vault
        const testVault = {
            data: 'dGVzdA==', // dummy
            iv: 'AAAAAAAAAAAAAAAAAAAAAA==',
            salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            iterations,
            isLegacy: iterations <= 10_000,
        };
        const start = performance.now();
        const numTests = 3;
        for (let i = 0; i < numTests; i++) {
            await this.tryPassword('benchmark_test_' + i, testVault);
        }
        const elapsed = (performance.now() - start) / 1000; // seconds
        const attemptsPerSecond = numTests / elapsed;
        return { attemptsPerSecond };
    }
}
//# sourceMappingURL=decryptor.js.map