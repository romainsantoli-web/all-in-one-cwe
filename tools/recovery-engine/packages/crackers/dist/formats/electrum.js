/**
 * Electrum Wallet Cracker
 * V1: SHA-256 KDF + AES-256-CBC (seed storage)
 * V2+: PBKDF2-SHA512(password, "", 1024) + AES-256-CBC
 * V4+: PBKDF2-SHA512(password, "", 2048) + AES-256-CBC
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
export const ElectrumCracker = {
    id: 'electrum',
    name: 'Electrum Wallet',
    description: 'Electrum Bitcoin wallet (PBKDF2-SHA512 + AES-256-CBC)',
    fileExtensions: ['.json', '.dat'],
    async detect(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8').trim();
            // Electrum v2+ stores wallet as JSON with encrypted "keystore"
            if (content.startsWith('{')) {
                const data = JSON.parse(content);
                // Electrum wallet has "wallet_type" or encrypted "keystore"
                if (data.wallet_type || data.keystore)
                    return true;
                // Or xprv field that's encrypted
                if (data.keystore?.xprv || data.keystore?.seed)
                    return true;
            }
            // Electrum v1: base64 encoded encrypted data
            const decoded = Buffer.from(content, 'base64');
            return decoded.length > 16 && decoded.length < 10000;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8').trim();
        if (content.startsWith('{')) {
            const data = JSON.parse(content);
            const keystore = data.keystore || data;
            // v2/v4 encrypted xprv or seed
            const encrypted = keystore.xprv || keystore.seed || '';
            if (!encrypted)
                throw new Error('No encrypted data found in Electrum wallet');
            // Determine version based on seed_version
            const seedVersion = keystore.seed_version || data.seed_version;
            const version = seedVersion >= 40 ? 4 : 2;
            return {
                type: 'electrum',
                version: version,
                encryptedData: Buffer.from(encrypted, 'base64').toString('base64'),
                iterations: version >= 4 ? 2048 : 1024,
            };
        }
        // Electrum v1: entire file is base64-encoded encrypted data
        return {
            type: 'electrum',
            version: 1,
            encryptedData: content,
            iterations: 1, // v1 uses simple SHA-256
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const encData = Buffer.from(p.encryptedData, 'base64');
            if (p.version === 1) {
                // V1: key = SHA-256(SHA-256(password))
                const key = crypto.createHash('sha256')
                    .update(crypto.createHash('sha256').update(password).digest())
                    .digest();
                const iv = encData.subarray(0, 16);
                const ct = encData.subarray(16);
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
                // Check for valid UTF-8 seed words
                const text = decrypted.toString('utf-8');
                return /^[a-z ]+$/.test(text.trim());
            }
            else {
                // V2/V4: PBKDF2-SHA512
                const key = await new Promise((res, rej) => crypto.pbkdf2(password, '', p.iterations, 64, 'sha512', (e, k) => e ? rej(e) : res(k)));
                const aesKey = key.subarray(0, 32);
                const iv = key.subarray(32, 48);
                // Decrypt: the encrypted data is the raw ciphertext
                const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
                const decrypted = Buffer.concat([decipher.update(encData), decipher.final()]);
                // Check for valid content (xprv key or seed phrase)
                const text = decrypted.toString('utf-8');
                return text.startsWith('xprv') || /^[a-z ]{20,}$/.test(text.trim());
            }
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: `Electrum v${p.version}`,
            description: `Electrum wallet — ${p.version === 1 ? 'SHA-256 KDF' : `PBKDF2-SHA512 × ${p.iterations}`}`,
            kdf: p.version === 1 ? 'SHA-256 (double)' : `PBKDF2-SHA512 × ${p.iterations}`,
            cipher: 'AES-256-CBC',
            iterations: p.iterations,
            difficulty: 'easy',
            estimatedSpeed: p.version === 1 ? '~500,000/s' : '~5,000/s',
        };
    },
};
//# sourceMappingURL=electrum.js.map