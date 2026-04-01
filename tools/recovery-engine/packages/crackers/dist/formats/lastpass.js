/**
 * LastPass Export/Vault Cracker
 * Format: PBKDF2-SHA256 + AES-256-CBC/ECB
 * Salt = email address, typically 100,100+ iterations
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
export const LastPassCracker = {
    id: 'lastpass',
    name: 'LastPass',
    description: 'LastPass vault/export (PBKDF2-SHA256 + AES-256)',
    fileExtensions: ['.csv', '.html', '.dat'],
    async detect(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8').substring(0, 2000);
            // LastPass encrypted vault starts with "LPB64" or contains lastpass markers
            return content.includes('LPB64') || content.includes('lastpass') ||
                (content.startsWith('!') && content.includes('|'));
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');
        let iterations = 100100; // Default modern iteration count
        let isBase64 = true;
        let encryptedChunk = '';
        if (content.startsWith('LPB64')) {
            // Base64 encoded vault
            encryptedChunk = content.substring(5, 200);
            isBase64 = true;
        }
        else if (content.startsWith('!')) {
            // AES-CBC: "!IV|ciphertext"
            const parts = content.split('|');
            if (parts.length >= 2) {
                encryptedChunk = parts[0].substring(1) + '|' + parts[1].substring(0, 100);
                isBase64 = true;
            }
        }
        else {
            // Hex-encoded or raw (AES-ECB, old format)
            encryptedChunk = content.substring(0, 200);
            isBase64 = false;
        }
        return {
            type: 'lastpass',
            iterations,
            salt: '', // User must provide email via --salt flag
            encryptedVault: encryptedChunk,
            isBase64,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            if (!p.salt) {
                throw new Error('LastPass requires email as salt (--salt your@email.com)');
            }
            // Key = PBKDF2-SHA256(password, email, iterations, 32)
            const key = await new Promise((res, rej) => crypto.pbkdf2(password, p.salt, p.iterations, 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            // Login hash = PBKDF2-SHA256(key_hex, password, 1, 32) — used for auth
            // For vault decryption, try to decrypt first chunk
            const vault = p.encryptedVault;
            if (p.isBase64 && vault.includes('|')) {
                // AES-256-CBC: IV | ciphertext
                const parts = vault.split('|');
                const iv = Buffer.from(parts[0], 'base64');
                const ct = Buffer.from(parts[1], 'base64');
                if (iv.length !== 16)
                    return false;
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
                // Check if decrypted data looks like valid text
                const str = decrypted.toString('utf-8');
                return /^[\x20-\x7E\n\r\t]/.test(str);
            }
            else {
                // AES-256-ECB (legacy)
                const ct = Buffer.from(vault, 'hex');
                if (ct.length < 16)
                    return false;
                const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
                const decrypted = Buffer.concat([decipher.update(ct.subarray(0, 32)), decipher.final()]);
                const str = decrypted.toString('utf-8');
                return /^[\x20-\x7E\n\r\t]/.test(str);
            }
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'LastPass Vault',
            description: `LastPass encrypted vault — ${p.iterations.toLocaleString()} iterations`,
            kdf: `PBKDF2-SHA256 × ${p.iterations.toLocaleString()}`,
            cipher: p.isBase64 ? 'AES-256-CBC' : 'AES-256-ECB',
            iterations: p.iterations,
            difficulty: p.iterations >= 100000 ? 'medium' : 'easy',
        };
    },
};
//# sourceMappingURL=lastpass.js.map