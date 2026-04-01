/**
 * MetaMask Vault Cracker
 * Format: PBKDF2-SHA256 + AES-256-GCM
 * Iterations: 10k (legacy) / 600k / 900k (modern)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
function b64(s) { return Buffer.from(s, 'base64'); }
export const MetaMaskCracker = {
    id: 'metamask',
    name: 'MetaMask',
    description: 'MetaMask browser wallet vault (PBKDF2 + AES-256-GCM)',
    fileExtensions: ['.json'],
    async detect(filePath) {
        try {
            const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
            return !!(raw.data && raw.iv && raw.salt &&
                (raw.iterations || raw.keyMetadata?.params?.iterations));
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        const iterations = raw.iterations ?? raw.keyMetadata?.params?.iterations ?? 10_000;
        return { type: 'metamask', data: raw.data, iv: raw.iv, salt: raw.salt, iterations };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const key = await new Promise((res, rej) => crypto.pbkdf2(password, b64(p.salt), p.iterations, 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            const dataBuffer = b64(p.data);
            const authTag = dataBuffer.subarray(dataBuffer.length - 16);
            const ciphertext = dataBuffer.subarray(0, dataBuffer.length - 16);
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, b64(p.iv));
            decipher.setAuthTag(authTag);
            decipher.update(ciphertext);
            decipher.final();
            return true;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'MetaMask Vault',
            description: `MetaMask encrypted vault — ${p.iterations.toLocaleString()} iterations`,
            kdf: `PBKDF2-SHA256 × ${p.iterations.toLocaleString()}`,
            cipher: 'AES-256-GCM',
            iterations: p.iterations,
            difficulty: p.iterations >= 600_000 ? 'medium' : 'easy',
        };
    },
};
//# sourceMappingURL=metamask.js.map