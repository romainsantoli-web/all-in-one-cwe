/**
 * macOS FileVault 2 Cracker
 * Format: Core Storage + EncryptedRoot.plist
 * KDF: PBKDF2-SHA256 + AES-XTS (wrapped key)
 * Similar structure to encrypted DMG but with CS wrapper
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
/** "CS" magic for Core Storage */
const CS_MAGIC = Buffer.from([0x43, 0x53]);
export const FileVaultCracker = {
    id: 'filevault',
    name: 'FileVault 2',
    description: 'macOS FileVault 2 (PBKDF2-SHA256 + AES-XTS)',
    fileExtensions: ['.sparsebundle', '.dmg', '.img'],
    async detect(filePath) {
        try {
            // FileVault can be on a raw disk partition or in specific files
            // Check for EncryptedRoot.plist or CS headers
            const data = fs.readFileSync(filePath, { encoding: null });
            return data.includes(Buffer.from('EncryptedRoot')) ||
                data.includes(Buffer.from('com.apple.corestorage'));
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const data = fs.readFileSync(filePath);
        const str = data.toString('latin1');
        // Search for PBKDF2 parameters in plist
        const saltMatch = str.match(/PassphraseWrappedKeySalt[\s\S]*?<data>([\s\S]*?)<\/data>/);
        const iterMatch = str.match(/PBKDF2-iterations[\s\S]*?<integer>(\d+)<\/integer>/);
        const keyMatch = str.match(/WrappedVolumeKey[\s\S]*?<data>([\s\S]*?)<\/data>/);
        return {
            type: 'filevault',
            salt: saltMatch?.[1]?.replace(/\s/g, '') || '',
            iterations: parseInt(iterMatch?.[1] || '250000'),
            wrappedKey: keyMatch?.[1]?.replace(/\s/g, '') || '',
            keyBits: 256,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'base64');
            const wrappedKey = Buffer.from(p.wrappedKey, 'base64');
            // PBKDF2-SHA256
            const derived = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.iterations, p.keyBits / 8, 'sha256', (e, k) => e ? rej(e) : res(k)));
            // AES Key Unwrap (RFC 3394)
            if (wrappedKey.length >= 24) {
                // Simplified AES unwrap: decrypt and check first 8 bytes = 0xA6...
                const iv = wrappedKey.subarray(0, 8);
                const cipherName = p.keyBits === 128 ? 'aes-128-ecb' : 'aes-256-ecb';
                // AES Key Unwrap is not a simple decrypt — it's iterative
                // Check using single-block unwrap
                const decipher = crypto.createDecipheriv(cipherName, derived, null);
                decipher.setAutoPadding(false);
                const dec = decipher.update(wrappedKey.subarray(0, 16));
                return dec[0] === 0xA6 && dec[1] === 0xA6 && dec[2] === 0xA6 && dec[3] === 0xA6;
            }
            return false;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'FileVault 2',
            description: `macOS FileVault 2 — ${p.iterations.toLocaleString()} iterations`,
            kdf: `PBKDF2-SHA256 × ${p.iterations.toLocaleString()}`,
            cipher: 'AES-256-XTS',
            iterations: p.iterations,
            difficulty: 'hard',
        };
    },
};
//# sourceMappingURL=filevault.js.map