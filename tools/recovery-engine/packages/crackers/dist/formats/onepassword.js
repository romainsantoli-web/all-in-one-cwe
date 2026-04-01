/**
 * 1Password Vault Cracker
 * OPVault: PBKDF2-SHA512 + AES-256-CBC + HMAC-SHA256
 * 1Password 7+: SRP-based (not directly crackable offline)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
export const OnePasswordCracker = {
    id: '1password',
    name: '1Password',
    description: '1Password vault (OPVault / AgileKeychain — PBKDF2 + AES)',
    fileExtensions: ['.opvault', '.agilekeychain'],
    async detect(filePath) {
        try {
            const stat = fs.statSync(filePath);
            if (stat.isDirectory()) {
                // OPVault is a directory with profile.js inside
                return fs.existsSync(path.join(filePath, 'default', 'profile.js'));
            }
            // Could be a profile.js file directly
            if (filePath.endsWith('profile.js')) {
                const content = fs.readFileSync(filePath, 'utf-8');
                return content.includes('iterations') && content.includes('masterKey');
            }
            return false;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        let profilePath = filePath;
        // Navigate to profile.js if given directory
        if (fs.statSync(filePath).isDirectory()) {
            profilePath = path.join(filePath, 'default', 'profile.js');
        }
        const content = fs.readFileSync(profilePath, 'utf-8');
        // OPVault profile.js contains: var profile = { ... };
        const jsonMatch = content.match(/\{[\s\S]+\}/);
        if (!jsonMatch)
            throw new Error('Could not parse 1Password profile');
        const profile = JSON.parse(jsonMatch[0]);
        return {
            type: '1password',
            format: 'opvault',
            salt: Buffer.from(profile.salt, 'base64').toString('base64'),
            iterations: profile.iterations || 100000,
            masterKey: profile.masterKey ? Buffer.from(profile.masterKey, 'base64').toString('base64') : '',
            masterKeyHmac: '', // Extracted from masterKey opdata
            overviewKey: profile.overviewKey ? Buffer.from(profile.overviewKey, 'base64').toString('base64') : '',
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'base64');
            // PBKDF2-SHA512(password, salt, iterations, 64)
            const derived = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.iterations, 64, 'sha512', (e, k) => e ? rej(e) : res(k)));
            // Split into encryption key (32) and HMAC key (32)
            const encKey = derived.subarray(0, 32);
            const hmacKey = derived.subarray(32, 64);
            // Decrypt and verify overview key or master key (opdata01 format)
            const keyData = Buffer.from(p.overviewKey || p.masterKey, 'base64');
            // opdata01 format: "opdata01" + plaintext_length(8) + IV(16) + ciphertext + HMAC(32)
            if (keyData.length < 64)
                return false;
            const magic = keyData.subarray(0, 8).toString('ascii');
            if (magic !== 'opdata01') {
                // Try direct AES decrypt
                return false;
            }
            const ptLen = Number(keyData.readBigUInt64LE(8));
            const iv = keyData.subarray(16, 32);
            const ciphertext = keyData.subarray(32, keyData.length - 32);
            const hmac = keyData.subarray(keyData.length - 32);
            // Verify HMAC first
            const computed = crypto.createHmac('sha256', hmacKey)
                .update(keyData.subarray(0, keyData.length - 32)).digest();
            if (!computed.equals(hmac))
                return false;
            // HMAC matches — password is correct
            return true;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: `1Password (${p.format})`,
            description: `1Password vault — ${p.iterations.toLocaleString()} iterations`,
            kdf: `PBKDF2-SHA512 × ${p.iterations.toLocaleString()}`,
            cipher: 'AES-256-CBC + HMAC-SHA256',
            iterations: p.iterations,
            difficulty: p.iterations >= 100000 ? 'hard' : 'medium',
        };
    },
};
//# sourceMappingURL=onepassword.js.map