/**
 * Bitwarden Export Cracker
 * Format: PBKDF2-SHA256 + AES-256-CBC + HMAC-SHA256
 * (Encrypted JSON export or org vault backup)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
export const BitwardenCracker = {
    id: 'bitwarden',
    name: 'Bitwarden',
    description: 'Bitwarden encrypted export (PBKDF2/Argon2 + AES-256)',
    fileExtensions: ['.json'],
    async detect(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const data = JSON.parse(content);
            return !!(data.encrypted === true && data.encKeyValidation_DO_NOT_EDIT);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');
        const data = JSON.parse(content);
        if (!data.encrypted)
            throw new Error('Not an encrypted Bitwarden export');
        // Parse the validation field: "encType.iv|ct|mac"
        const validation = data.encKeyValidation_DO_NOT_EDIT;
        const [typeStr, rest] = validation.split('.');
        const parts = rest.split('|');
        const kdfConfig = data.kdfConfig || {};
        return {
            type: 'bitwarden',
            kdfType: kdfConfig.kdfType === 1 ? 'argon2id' : 'pbkdf2',
            iterations: kdfConfig.iterations || 600000,
            encType: parseInt(typeStr),
            iv: parts[0],
            ct: parts[1],
            mac: parts[2] || '',
            salt: data.salt || '',
            argon2Memory: kdfConfig.memory,
            argon2Parallelism: kdfConfig.parallelism,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            let masterKey;
            if (p.kdfType === 'argon2id') {
                const argon2 = await import('argon2');
                const salt = Buffer.from(p.salt || '', 'utf-8');
                masterKey = await argon2.hash(password, {
                    salt: crypto.createHash('sha256').update(salt).digest(),
                    type: 2, // argon2id
                    timeCost: p.iterations,
                    memoryCost: (p.argon2Memory || 64) * 1024, // MB to KB
                    parallelism: p.argon2Parallelism || 4,
                    hashLength: 32,
                    raw: true,
                });
            }
            else {
                // PBKDF2-SHA256(password, salt=email, iterations, 32)
                const salt = Buffer.from(p.salt || '', 'utf-8');
                masterKey = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.iterations, 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            }
            // Stretch master key: HKDF-SHA256(masterKey, "enc" / "mac")
            const stretchedKey = await new Promise((res, rej) => crypto.pbkdf2(masterKey, password, 1, 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            // For Bitwarden: derive encKey and macKey from stretched key
            // Method: HKDF-expand with SHA-256
            const prk = crypto.createHmac('sha256', masterKey).update(Buffer.from('enc')).digest();
            const encKey = prk.subarray(0, 32);
            const macKey = crypto.createHmac('sha256', masterKey).update(Buffer.from('mac')).digest();
            // Verify MAC
            const iv = Buffer.from(p.iv, 'base64');
            const ct = Buffer.from(p.ct, 'base64');
            const mac = Buffer.from(p.mac, 'base64');
            const computedMac = crypto.createHmac('sha256', macKey)
                .update(iv).update(ct).digest();
            return computedMac.equals(mac);
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'Bitwarden Export',
            description: `Bitwarden encrypted export — ${p.iterations.toLocaleString()} iterations`,
            kdf: `${p.kdfType === 'argon2id' ? 'Argon2id' : 'PBKDF2-SHA256'} × ${p.iterations.toLocaleString()}`,
            cipher: 'AES-256-CBC + HMAC-SHA256',
            iterations: p.iterations,
            difficulty: p.iterations >= 600000 ? 'hard' : 'medium',
        };
    },
};
//# sourceMappingURL=bitwarden.js.map