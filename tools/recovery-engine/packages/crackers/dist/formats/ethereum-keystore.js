/**
 * Ethereum Keystore (Web3 Secret Storage) Cracker
 * Format: JSON file with scrypt/PBKDF2 + AES-128-CTR
 * Verification: keccak256(derivedKey[16:32] + ciphertext) == mac
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import jsSha3 from 'js-sha3';
/** Ethereum keccak-256 (pre-FIPS, NOT SHA-3) */
function keccak256(data) {
    return Buffer.from(jsSha3.keccak_256.arrayBuffer(data));
}
export const EthKeystoreCracker = {
    id: 'ethereum-keystore',
    name: 'Ethereum Keystore',
    description: 'Ethereum Web3 Secret Storage (scrypt/PBKDF2 + AES-128-CTR)',
    fileExtensions: ['.json'],
    async detect(filePath) {
        try {
            const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
            return content.version === 3 && content.crypto?.cipher && content.crypto?.kdf;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        // Handle both "crypto" and "Crypto" (case sensitivity)
        const c = content.crypto || content.Crypto;
        if (!c)
            throw new Error('Invalid Ethereum keystore: missing crypto field');
        const kdfParams = c.kdfparams || c.kdfParams;
        const params = {
            type: 'ethereum-keystore',
            kdf: c.kdf,
            dklen: kdfParams.dklen || 32,
            salt: kdfParams.salt,
            iv: c.cipherparams?.iv || c.cipherParams?.iv,
            ciphertext: c.ciphertext,
            mac: c.mac,
            cipher: c.cipher || 'aes-128-ctr',
        };
        if (c.kdf === 'scrypt') {
            params.n = kdfParams.n;
            params.r = kdfParams.r;
            params.p = kdfParams.p;
        }
        else if (c.kdf === 'pbkdf2') {
            params.c = kdfParams.c;
            params.prf = kdfParams.prf;
        }
        return params;
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'hex');
            let derivedKey;
            if (p.kdf === 'scrypt') {
                derivedKey = await new Promise((res, rej) => crypto.scrypt(Buffer.from(password), salt, p.dklen, {
                    N: p.n || 262144,
                    r: p.r || 8,
                    p: p.p || 1,
                    maxmem: 256 * 1024 * 1024, // 256 MB
                }, (e, k) => e ? rej(e) : res(k)));
            }
            else {
                // PBKDF2
                const hmacAlg = (p.prf || 'hmac-sha256').replace('hmac-', '');
                derivedKey = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.c || 262144, p.dklen, hmacAlg, (e, k) => e ? rej(e) : res(k)));
            }
            // Verify MAC: keccak256(derivedKey[16:32] + ciphertext) == mac
            const ciphertext = Buffer.from(p.ciphertext, 'hex');
            const macInput = Buffer.concat([derivedKey.subarray(16, 32), ciphertext]);
            const computedMac = keccak256(macInput);
            const expectedMac = Buffer.from(p.mac, 'hex');
            return computedMac.equals(expectedMac);
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        if (p.kdf === 'scrypt') {
            return {
                format: 'Ethereum Keystore (scrypt)',
                description: `Ethereum keystore — scrypt N=${p.n}, r=${p.r}, p=${p.p}`,
                kdf: `scrypt (N=${p.n}, r=${p.r}, p=${p.p})`,
                cipher: p.cipher,
                difficulty: (p.n || 0) >= 262144 ? 'hard' : 'medium',
                estimatedSpeed: '~1-5/s',
            };
        }
        return {
            format: 'Ethereum Keystore (PBKDF2)',
            description: `Ethereum keystore — PBKDF2 ${(p.c || 0).toLocaleString()} iterations`,
            kdf: `PBKDF2-SHA256 × ${p.c?.toLocaleString()}`,
            cipher: p.cipher,
            iterations: p.c,
            difficulty: 'medium',
        };
    },
};
//# sourceMappingURL=ethereum-keystore.js.map