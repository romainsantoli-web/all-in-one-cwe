/**
 * Exodus Wallet Cracker
 * Format: seed.seco file — scrypt + AES-256-GCM
 * The .seco format: header(4) + version(1) + salt(32) + nonce(12) + ciphertext + tag(16)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// .seco magic bytes
const SECO_MAGIC = Buffer.from([0x65, 0x78, 0x6F, 0x00]); // "exo\0"
export const ExodusCracker = {
    id: 'exodus',
    name: 'Exodus Wallet',
    description: 'Exodus wallet seed.seco (scrypt + AES-256-GCM)',
    fileExtensions: ['.seco'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(100);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 100, 0);
            fs.closeSync(fd);
            // Check for .seco extension or exodus-specific patterns
            return filePath.endsWith('.seco') ||
                (buf[0] === 0x65 && buf[1] === 0x78 && buf[2] === 0x6F);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const data = fs.readFileSync(filePath);
        // .seco format parsing
        let offset = 0;
        // Try to detect format
        if (data.subarray(0, 3).toString('ascii') === 'exo') {
            offset = 4; // skip magic
        }
        const version = data[offset];
        offset += 1;
        // Default scrypt params for Exodus
        const scryptN = 16384; // 2^14
        const scryptR = 8;
        const scryptP = 1;
        const salt = data.subarray(offset, offset + 32);
        offset += 32;
        const nonce = data.subarray(offset, offset + 12);
        offset += 12;
        // Rest is ciphertext + 16-byte auth tag
        const authTag = data.subarray(data.length - 16);
        const ciphertext = data.subarray(offset, data.length - 16);
        return {
            type: 'exodus',
            salt: salt.toString('base64'),
            nonce: nonce.toString('base64'),
            ciphertext: ciphertext.toString('base64'),
            authTag: authTag.toString('base64'),
            scryptN,
            scryptR,
            scryptP,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'base64');
            const nonce = Buffer.from(p.nonce, 'base64');
            const ciphertext = Buffer.from(p.ciphertext, 'base64');
            const authTag = Buffer.from(p.authTag, 'base64');
            // scrypt key derivation
            const key = await new Promise((res, rej) => crypto.scrypt(Buffer.from(password), salt, 32, {
                N: p.scryptN,
                r: p.scryptR,
                p: p.scryptP,
                maxmem: 128 * p.scryptN * p.scryptR * 2, // scrypt memory requirement
            }, (e, k) => e ? rej(e) : res(k)));
            // AES-256-GCM decrypt
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(authTag);
            decipher.update(ciphertext);
            decipher.final(); // Throws if auth tag verification fails
            return true;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'Exodus Wallet',
            description: `Exodus seed.seco — scrypt (N=${p.scryptN})`,
            kdf: `scrypt (N=${p.scryptN}, r=${p.scryptR}, p=${p.scryptP})`,
            cipher: 'AES-256-GCM',
            difficulty: p.scryptN >= 16384 ? 'medium' : 'easy',
            estimatedSpeed: '~10-50/s',
        };
    },
};
//# sourceMappingURL=exodus.js.map