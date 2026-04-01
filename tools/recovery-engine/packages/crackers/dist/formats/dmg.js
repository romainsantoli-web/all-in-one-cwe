/**
 * macOS DMG Cracker
 * Format: Apple Disk Image with PBKDF2 + AES-128/256 encryption
 * The koly trailer + XML plist contain encryption parameters.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
const KOLY_MAGIC = Buffer.from('koly');
export const DmgCracker = {
    id: 'dmg',
    name: 'macOS DMG',
    description: 'Encrypted macOS disk images (PBKDF2 + AES)',
    fileExtensions: ['.dmg'],
    async detect(filePath) {
        try {
            const stat = fs.statSync(filePath);
            if (stat.size < 512)
                return false;
            // Read koly trailer (last 512 bytes)
            const buf = Buffer.alloc(512);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 512, stat.size - 512);
            fs.closeSync(fd);
            // Check for koly magic
            return buf.subarray(0, 4).equals(KOLY_MAGIC);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const data = fs.readFileSync(filePath);
        // Search for encrypted DMG markers in XML plist
        const xmlStr = data.toString('latin1');
        // Look for EncryptedEncoding plist keys
        const saltMatch = xmlStr.match(/<key>PBKDF2-salt<\/key>\s*<data>([\s\S]*?)<\/data>/);
        const iterMatch = xmlStr.match(/<key>PBKDF2-iterations<\/key>\s*<integer>(\d+)<\/integer>/);
        const bitsMatch = xmlStr.match(/<key>key-bits<\/key>\s*<integer>(\d+)<\/integer>/);
        const ivMatch = xmlStr.match(/<key>IV<\/key>\s*<data>([\s\S]*?)<\/data>/);
        const blobMatch = xmlStr.match(/<key>wrapped-key<\/key>\s*<data>([\s\S]*?)<\/data>/);
        // Defaults for encrypted DMGs
        const salt = saltMatch?.[1]?.replace(/\s/g, '') || '';
        const iterations = parseInt(iterMatch?.[1] || '250000');
        const keyBits = parseInt(bitsMatch?.[1] || '128');
        const iv = ivMatch?.[1]?.replace(/\s/g, '') || '';
        const encKeyBlob = blobMatch?.[1]?.replace(/\s/g, '') || '';
        if (!salt && !encKeyBlob) {
            // Fallback: scan for binary encryption header
            // Encrypted DMGs have a v2 header starting with specific bytes
            throw new Error('Could not find encryption parameters in DMG — file may not be encrypted');
        }
        return {
            type: 'dmg',
            salt: Buffer.from(salt, 'base64').toString('base64'),
            iterations,
            keyBits,
            iv: iv ? Buffer.from(iv, 'base64').toString('base64') : Buffer.alloc(16).toString('base64'),
            encKeyBlob: encKeyBlob ? Buffer.from(encKeyBlob, 'base64').toString('base64') : '',
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'base64');
            const keyLen = p.keyBits / 8;
            // PBKDF2-SHA1 (macOS standard for DMG)
            const derived = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.iterations, keyLen + 32, 'sha1', (e, k) => e ? rej(e) : res(k)));
            const aesKey = derived.subarray(0, keyLen);
            const hmacKey = derived.subarray(keyLen, keyLen + 20);
            if (p.encKeyBlob) {
                // AES key unwrap of the encrypted key blob
                const blob = Buffer.from(p.encKeyBlob, 'base64');
                const iv = Buffer.from(p.iv, 'base64');
                // Try AES-CBC decrypt of wrapped key
                const cipherName = keyLen === 16 ? 'aes-128-cbc' : 'aes-256-cbc';
                const decipher = crypto.createDecipheriv(cipherName, aesKey, iv);
                decipher.setAutoPadding(false);
                const decrypted = Buffer.concat([decipher.update(blob), decipher.final()]);
                // Verify: unwrapped key should have valid structure
                // Apple uses RFC 3394 AES Key Wrap — check first 8 bytes = A6A6A6A6A6A6A6A6
                if (decrypted.length >= 8) {
                    const check = decrypted.subarray(0, 8);
                    const expected = Buffer.from([0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]);
                    return check.equals(expected);
                }
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
            format: 'macOS DMG',
            description: `Encrypted disk image — ${p.iterations.toLocaleString()} iterations`,
            kdf: `PBKDF2-SHA1 × ${p.iterations.toLocaleString()}`,
            cipher: `AES-${p.keyBits}-CBC`,
            iterations: p.iterations,
            difficulty: p.iterations >= 250000 ? 'medium' : 'easy',
        };
    },
};
//# sourceMappingURL=dmg.js.map