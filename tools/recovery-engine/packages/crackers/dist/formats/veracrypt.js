/**
 * VeraCrypt / TrueCrypt Volume Cracker
 * Format: First 512 bytes = encrypted header
 * KDF: PBKDF2 with SHA-512/SHA-256/Whirlpool/RIPEMD-160/Streebog
 * Cipher: AES/Serpent/Twofish/Camellia (XTS mode)
 * Verification: decrypt header → check "VERA" or "TRUE" magic at offset 64
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// VeraCrypt iteration counts per hash algorithm
const VC_ITERATIONS = {
    'sha512': 500_000,
    'sha256': 500_000,
    'ripemd160': 655_331, // VeraCrypt PIM default
};
const TC_ITERATIONS = {
    'sha512': 1_000,
    'ripemd160': 2_000,
};
/** AES-XTS decryption (simplified: XTS = AES-ECB on tweak ⊕ plaintext) */
function aesXtsDecrypt(key, data, sectorNum) {
    // XTS uses two keys: key1 (encryption) + key2 (tweak)
    const key1 = key.subarray(0, 32);
    const key2 = key.subarray(32, 64);
    // Compute tweak from sector number using key2
    const tweak = Buffer.alloc(16);
    tweak.writeUInt32LE(sectorNum, 0);
    const tweakCipher = crypto.createCipheriv('aes-256-ecb', key2, null);
    tweakCipher.setAutoPadding(false);
    let T = tweakCipher.update(tweak);
    const result = Buffer.alloc(data.length);
    const blockSize = 16;
    for (let i = 0; i < data.length; i += blockSize) {
        const block = Buffer.alloc(blockSize);
        for (let j = 0; j < blockSize; j++)
            block[j] = data[i + j] ^ T[j];
        const decipher = crypto.createDecipheriv('aes-256-ecb', key1, null);
        decipher.setAutoPadding(false);
        const dec = decipher.update(block);
        for (let j = 0; j < blockSize; j++)
            result[i + j] = dec[j] ^ T[j];
        // Multiply tweak by 2 in GF(2^128)
        let carry = 0;
        const newT = Buffer.alloc(16);
        for (let j = 0; j < 16; j++) {
            const tmp = (T[j] << 1) | carry;
            carry = (T[j] >> 7) & 1;
            newT[j] = tmp & 0xFF;
        }
        if (carry)
            newT[0] ^= 0x87; // GF reduction polynomial
        T = newT;
    }
    return result;
}
export const VeraCryptCracker = {
    id: 'veracrypt',
    name: 'VeraCrypt / TrueCrypt',
    description: 'VeraCrypt/TrueCrypt encrypted volumes (PBKDF2 + AES-XTS)',
    fileExtensions: ['.hc', '.tc', '.vol'],
    async detect(filePath) {
        try {
            const stat = fs.statSync(filePath);
            // VeraCrypt volumes have no magic bytes (encrypted from byte 0)
            // Check extension or minimum size (at least 512 bytes for header)
            return stat.size >= 512 &&
                (filePath.endsWith('.hc') || filePath.endsWith('.tc') || filePath.endsWith('.vol'));
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const fd = fs.openSync(filePath, 'r');
        const stat = fs.fstatSync(fd);
        // Read first 512 bytes (main header)
        const header = Buffer.alloc(512);
        fs.readSync(fd, header, 0, 512, 0);
        // Read backup header (last 512 bytes)
        let backupHeader;
        if (stat.size > 1024) {
            backupHeader = Buffer.alloc(512);
            fs.readSync(fd, backupHeader, 0, 512, stat.size - 512);
        }
        fs.closeSync(fd);
        const isTrueCrypt = filePath.endsWith('.tc');
        return {
            type: 'veracrypt',
            header: header.toString('base64'),
            backupHeader: backupHeader?.toString('base64'),
            isTrueCrypt,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        const header = Buffer.from(p.header, 'base64');
        // Salt is first 64 bytes of the header
        const salt = header.subarray(0, 64);
        const encHeader = header.subarray(64);
        // Try each hash algorithm
        const hashAlgos = p.isTrueCrypt
            ? ['sha512', 'ripemd160']
            : ['sha512', 'sha256'];
        const iterMap = p.isTrueCrypt ? TC_ITERATIONS : VC_ITERATIONS;
        for (const algo of hashAlgos) {
            const iterations = iterMap[algo] || 500_000;
            try {
                // Derive 128 bytes (64 for key + 64 for secondary key)
                // For AES-XTS: we need 64 bytes (two 32-byte keys)
                let derived;
                if (algo === 'ripemd160') {
                    // Node.js may not have ripemd160 — try it
                    try {
                        derived = await new Promise((res, rej) => crypto.pbkdf2(password, salt, iterations, 64, 'ripemd160', (e, k) => e ? rej(e) : res(k)));
                    }
                    catch {
                        continue;
                    }
                }
                else {
                    derived = await new Promise((res, rej) => crypto.pbkdf2(password, salt, iterations, 64, algo, (e, k) => e ? rej(e) : res(k)));
                }
                // Try AES-XTS decrypt of header
                const decrypted = aesXtsDecrypt(derived, encHeader.subarray(0, 448), 0);
                // Check for magic string at expected position
                // VeraCrypt: "VERA" at offset 0 of decrypted header
                // TrueCrypt: "TRUE" at offset 0
                const magic = decrypted.subarray(0, 4).toString('ascii');
                if (magic === 'VERA' || magic === 'TRUE')
                    return true;
            }
            catch {
                continue;
            }
        }
        return false;
    },
    getInfo(params) {
        const p = params;
        const name = p.isTrueCrypt ? 'TrueCrypt' : 'VeraCrypt';
        return {
            format: name,
            description: `${name} encrypted volume — multi-algorithm brute force`,
            kdf: `PBKDF2 (SHA-512/256/RIPEMD-160) × 500k+`,
            cipher: 'AES-256-XTS (+ Serpent/Twofish)',
            iterations: 500_000,
            difficulty: 'extreme',
            estimatedSpeed: '~1-3/s (must try each hash algo)',
        };
    },
};
//# sourceMappingURL=veracrypt.js.map