/**
 * 7-Zip Archive Cracker
 * Format: AES-256-CBC with SHA-256-based KDF
 * Iterations: 2^NumCyclesPower (typically 2^19 = 524,288)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
const SEVENZ_MAGIC = Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
/** CRC-32 lookup table (IEEE polynomial) */
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++)
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    CRC32_TABLE[i] = c >>> 0;
}
function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
        crc = CRC32_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}
/** 7-Zip AES key derivation: SHA-256(salt + password_utf16) iterated 2^numCyclesPower times */
function derive7zKey(password, salt, numCyclesPower) {
    const passUtf16 = Buffer.from(password, 'utf-16le');
    const base = Buffer.concat([salt, passUtf16]);
    const iterations = 1 << numCyclesPower;
    // 7-Zip KDF: hash(salt + password + counter_le64) for counter 0..iterations-1
    const combined = Buffer.alloc(base.length + 8);
    base.copy(combined);
    let result = Buffer.alloc(32);
    const sha = crypto.createHash('sha256');
    for (let i = 0; i < iterations; i++) {
        // Write 64-bit little-endian counter
        combined[base.length] = i & 0xFF;
        combined[base.length + 1] = (i >>> 8) & 0xFF;
        combined[base.length + 2] = (i >>> 16) & 0xFF;
        combined[base.length + 3] = (i >>> 24) & 0xFF;
        combined[base.length + 4] = 0;
        combined[base.length + 5] = 0;
        combined[base.length + 6] = 0;
        combined[base.length + 7] = 0;
        sha.update(combined);
    }
    // Note: 7-Zip actually accumulates into a SHA-256 hash
    // Simplified: we hash (salt+password) repeatedly
    // Real implementation: SHA-256 accumulator over all counter values
    result = sha.digest();
    return result;
}
export const SevenZipCracker = {
    id: '7zip',
    name: '7-Zip Archive',
    description: 'Encrypted 7z files (AES-256 + SHA-256 KDF)',
    fileExtensions: ['.7z'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(6);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 6, 0);
            fs.closeSync(fd);
            return buf.equals(SEVENZ_MAGIC);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const fd = fs.openSync(filePath, 'r');
        const stat = fs.fstatSync(fd);
        const headerBuf = Buffer.alloc(Math.min(stat.size, 32768));
        fs.readSync(fd, headerBuf, 0, headerBuf.length, 0);
        fs.closeSync(fd);
        if (!headerBuf.subarray(0, 6).equals(SEVENZ_MAGIC)) {
            throw new Error('Not a 7-Zip file');
        }
        // Parse 7z header — look for AES encryption codec ID 06F10701
        // Simplified: extract using known header structure
        const majorVersion = headerBuf[6];
        const minorVersion = headerBuf[7];
        const startHeaderCrc = headerBuf.readUInt32LE(8);
        const nextHeaderOffset = Number(headerBuf.readBigUInt64LE(12));
        const nextHeaderSize = Number(headerBuf.readBigUInt64LE(20));
        // Read the next header (which may contain encryption info for header-encrypted archives)
        // For simplicity, scan for AES codec pattern 06 F1 07 01
        const aesPattern = Buffer.from([0x06, 0xF1, 0x07, 0x01]);
        let aesPos = -1;
        for (let i = 0; i < headerBuf.length - 4; i++) {
            if (headerBuf[i] === 0x06 && headerBuf[i + 1] === 0xF1 && headerBuf[i + 2] === 0x07 && headerBuf[i + 3] === 0x01) {
                aesPos = i;
                break;
            }
        }
        // Default params if header scanning fails
        // User can override via CLI
        let numCyclesPower = 19; // Default: 2^19 = 524,288
        let salt = Buffer.alloc(0);
        let iv = Buffer.alloc(16);
        if (aesPos >= 0 && aesPos + 10 < headerBuf.length) {
            const propByte = headerBuf[aesPos + 4];
            numCyclesPower = propByte & 0x3F;
            const saltSize = (propByte >> 6) & 0x03;
            const ivSize = ((propByte >> 6) & 0x03);
            // Parse salt and IV from properties
            const propsStart = aesPos + 5;
            if (saltSize > 0 && propsStart + saltSize <= headerBuf.length) {
                salt = headerBuf.subarray(propsStart, propsStart + saltSize);
            }
            if (propsStart + saltSize + ivSize <= headerBuf.length) {
                const rawIv = headerBuf.subarray(propsStart + saltSize, propsStart + saltSize + ivSize);
                rawIv.copy(iv);
            }
        }
        // First encrypted block (for verification)
        const dataStart = 32; // After signature header
        const encBlock = headerBuf.subarray(dataStart, dataStart + 32);
        return {
            type: '7zip',
            salt: salt.toString('base64'),
            iv: iv.toString('base64'),
            numCyclesPower,
            encBlock: encBlock.toString('base64'),
            packSize: 0,
            unpackSize: 0,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'base64');
            const iv = Buffer.from(p.iv, 'base64');
            const encBlock = Buffer.from(p.encBlock, 'base64');
            const key = derive7zKey(password, salt, p.numCyclesPower);
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            decipher.setAutoPadding(false);
            const decrypted = decipher.update(encBlock);
            if (decrypted.length < 2)
                return false;
            // CRC32 verification if available
            if (p.crc32 !== undefined && p.crc32 !== 0 && p.unpackSize > 0 && p.unpackSize <= decrypted.length) {
                const crc = crc32(decrypted.subarray(0, p.unpackSize));
                return crc === p.crc32;
            }
            // LZMA header validation for compressed data:
            // Byte 0: LZMA properties = lc + lp*9 + pb*9*5 (max: 8 + 4*9 + 4*45 = 224 = 0xE0)
            // Bytes 1-4: dictionary size (LE, typically power of 2, 4KB - 1.5GB)
            const propsByte = decrypted[0];
            if (propsByte > 0xE0)
                return false; // Invalid LZMA properties
            // Decode LZMA properties to verify ranges
            const lc = propsByte % 9;
            const remainder = Math.floor(propsByte / 9);
            const lp = remainder % 5;
            const pb = Math.floor(remainder / 5);
            if (lc > 8 || lp > 4 || pb > 4)
                return false;
            // Check dictionary size (bytes 1-4): should be reasonable (not 0, not > 4GB)
            if (decrypted.length >= 5) {
                const dictSize = decrypted.readUInt32LE(1);
                if (dictSize === 0)
                    return false;
                if (dictSize > 0x80000000)
                    return false; // > 2GB
            }
            // Additional: reject all-zeros or repeating patterns (random miss)
            const zeros = decrypted.filter((b) => b === 0).length;
            if (zeros > decrypted.length * 0.9)
                return false;
            return true;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        const iterations = 1 << p.numCyclesPower;
        return {
            format: '7-Zip (AES-256)',
            description: `7-Zip encrypted archive — 2^${p.numCyclesPower} = ${iterations.toLocaleString()} iterations`,
            kdf: `SHA-256 KDF × ${iterations.toLocaleString()}`,
            cipher: 'AES-256-CBC',
            iterations,
            difficulty: iterations > 500000 ? 'medium' : 'easy',
        };
    },
};
//# sourceMappingURL=sevenzip.js.map