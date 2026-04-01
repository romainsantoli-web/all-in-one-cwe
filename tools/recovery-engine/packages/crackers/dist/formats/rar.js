/**
 * RAR Archive Cracker
 * RAR3: AES-128-CBC with custom KDF (SHA-1 based, slow)
 * RAR5: AES-256-CBC with PBKDF2-HMAC-SHA256
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// ── RAR5 magic: Rar!\x1a\x07\x01\x00 ──
const RAR5_MAGIC = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);
// ── RAR3 magic: Rar!\x1a\x07\x00 ──
const RAR3_MAGIC = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
function readVInt(buf, offset) {
    let value = 0;
    let shift = 0;
    let size = 0;
    while (offset + size < buf.length) {
        const b = buf[offset + size];
        value |= (b & 0x7F) << shift;
        size++;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    return { value, size };
}
export const RarCracker = {
    id: 'rar',
    name: 'RAR Archive',
    description: 'Encrypted RAR files (RAR3/RAR5 — AES + PBKDF2)',
    fileExtensions: ['.rar'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(8);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 8, 0);
            fs.closeSync(fd);
            return buf.subarray(0, 8).equals(RAR5_MAGIC) || buf.subarray(0, 7).equals(RAR3_MAGIC);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const fd = fs.openSync(filePath, 'r');
        const buf = Buffer.alloc(8192);
        const bytesRead = fs.readSync(fd, buf, 0, 8192, 0);
        fs.closeSync(fd);
        if (buf.subarray(0, 8).equals(RAR5_MAGIC)) {
            // RAR5: scan for encryption header
            let pos = 8; // skip magic
            while (pos < bytesRead - 20) {
                const crc = buf.readUInt32LE(pos);
                const { value: headerSize, size: s1 } = readVInt(buf, pos + 4);
                const { value: headerType, size: s2 } = readVInt(buf, pos + 4 + s1);
                // Type 4 = encryption header
                if (headerType === 4) {
                    const dataPos = pos + 4 + s1 + s2;
                    const { value: encVersion, size: s3 } = readVInt(buf, dataPos);
                    const { value: encFlags, size: s4 } = readVInt(buf, dataPos + s3);
                    const kdfCount = buf[dataPos + s3 + s4];
                    const salt = buf.subarray(dataPos + s3 + s4 + 1, dataPos + s3 + s4 + 1 + 16);
                    let checkValue;
                    if (encFlags & 0x01) {
                        checkValue = buf.subarray(dataPos + s3 + s4 + 17, dataPos + s3 + s4 + 17 + 12);
                    }
                    return {
                        type: 'rar',
                        version: 5,
                        salt: salt.toString('base64'),
                        kdfCount,
                        checkValue: checkValue?.toString('base64'),
                    };
                }
                pos += 4 + headerSize;
                if (headerSize === 0)
                    break;
            }
            throw new Error('RAR5: No encryption header found — file may not be encrypted');
        }
        else if (buf.subarray(0, 7).equals(RAR3_MAGIC)) {
            // RAR3: find encrypted file header with salt
            let pos = 7;
            while (pos < bytesRead - 20) {
                if (pos + 7 >= bytesRead)
                    break;
                const headType = buf[pos + 2];
                const flags = buf.readUInt16LE(pos + 3);
                const headSize = buf.readUInt16LE(pos + 5);
                // File header with encryption (flag 0x04 set)
                if (headType === 0x74 && (flags & 0x04)) {
                    const salt3 = buf.subarray(pos + headSize - 8, pos + headSize);
                    // Read first encrypted block for password verification
                    const dataStart = pos + headSize;
                    const blockLen = Math.min(32, bytesRead - dataStart);
                    const encData3 = blockLen >= 16
                        ? buf.subarray(dataStart, dataStart + blockLen).toString('base64')
                        : undefined;
                    return { type: 'rar', version: 3, salt3: salt3.toString('base64'), encData3 };
                }
                pos += headSize;
                if (headSize === 0)
                    break;
            }
            throw new Error('RAR3: No encrypted file header found');
        }
        throw new Error('Not a recognized RAR file');
    },
    async tryPassword(password, params) {
        const p = params;
        if (p.version === 5) {
            // RAR5: PBKDF2-HMAC-SHA256(password, salt, 2^(kdfCount+15))
            const iterations = 1 << ((p.kdfCount || 0) + 15);
            const salt = Buffer.from(p.salt, 'base64');
            const derived = await new Promise((res, rej) => crypto.pbkdf2(Buffer.from(password, 'utf-8'), salt, iterations, 32 + 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            if (p.checkValue) {
                // Quick password check value verification
                const checkSalt = Buffer.from(p.checkValue, 'base64');
                const checkKey = derived.subarray(32, 64);
                const computed = crypto.createHmac('sha256', checkKey).update(checkSalt.subarray(0, 8)).digest();
                return computed.subarray(0, 4).equals(checkSalt.subarray(8, 12));
            }
            // Without check value, we can't verify quickly
            return false;
        }
        else {
            // RAR3: SHA-1 based KDF with proper key + IV derivation
            const salt = Buffer.from(p.salt3, 'base64');
            const passBytes = Buffer.from(password, 'utf-16le');
            const rounds = 0x40000; // 262144
            const step = rounds / 16; // 16384
            const iv = Buffer.alloc(16);
            const hash = crypto.createHash('sha1');
            for (let i = 0; i < rounds; i++) {
                hash.update(passBytes);
                hash.update(salt);
                const ibuf = Buffer.alloc(3);
                ibuf[0] = i & 0xFF;
                ibuf[1] = (i >> 8) & 0xFF;
                ibuf[2] = (i >> 16) & 0xFF;
                hash.update(ibuf);
                if (i % step === 0) {
                    // Extract IV byte from intermediate SHA-1 state (byte 19 = last)
                    iv[i / step] = hash.copy().digest()[19];
                }
            }
            const key = hash.digest().subarray(0, 16);
            // Verify by decrypting first encrypted block
            if (p.encData3) {
                const encBlock = Buffer.from(p.encData3, 'base64');
                if (encBlock.length >= 16) {
                    try {
                        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
                        decipher.setAutoPadding(false);
                        const dec = decipher.update(encBlock);
                        // Wrong password → pseudo-random bytes, right → compressed data
                        // Reject trivial patterns: all same byte, all zeros
                        const allSame = dec.every((b) => b === dec[0]);
                        return !allSame;
                    }
                    catch {
                        return false;
                    }
                }
            }
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        if (p.version === 5) {
            const iterations = 1 << ((p.kdfCount || 0) + 15);
            return {
                format: 'RAR5',
                description: `RAR5 encrypted archive — ${iterations.toLocaleString()} iterations`,
                kdf: `PBKDF2-HMAC-SHA256 × ${iterations.toLocaleString()}`,
                cipher: 'AES-256-CBC',
                iterations,
                difficulty: iterations > 100000 ? 'hard' : 'medium',
            };
        }
        return {
            format: 'RAR3',
            description: 'RAR3 encrypted archive — SHA-1 based KDF (262k rounds)',
            kdf: 'SHA-1 × 262,144',
            cipher: 'AES-128-CBC',
            iterations: 262144,
            difficulty: 'medium',
        };
    },
};
//# sourceMappingURL=rar.js.map