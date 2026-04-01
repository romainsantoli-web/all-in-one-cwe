/**
 * ZIP File Cracker
 * Formats: ZipCrypto (legacy, fast) / WinZip AES-256 (modern)
 *
 * ZipCrypto: PKWARE traditional encryption — CRC-based key init, 12-byte header
 * WinZip AES: PBKDF2-SHA1 (1000 iter) + AES-CTR + HMAC-SHA1
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// ── ZipCrypto key engine ──
class ZipCryptoKeys {
    key0 = 0x12345678;
    key1 = 0x23456789;
    key2 = 0x34567890;
    crc32Table;
    constructor() {
        this.crc32Table = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++)
                c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            this.crc32Table[i] = c >>> 0;
        }
    }
    updateKeys(byte) {
        this.key0 = this.crc32Update(this.key0, byte);
        this.key1 = ((this.key1 + (this.key0 & 0xFF)) >>> 0);
        this.key1 = ((Math.imul(this.key1, 134775813) + 1) >>> 0);
        this.key2 = this.crc32Update(this.key2, (this.key1 >>> 24) & 0xFF);
    }
    crc32Update(crc, byte) {
        return (this.crc32Table[(crc ^ byte) & 0xFF] ^ (crc >>> 8)) >>> 0;
    }
    initPassword(password) {
        this.key0 = 0x12345678;
        this.key1 = 0x23456789;
        this.key2 = 0x34567890;
        for (let i = 0; i < password.length; i++) {
            this.updateKeys(password.charCodeAt(i));
        }
    }
    decryptByte() {
        const temp = (this.key2 | 2) & 0xFFFF;
        return (Math.imul(temp, (temp ^ 1)) >>> 8) & 0xFF;
    }
    decrypt(data) {
        const result = Buffer.alloc(data.length);
        for (let i = 0; i < data.length; i++) {
            const keyByte = this.decryptByte();
            result[i] = data[i] ^ keyByte;
            this.updateKeys(result[i]);
        }
        return result;
    }
}
// ── Parse ZIP local file header ──
function parseZipEntry(buf) {
    // PK\x03\x04 signature
    if (buf[0] !== 0x50 || buf[1] !== 0x4B || buf[2] !== 0x03 || buf[3] !== 0x04)
        return null;
    const flags = buf.readUInt16LE(6);
    const compression = buf.readUInt16LE(8);
    const modTime = buf.readUInt16LE(10);
    const crc32 = buf.readUInt32LE(14);
    const compSize = buf.readUInt32LE(18);
    const fnameLen = buf.readUInt16LE(26);
    const extraLen = buf.readUInt16LE(28);
    const isEncrypted = (flags & 1) !== 0;
    if (!isEncrypted)
        return null;
    const dataOffset = 30 + fnameLen + extraLen;
    // Check for AES extra field (0x9901)
    let aesStrength = 0;
    let offset = 30 + fnameLen;
    const extraEnd = offset + extraLen;
    while (offset + 4 <= extraEnd) {
        const headerId = buf.readUInt16LE(offset);
        const dataSize = buf.readUInt16LE(offset + 2);
        if (headerId === 0x9901 && dataSize >= 7) {
            aesStrength = buf[offset + 8]; // 1=128, 2=192, 3=256
            break;
        }
        offset += 4 + dataSize;
    }
    if (aesStrength > 0) {
        // WinZip AES encryption
        const saltLen = [0, 8, 12, 16][aesStrength];
        const salt = buf.subarray(dataOffset, dataOffset + saltLen);
        const verifier = buf.subarray(dataOffset + saltLen, dataOffset + saltLen + 2);
        const methods = ['', 'aes128', 'aes192', 'aes256'];
        return {
            type: 'zip',
            method: methods[aesStrength],
            salt: salt.toString('base64'),
            verifier: verifier.toString('base64'),
            strength: aesStrength,
        };
    }
    else {
        // ZipCrypto (traditional PKWARE)
        const encHeader = buf.subarray(dataOffset, dataOffset + 12);
        const useCrc = (flags & 8) === 0; // bit 3 = data descriptor, means CRC unavailable
        const checkByte = useCrc ? (crc32 >>> 24) & 0xFF : (modTime >>> 8) & 0xFF;
        return {
            type: 'zip',
            method: 'zipcrypto',
            encHeader: encHeader.toString('base64'),
            checkByte,
            crc32,
        };
    }
}
export const ZipCracker = {
    id: 'zip',
    name: 'ZIP Archive',
    description: 'Encrypted ZIP files (ZipCrypto / WinZip AES)',
    fileExtensions: ['.zip'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(4);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 4, 0);
            fs.closeSync(fd);
            return buf[0] === 0x50 && buf[1] === 0x4B && buf[2] === 0x03 && buf[3] === 0x04;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const fd = fs.openSync(filePath, 'r');
        const buf = Buffer.alloc(4096);
        fs.readSync(fd, buf, 0, 4096, 0);
        fs.closeSync(fd);
        const params = parseZipEntry(buf);
        if (!params)
            throw new Error('Not an encrypted ZIP file or encryption format not recognized');
        return params;
    },
    async tryPassword(password, params) {
        const p = params;
        if (p.method === 'zipcrypto') {
            // ZipCrypto: init keys with password, decrypt 12-byte header, check last byte
            const keys = new ZipCryptoKeys();
            keys.initPassword(password);
            const header = keys.decrypt(Buffer.from(p.encHeader, 'base64'));
            return header[11] === p.checkByte;
        }
        else {
            // WinZip AES: PBKDF2-SHA1
            const saltLen = [0, 8, 12, 16][p.strength];
            const keyLen = [0, 16, 24, 32][p.strength];
            const totalLen = keyLen * 2 + 2;
            const salt = Buffer.from(p.salt, 'base64');
            const verifier = Buffer.from(p.verifier, 'base64');
            const derived = await new Promise((res, rej) => crypto.pbkdf2(password, salt, 1000, totalLen, 'sha1', (e, k) => e ? rej(e) : res(k)));
            // Last 2 bytes = password verification value
            return derived[totalLen - 2] === verifier[0] && derived[totalLen - 1] === verifier[1];
        }
    },
    getInfo(params) {
        const p = params;
        if (p.method === 'zipcrypto') {
            return {
                format: 'ZIP (ZipCrypto)',
                description: 'PKWARE traditional encryption — fast to crack',
                kdf: 'CRC32-based key initialization',
                cipher: 'ZipCrypto stream cipher',
                difficulty: 'easy',
                estimatedSpeed: '~500,000/s',
            };
        }
        const bits = [0, 128, 192, 256][p.strength];
        return {
            format: `ZIP (WinZip AES-${bits})`,
            description: `WinZip AES-${bits} encryption with PBKDF2`,
            kdf: 'PBKDF2-SHA1 × 1,000',
            cipher: `AES-${bits}-CTR + HMAC-SHA1`,
            iterations: 1000,
            difficulty: 'easy',
            estimatedSpeed: '~10,000/s',
        };
    },
};
//# sourceMappingURL=zip.js.map