/**
 * PDF Password Cracker
 * Supports: PDF 1.1-2.0 encryption
 * - R2-R4: RC4 / AES-128 (MD5-based key derivation)
 * - R5-R6: AES-256 (SHA-256/384/512 based — PDF 2.0)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// PDF password padding string (32 bytes)
const PDF_PADDING = Buffer.from([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4B, 0x49, 0x43, 0x4B, 0x53, 0x2E,
    0x77, 0x6F, 0x72, 0x63, 0x65, 0x73, 0x74, 0x65,
    0x72, 0x73, 0x68, 0x69, 0x72, 0x65, 0x2E, 0x2E,
]);
function padPassword(password) {
    const pass = Buffer.from(password, 'latin1');
    const padded = Buffer.alloc(32);
    pass.copy(padded, 0, 0, Math.min(pass.length, 32));
    if (pass.length < 32)
        PDF_PADDING.copy(padded, pass.length, 0, 32 - pass.length);
    return padded;
}
/** Extract hex/string value from PDF dictionary */
function extractPdfValue(content, key) {
    // Match /Key <hex> or /Key (literal) or /Key value
    const hexMatch = content.match(new RegExp(`/${key}\\s*<([0-9a-fA-F]+)>`));
    if (hexMatch)
        return hexMatch[1];
    const litMatch = content.match(new RegExp(`/${key}\\s*\\(([^)]*)`));
    if (litMatch)
        return litMatch[1];
    return null;
}
function extractPdfNumber(content, key) {
    const match = content.match(new RegExp(`/${key}\\s+(-?\\d+)`));
    return match ? parseInt(match[1]) : null;
}
function hexToBuffer(hex) {
    return Buffer.from(hex, 'hex');
}
export const PdfCracker = {
    id: 'pdf',
    name: 'PDF Document',
    description: 'Password-protected PDF files (RC4 / AES-128 / AES-256)',
    fileExtensions: ['.pdf'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(5);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 5, 0);
            fs.closeSync(fd);
            return buf.toString('ascii') === '%PDF-';
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        // Read the whole file — PDFs have trailers at the end
        const content = fs.readFileSync(filePath, 'latin1');
        // Find /Encrypt dictionary
        if (!content.includes('/Encrypt')) {
            throw new Error('PDF is not encrypted');
        }
        // Extract encryption parameters
        const R = extractPdfNumber(content, 'R') ?? 0;
        const V = extractPdfNumber(content, 'V') ?? 0;
        const P = extractPdfNumber(content, 'P') ?? 0;
        const length = extractPdfNumber(content, 'Length') ?? (V >= 5 ? 256 : V >= 4 ? 128 : 40);
        const O = extractPdfValue(content, 'O');
        const U = extractPdfValue(content, 'U');
        const OE = extractPdfValue(content, 'OE');
        const UE = extractPdfValue(content, 'UE');
        if (!O || !U)
            throw new Error('PDF: Missing /O or /U values');
        // Extract file ID
        let fileId = '';
        const idMatch = content.match(/\/ID\s*\[\s*<([0-9a-fA-F]+)>/);
        if (idMatch)
            fileId = idMatch[1];
        const encryptMetadata = !content.includes('/EncryptMetadata false');
        return {
            type: 'pdf',
            revision: R,
            version: V,
            length,
            permissions: P,
            ownerPassword: hexToBuffer(O).toString('base64'),
            userPassword: hexToBuffer(U).toString('base64'),
            ownerEncrypt: OE ? hexToBuffer(OE).toString('base64') : undefined,
            userEncrypt: UE ? hexToBuffer(UE).toString('base64') : undefined,
            fileId: fileId ? hexToBuffer(fileId).toString('base64') : '',
            encryptMetadata,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        if (p.revision >= 5) {
            // PDF 2.0 (R=5 or R=6): SHA-256 based
            return tryPasswordR6(password, p);
        }
        else if (p.revision >= 3) {
            // R3/R4: MD5-based
            return tryPasswordR3R4(password, p);
        }
        else {
            // R2: simple MD5
            return tryPasswordR2(password, p);
        }
    },
    getInfo(params) {
        const p = params;
        if (p.revision >= 5) {
            return {
                format: `PDF 2.0 (R${p.revision})`,
                description: 'PDF AES-256 encryption (SHA-256/384/512 based)',
                kdf: 'SHA-256 + SHA-384/512 validation',
                cipher: 'AES-256-CBC',
                difficulty: 'medium',
                estimatedSpeed: '~50,000/s',
            };
        }
        return {
            format: `PDF (R${p.revision}, V${p.version})`,
            description: `PDF encryption — ${p.length}-bit key, MD5-based`,
            kdf: 'MD5 (50× for R3+)',
            cipher: p.version >= 4 ? 'AES-128-CBC' : `RC4-${p.length}`,
            difficulty: 'easy',
            estimatedSpeed: '~200,000/s',
        };
    },
};
// ── R6 (PDF 2.0) password check ──
function tryPasswordR6(password, p) {
    const U = Buffer.from(p.userPassword, 'base64');
    const passBytes = Buffer.from(password, 'utf-8').subarray(0, 127);
    // U structure (48 bytes): hash(32) + validation_salt(8) + key_salt(8)
    if (U.length < 48)
        return false;
    const uHash = U.subarray(0, 32);
    const uValidSalt = U.subarray(32, 40);
    // R6 uses iterative SHA-256/384/512 algorithm (Algorithm 2.B from ISO 32000-2)
    // Simplified R5 check: SHA-256(password + validation_salt)
    if (p.revision === 5) {
        const computed = crypto.createHash('sha256')
            .update(passBytes).update(uValidSalt).digest();
        return computed.equals(uHash);
    }
    // R6: Algorithm 2.B (iterative mixing)
    const hash = computeHashR6(passBytes, uValidSalt, Buffer.alloc(0));
    return hash.subarray(0, 32).equals(uHash);
}
/** Algorithm 2.B from ISO 32000-2 */
function computeHashR6(pass, salt, userKey) {
    let K = crypto.createHash('sha256').update(pass).update(salt).update(userKey).digest();
    let round = 0;
    let lastE = 0;
    while (true) {
        // K1 = repeat(password + K + userKey) × 64
        const K1block = Buffer.concat([pass, K, userKey]);
        const K1 = Buffer.alloc(K1block.length * 64);
        for (let i = 0; i < 64; i++)
            K1block.copy(K1, i * K1block.length);
        // E = AES-128-CBC(K[0:16], K[16:32], K1)
        const aesKey = K.subarray(0, 16);
        const aesIv = K.subarray(16, 32);
        const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, aesIv);
        cipher.setAutoPadding(false);
        const E = Buffer.concat([cipher.update(K1), cipher.final()]);
        // Pick hash based on sum of first 16 bytes of E mod 3
        let sum = 0;
        for (let i = 0; i < 16; i++)
            sum += E[i];
        const hashFn = ['sha256', 'sha384', 'sha512'][sum % 3];
        K = crypto.createHash(hashFn).update(E).digest();
        lastE = E[E.length - 1];
        round++;
        if (round >= 64 && lastE <= round - 32)
            break;
    }
    return K.subarray(0, 32);
}
// ── R3/R4 password check ──
function tryPasswordR3R4(password, p) {
    const padded = padPassword(password);
    const fileId = Buffer.from(p.fileId, 'base64');
    const U = Buffer.from(p.userPassword, 'base64');
    const keyLen = p.length / 8;
    // Compute encryption key
    const md5 = crypto.createHash('md5');
    md5.update(padded);
    md5.update(Buffer.from(p.ownerPassword, 'base64'));
    const pBuf = Buffer.alloc(4);
    pBuf.writeInt32LE(p.permissions);
    md5.update(pBuf);
    md5.update(fileId);
    if (!p.encryptMetadata && p.version >= 4) {
        md5.update(Buffer.from([0xFF, 0xFF, 0xFF, 0xFF]));
    }
    let key = md5.digest().subarray(0, keyLen);
    // MD5 50 iterations for R3+
    for (let i = 0; i < 50; i++) {
        key = crypto.createHash('md5').update(key.subarray(0, keyLen)).digest().subarray(0, keyLen);
    }
    // Compute expected U value (R3/R4): MD5(padding + fileId) then RC4 × 20
    const uHash = crypto.createHash('md5').update(PDF_PADDING).update(fileId).digest();
    let result = Buffer.from(uHash);
    for (let i = 0; i < 20; i++) {
        const xorKey = Buffer.alloc(keyLen);
        for (let j = 0; j < keyLen; j++)
            xorKey[j] = key[j] ^ i;
        // RC4 encrypt
        const rc4 = createRC4(xorKey);
        result = Buffer.from(rc4(result));
    }
    // Compare first 16 bytes
    return result.subarray(0, 16).equals(U.subarray(0, 16));
}
// ── R2 password check ──
function tryPasswordR2(password, p) {
    const padded = padPassword(password);
    const fileId = Buffer.from(p.fileId, 'base64');
    const U = Buffer.from(p.userPassword, 'base64');
    const md5 = crypto.createHash('md5');
    md5.update(padded);
    md5.update(Buffer.from(p.ownerPassword, 'base64'));
    const pBuf = Buffer.alloc(4);
    pBuf.writeInt32LE(p.permissions);
    md5.update(pBuf);
    md5.update(fileId);
    const key = md5.digest().subarray(0, 5); // 40-bit key for R2
    // U = RC4(padding, key)
    const rc4 = createRC4(key);
    const computed = rc4(Buffer.from(PDF_PADDING));
    return computed.equals(U);
}
// ── Simple RC4 implementation ──
function createRC4(key) {
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++)
        S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key.length]) & 0xFF;
        [S[i], S[j]] = [S[j], S[i]];
    }
    return (data) => {
        const out = Buffer.alloc(data.length);
        let i2 = 0, j2 = 0;
        const S2 = Uint8Array.from(S);
        for (let k = 0; k < data.length; k++) {
            i2 = (i2 + 1) & 0xFF;
            j2 = (j2 + S2[i2]) & 0xFF;
            [S2[i2], S2[j2]] = [S2[j2], S2[i2]];
            out[k] = data[k] ^ S2[(S2[i2] + S2[j2]) & 0xFF];
        }
        return out;
    };
}
//# sourceMappingURL=pdf.js.map