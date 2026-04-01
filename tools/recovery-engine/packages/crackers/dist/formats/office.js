/**
 * Microsoft Office Cracker (Office 2010/2013/2016/2019/2021+)
 * Format: OOXML (ZIP-based) with EncryptionInfo + EncryptedPackage
 * Crypto: PBKDF2-SHA512 + AES-256-CBC (Office 2013+)
 *         PBKDF2-SHA1 + AES-128-CBC (Office 2010)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// OLE2 magic (legacy .doc/.xls)
const OLE2_MAGIC = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
// ZIP magic (OOXML .docx/.xlsx)
const ZIP_MAGIC = Buffer.from([0x50, 0x4B, 0x03, 0x04]);
/**
 * Parse EncryptionInfo from Office OOXML file.
 * The EncryptionInfo stream is inside the ZIP at EncryptionInfo entry,
 * or in OLE2 at 'EncryptionInfo' stream.
 */
function parseEncryptionInfo(buf) {
    // Look for XML-based EncryptionInfo (OOXML Agile)
    const xmlStr = buf.toString('utf-8');
    // Agile encryption (Office 2010+)
    const saltMatch = xmlStr.match(/saltValue="([^"]+)"/);
    const spinMatch = xmlStr.match(/spinCount="(\d+)"/);
    const hashMatch = xmlStr.match(/hashAlgorithm="([^"]+)"/);
    const kbMatch = xmlStr.match(/keyBits="(\d+)"/);
    const blockMatch = xmlStr.match(/blockSize="(\d+)"/);
    const verifierInputMatch = xmlStr.match(/encryptedVerifierHashInput="([^"]+)"/);
    const verifierValueMatch = xmlStr.match(/encryptedVerifierHashValue="([^"]+)"/);
    if (saltMatch && spinMatch && verifierInputMatch && verifierValueMatch) {
        const hashAlg = hashMatch?.[1] || 'SHA512';
        const keyBits = parseInt(kbMatch?.[1] || '256');
        return {
            version: keyBits >= 256 ? '2013+' : '2010',
            hashAlgorithm: hashAlg,
            keyBits,
            saltValue: saltMatch[1],
            spinCount: parseInt(spinMatch[1]),
            encVerifierHashInput: verifierInputMatch[1],
            encVerifierHashValue: verifierValueMatch[1],
            blockSize: parseInt(blockMatch?.[1] || '16'),
        };
    }
    return null;
}
export const OfficeCracker = {
    id: 'office',
    name: 'Microsoft Office',
    description: 'Password-protected Office documents (PBKDF2 + AES)',
    fileExtensions: ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(8);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 8, 0);
            fs.closeSync(fd);
            // OOXML (ZIP) or OLE2
            if (buf.subarray(0, 4).equals(ZIP_MAGIC) || buf.subarray(0, 8).equals(OLE2_MAGIC)) {
                // Quick check: scan for EncryptionInfo marker
                const fullBuf = fs.readFileSync(filePath);
                return fullBuf.includes(Buffer.from('EncryptionInfo')) ||
                    fullBuf.includes(Buffer.from('encryptedVerifierHash'));
            }
            return false;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const buf = fs.readFileSync(filePath);
        // For OOXML, find EncryptionInfo stream inside ZIP
        // Scan for XML encryption info
        const info = parseEncryptionInfo(buf);
        if (!info)
            throw new Error('Could not parse Office encryption info');
        return {
            type: 'office',
            version: info.version,
            hashAlgorithm: info.hashAlgorithm,
            keyBits: info.keyBits,
            saltValue: info.saltValue,
            spinCount: info.spinCount,
            encVerifierHashInput: info.encVerifierHashInput,
            encVerifierHashValue: info.encVerifierHashValue,
            blockSize: info.blockSize,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.saltValue, 'base64');
            const hashAlg = p.hashAlgorithm.toLowerCase().replace('-', '');
            const keyLen = p.keyBits / 8;
            // Step 1: PBKDF2-like key derivation (Office-specific)
            // H0 = hash(salt + UTF-16LE(password))
            const passUtf16 = Buffer.from(password, 'utf-16le');
            let H = crypto.createHash(hashAlg).update(salt).update(passUtf16).digest();
            // Iterate: H_n = hash(iterator_LE32 + H_{n-1})
            for (let i = 0; i < p.spinCount; i++) {
                const iterBuf = Buffer.alloc(4);
                iterBuf.writeUInt32LE(i);
                H = crypto.createHash(hashAlg).update(iterBuf).update(H).digest();
            }
            // Derive encryption key for verifier
            // cbRequiredKeyLength = keyBits / 8, cbHash = hash output length
            const verifierInputBlockKey = Buffer.from([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79]);
            const verifierValueBlockKey = Buffer.from([0xD7, 0xAA, 0x0F, 0x1D, 0x96, 0x15, 0x87, 0x48]);
            const inputKeyDerived = crypto.createHash(hashAlg).update(H).update(verifierInputBlockKey).digest();
            const valueKeyDerived = crypto.createHash(hashAlg).update(H).update(verifierValueBlockKey).digest();
            const inputKey = inputKeyDerived.subarray(0, keyLen);
            const valueKey = valueKeyDerived.subarray(0, keyLen);
            // Decrypt verifier hash input
            const encInput = Buffer.from(p.encVerifierHashInput, 'base64');
            const encValue = Buffer.from(p.encVerifierHashValue, 'base64');
            const iv = salt; // IV = salt for Office Agile
            const decipher1 = crypto.createDecipheriv(`aes-${p.keyBits}-cbc`, inputKey, iv.subarray(0, p.blockSize));
            decipher1.setAutoPadding(false);
            const decInput = Buffer.concat([decipher1.update(encInput), decipher1.final()]);
            const decipher2 = crypto.createDecipheriv(`aes-${p.keyBits}-cbc`, valueKey, iv.subarray(0, p.blockSize));
            decipher2.setAutoPadding(false);
            const decValue = Buffer.concat([decipher2.update(encValue), decipher2.final()]);
            // Verify: hash(decryptedInput) = decryptedValue (truncated to hash length)
            const hashLen = crypto.createHash(hashAlg).update(Buffer.alloc(0)).digest().length;
            const computed = crypto.createHash(hashAlg).update(decInput).digest();
            return computed.equals(decValue.subarray(0, hashLen));
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: `Microsoft Office ${p.version}`,
            description: `Office encrypted document — ${p.spinCount.toLocaleString()} iterations`,
            kdf: `PBKDF2-${p.hashAlgorithm} × ${p.spinCount.toLocaleString()}`,
            cipher: `AES-${p.keyBits}-CBC`,
            iterations: p.spinCount,
            difficulty: p.spinCount >= 100000 ? 'medium' : 'easy',
        };
    },
};
//# sourceMappingURL=office.js.map