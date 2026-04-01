/**
 * KeePass (.kdbx) Cracker
 * KDBX3: AES-KDF + AES-256-CBC (or Twofish/ChaCha20)
 * KDBX4: Argon2d/2id or AES-KDF + AES-256-CBC/ChaCha20
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
const KDBX3_SIG1 = 0x9AA2D903;
const KDBX4_SIG1 = 0x9AA2D903;
const KDBX_SIG2 = 0xB54BFB67;
// Header field IDs
const HEADER_FIELD = {
    END: 0, CIPHER_ID: 2, COMPRESSION: 3, MASTER_SEED: 4,
    TRANSFORM_SEED: 5, TRANSFORM_ROUNDS: 6, ENCRYPTION_IV: 7,
    PROTECTED_STREAM_KEY: 8, STREAM_START_BYTES: 9,
    INNER_RANDOM_STREAM_ID: 10, KDF_PARAMETERS: 11,
};
// KDF UUIDs
const AES_KDF_UUID = Buffer.from([0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA]);
const ARGON2D_UUID = Buffer.from([0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C]);
const ARGON2ID_UUID = Buffer.from([0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6]);
function parseVariantMap(buf) {
    const map = new Map();
    let pos = 2; // skip version
    while (pos < buf.length) {
        const type = buf[pos];
        pos++;
        if (type === 0)
            break;
        const nameLen = buf.readInt32LE(pos);
        pos += 4;
        const name = buf.subarray(pos, pos + nameLen).toString('utf-8');
        pos += nameLen;
        const valLen = buf.readInt32LE(pos);
        pos += 4;
        const val = buf.subarray(pos, pos + valLen);
        pos += valLen;
        map.set(name, Buffer.from(val));
    }
    return map;
}
export const KeePassCracker = {
    id: 'keepass',
    name: 'KeePass',
    description: 'KeePass password database (.kdbx) — AES-KDF / Argon2',
    fileExtensions: ['.kdbx'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(8);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 8, 0);
            fs.closeSync(fd);
            const sig1 = buf.readUInt32LE(0);
            const sig2 = buf.readUInt32LE(4);
            return sig1 === KDBX3_SIG1 && sig2 === KDBX_SIG2;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const data = fs.readFileSync(filePath);
        const sig1 = data.readUInt32LE(0);
        const sig2 = data.readUInt32LE(4);
        if (sig1 !== KDBX3_SIG1 || sig2 !== KDBX_SIG2) {
            throw new Error('Not a KDBX file');
        }
        const minorVersion = data.readUInt16LE(8);
        const majorVersion = data.readUInt16LE(10);
        const isV4 = majorVersion >= 4;
        const params = {
            type: 'keepass',
            kdbxVersion: isV4 ? 4 : 3,
        };
        // Parse header fields
        let pos = 12;
        const headerStart = 0;
        while (pos < data.length) {
            const fieldId = data[pos];
            pos++;
            let fieldSize;
            if (isV4) {
                fieldSize = data.readInt32LE(pos);
                pos += 4;
            }
            else {
                fieldSize = data.readUInt16LE(pos);
                pos += 2;
            }
            const fieldData = data.subarray(pos, pos + fieldSize);
            pos += fieldSize;
            switch (fieldId) {
                case HEADER_FIELD.MASTER_SEED:
                    params.masterSeed = fieldData.toString('base64');
                    break;
                case HEADER_FIELD.TRANSFORM_SEED:
                    params.transformSeed = fieldData.toString('base64');
                    break;
                case HEADER_FIELD.TRANSFORM_ROUNDS:
                    params.transformRounds = Number(fieldData.readBigUInt64LE(0));
                    params.kdfType = 'aes-kdf';
                    break;
                case HEADER_FIELD.ENCRYPTION_IV:
                    params.encryptionIV = fieldData.toString('base64');
                    break;
                case HEADER_FIELD.STREAM_START_BYTES:
                    params.streamStartBytes = fieldData.toString('base64');
                    break;
                case HEADER_FIELD.KDF_PARAMETERS: {
                    const vm = parseVariantMap(fieldData);
                    const uuid = vm.get('$UUID');
                    if (uuid?.equals(AES_KDF_UUID)) {
                        params.kdfType = 'aes-kdf';
                        const rounds = vm.get('R');
                        if (rounds)
                            params.transformRounds = Number(rounds.readBigUInt64LE(0));
                        const seed = vm.get('S');
                        if (seed)
                            params.transformSeed = seed.toString('base64');
                    }
                    else if (uuid?.equals(ARGON2D_UUID) || uuid?.equals(ARGON2ID_UUID)) {
                        params.kdfType = uuid.equals(ARGON2D_UUID) ? 'argon2d' : 'argon2id';
                        const salt = vm.get('S');
                        if (salt)
                            params.argon2Salt = salt.toString('base64');
                        const iter = vm.get('I');
                        if (iter)
                            params.argon2Iterations = Number(iter.readBigUInt64LE(0));
                        const mem = vm.get('M');
                        if (mem)
                            params.argon2Memory = Number(mem.readBigUInt64LE(0));
                        const par = vm.get('P');
                        if (par)
                            params.argon2Parallelism = par.readUInt32LE(0);
                        const ver = vm.get('V');
                        if (ver)
                            params.argon2Version = ver.readUInt32LE(0);
                    }
                    break;
                }
                case HEADER_FIELD.END:
                    break;
            }
            if (fieldId === HEADER_FIELD.END)
                break;
        }
        if (isV4) {
            // KDBX4: SHA-256 of header + HMAC for verification
            const headerBytes = data.subarray(headerStart, pos);
            params.headerSha256 = crypto.createHash('sha256').update(headerBytes).digest().toString('base64');
            // HMAC block is right after header: SHA-256(32) + HMAC-SHA-256(32)
            if (pos + 64 <= data.length) {
                params.headerHmac = data.subarray(pos + 32, pos + 64).toString('base64');
                params.headerBytes = headerBytes.toString('base64');
            }
        }
        else {
            // KDBX3: store first 64 bytes of encrypted payload for streamStartBytes verification
            if (pos + 64 <= data.length) {
                params.encryptedPayload = data.subarray(pos, pos + 64).toString('base64');
            }
        }
        return params;
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            // Step 1: Composite key = SHA-256(SHA-256(password))
            const passHash = crypto.createHash('sha256').update(password, 'utf-8').digest();
            const compositeKey = crypto.createHash('sha256').update(passHash).digest();
            // Step 2: Transform key via KDF
            let transformedKey;
            if (p.kdfType === 'aes-kdf') {
                // AES-ECB encrypt compositeKey transformRounds times
                const seed = Buffer.from(p.transformSeed, 'base64');
                let key = Buffer.from(compositeKey);
                for (let i = 0; i < (p.transformRounds || 6000); i++) {
                    const cipher = crypto.createCipheriv('aes-256-ecb', seed, null);
                    cipher.setAutoPadding(false);
                    key = Buffer.concat([cipher.update(key), cipher.final()]);
                }
                transformedKey = crypto.createHash('sha256').update(key).digest();
            }
            else {
                // Argon2d or Argon2id
                try {
                    const argon2 = await import('argon2');
                    const salt = Buffer.from(p.argon2Salt, 'base64');
                    const hash = await argon2.hash(compositeKey, {
                        salt,
                        type: p.kdfType === 'argon2d' ? 0 : 2,
                        timeCost: p.argon2Iterations || 2,
                        memoryCost: (p.argon2Memory || 67108864) / 1024, // bytes to KB
                        parallelism: p.argon2Parallelism || 2,
                        hashLength: 32,
                        raw: true,
                        version: p.argon2Version || 0x13,
                    });
                    transformedKey = hash;
                }
                catch {
                    throw new Error('argon2 package required for KeePass Argon2 KDF — run: npm install argon2');
                }
            }
            // Step 3: Master key = SHA-256(masterSeed + transformedKey)
            const masterSeed = Buffer.from(p.masterSeed, 'base64');
            const masterKey = crypto.createHash('sha256')
                .update(masterSeed).update(transformedKey).digest();
            if (p.kdbxVersion === 4 && p.headerHmac && p.headerBytes) {
                // KDBX4: Verify HMAC of header
                const hmacKey = crypto.createHash('sha512')
                    .update(masterSeed).update(transformedKey).update(Buffer.from([0x01])).digest();
                // Block HMAC key derivation
                const blockIndex = Buffer.alloc(8); // block 0xFFFFFFFFFFFFFFFF for header
                blockIndex.fill(0xFF);
                const blockHmacKey = crypto.createHash('sha512')
                    .update(blockIndex).update(hmacKey).digest();
                const headerBytes = Buffer.from(p.headerBytes, 'base64');
                const computed = crypto.createHmac('sha256', blockHmacKey).update(headerBytes).digest();
                return computed.toString('base64') === p.headerHmac;
            }
            else if (p.streamStartBytes && p.encryptedPayload) {
                // KDBX3: Decrypt first block and compare to streamStartBytes
                const iv = Buffer.from(p.encryptionIV, 'base64');
                const encData = Buffer.from(p.encryptedPayload, 'base64');
                const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
                decipher.setAutoPadding(false);
                const dec = decipher.update(encData);
                const streamStart = Buffer.from(p.streamStartBytes, 'base64');
                // First 32 bytes of decrypted data must match streamStartBytes
                return dec.subarray(0, streamStart.length).equals(streamStart);
            }
            return false;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        if (p.kdfType === 'argon2d' || p.kdfType === 'argon2id') {
            const mem = ((p.argon2Memory || 0) / 1024 / 1024).toFixed(0);
            return {
                format: `KeePass KDBX${p.kdbxVersion} (${p.kdfType})`,
                description: `KeePass database — Argon2 (${mem}MB, ${p.argon2Iterations} iter)`,
                kdf: `${p.kdfType} (mem=${mem}MB, t=${p.argon2Iterations}, p=${p.argon2Parallelism})`,
                cipher: 'AES-256-CBC',
                iterations: p.argon2Iterations,
                difficulty: 'hard',
                estimatedSpeed: '~5-20/s',
            };
        }
        return {
            format: `KeePass KDBX${p.kdbxVersion} (AES-KDF)`,
            description: `KeePass database — ${(p.transformRounds || 0).toLocaleString()} AES rounds`,
            kdf: `AES-KDF × ${(p.transformRounds || 0).toLocaleString()}`,
            cipher: 'AES-256-CBC',
            iterations: p.transformRounds,
            difficulty: (p.transformRounds || 0) > 1_000_000 ? 'hard' : 'medium',
        };
    },
};
//# sourceMappingURL=keepass.js.map