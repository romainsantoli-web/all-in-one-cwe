/**
 * Bitcoin Core wallet.dat Cracker
 * Format: Berkeley DB with encrypted master key
 * KDF: SHA-512 based (SHA-512(password + salt) × iterations)
 * Cipher: AES-256-CBC
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// Berkeley DB page magic
const BDB_MAGIC = Buffer.from([0x00, 0x05, 0x31, 0x62]); // or 0x61 0x15 0x06 0x00
/**
 * Scan wallet.dat for mkey record.
 * mkey structure: encrypted_key(48) + salt(8) + method(4) + iterations(4)
 */
function findMasterKey(data) {
    // Search for mkey pattern — look for a 48-byte encrypted key followed by
    // reasonable salt and iteration values
    // The "mkey" string is stored as a key in the Berkeley DB
    const mkeyStr = Buffer.from('mkey');
    for (let i = 0; i < data.length - 100; i++) {
        // Look for mkey key name
        if (data[i] === 0x04 && data[i + 1] === 0x6D && data[i + 2] === 0x6B &&
            data[i + 3] === 0x65 && data[i + 4] === 0x79) {
            // Found "mkey" — scan nearby for the encrypted data
            // mkey value: encrypted_key_len(4) + encrypted_key + salt_len(4) + salt + method(4) + iterations(4)
            for (let j = i + 5; j < Math.min(i + 200, data.length - 70); j++) {
                const possibleLen = data.readUInt32LE(j);
                if (possibleLen === 48) {
                    const encKey = data.subarray(j + 4, j + 52);
                    const saltLen = data.readUInt32LE(j + 52);
                    if (saltLen === 8) {
                        const salt = data.subarray(j + 56, j + 64);
                        const method = data.readUInt32LE(j + 64);
                        const iterations = data.readUInt32LE(j + 68);
                        if (method === 0 && iterations > 0 && iterations < 10_000_000) {
                            return { encKey: Buffer.from(encKey), salt: Buffer.from(salt), method, iterations };
                        }
                    }
                }
            }
        }
    }
    // Alternative: scan for plausible encrypted key patterns
    for (let i = 0; i < data.length - 72; i++) {
        if (data.readUInt32LE(i) === 48) {
            const saltLenPos = i + 52;
            if (saltLenPos + 16 > data.length)
                continue;
            const saltLen = data.readUInt32LE(saltLenPos);
            if (saltLen !== 8)
                continue;
            const method = data.readUInt32LE(saltLenPos + 12);
            if (method !== 0)
                continue;
            const iterations = data.readUInt32LE(saltLenPos + 16);
            if (iterations < 1 || iterations > 10_000_000)
                continue;
            return {
                encKey: Buffer.from(data.subarray(i + 4, i + 52)),
                salt: Buffer.from(data.subarray(saltLenPos + 4, saltLenPos + 12)),
                method,
                iterations,
            };
        }
    }
    return null;
}
export const BitcoinCoreCracker = {
    id: 'bitcoin-core',
    name: 'Bitcoin Core',
    description: 'Bitcoin Core wallet.dat (SHA-512 KDF + AES-256-CBC)',
    fileExtensions: ['.dat'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(4096);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 4096, 0);
            fs.closeSync(fd);
            // Check for Berkeley DB magic and "mkey" string
            const data = fs.readFileSync(filePath);
            return data.includes(Buffer.from('mkey')) && data.includes(Buffer.from('\x62\x31\x05\x00'));
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const data = fs.readFileSync(filePath);
        const mkey = findMasterKey(data);
        if (!mkey)
            throw new Error('Could not find encrypted master key in wallet.dat');
        return {
            type: 'bitcoin-core',
            encryptedKey: mkey.encKey.toString('base64'),
            salt: mkey.salt.toString('base64'),
            derivationMethod: mkey.method,
            iterations: mkey.iterations,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.salt, 'base64');
            const encKey = Buffer.from(p.encryptedKey, 'base64');
            // Bitcoin Core KDF: SHA-512(password + salt) repeated iterations times
            let key = Buffer.concat([Buffer.from(password, 'utf-8'), salt]);
            for (let i = 0; i < p.iterations; i++) {
                key = crypto.createHash('sha512').update(key).digest();
            }
            // First 32 bytes = AES key, next 16 bytes = IV
            const aesKey = key.subarray(0, 32);
            const iv = key.subarray(32, 48);
            // Decrypt the encrypted master key
            const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
            decipher.setAutoPadding(false);
            const decrypted = Buffer.concat([decipher.update(encKey), decipher.final()]);
            // The decrypted master key should be 32 bytes of key data + 16 bytes padding
            // Verify PKCS7 padding
            const padByte = decrypted[decrypted.length - 1];
            if (padByte < 1 || padByte > 16)
                return false;
            for (let i = decrypted.length - padByte; i < decrypted.length; i++) {
                if (decrypted[i] !== padByte)
                    return false;
            }
            return true;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'Bitcoin Core wallet.dat',
            description: `Bitcoin Core encrypted wallet — ${p.iterations.toLocaleString()} iterations`,
            kdf: `SHA-512 × ${p.iterations.toLocaleString()}`,
            cipher: 'AES-256-CBC',
            iterations: p.iterations,
            difficulty: p.iterations >= 100000 ? 'medium' : 'easy',
        };
    },
};
//# sourceMappingURL=bitcoin-core.js.map