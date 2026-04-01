/**
 * BitLocker Volume Cracker
 * Format: "-FVE-FS-" header + VMK encrypted with password
 * KDF: SHA-256(UTF-16LE(password)) + key stretching
 * Cipher: AES-CCM (VMK protection)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
const FVE_MAGIC = Buffer.from('-FVE-FS-');
export const BitLockerCracker = {
    id: 'bitlocker',
    name: 'BitLocker',
    description: 'Windows BitLocker encrypted volumes (SHA-256 + AES-CCM)',
    fileExtensions: ['.bek', '.img', '.vhd', '.vhdx'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(512);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 512, 0);
            fs.closeSync(fd);
            // "-FVE-FS-" at offset 3
            return buf.subarray(3, 11).equals(FVE_MAGIC);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const fd = fs.openSync(filePath, 'r');
        const header = Buffer.alloc(65536);
        fs.readSync(fd, header, 0, 65536, 0);
        fs.closeSync(fd);
        // Find FVE metadata block
        // BitLocker stores 3 copies of metadata at offsets in the boot sector
        const metadataOffset1 = Number(header.readBigUInt64LE(176));
        const meta = Buffer.alloc(4096);
        const fd2 = fs.openSync(filePath, 'r');
        fs.readSync(fd2, meta, 0, 4096, metadataOffset1);
        fs.closeSync(fd2);
        // Scan for password-based VMK entry (type 0x2000 = password)
        // VMK entries have: size(2) + type(2) + value_type(2) + data
        let salt = Buffer.alloc(16);
        let encVmk = Buffer.alloc(0);
        let nonce = Buffer.alloc(12);
        let macTag = Buffer.alloc(16);
        // Scan metadata for password protector
        for (let pos = 0; pos < meta.length - 64; pos++) {
            // Look for protector type 0x2000 (password)
            if (meta.readUInt16LE(pos) === 0x2000) {
                // Extract salt (typically 16 bytes after the entry header)
                const entryStart = pos - 4;
                if (entryStart >= 0) {
                    salt = meta.subarray(entryStart + 28, entryStart + 44);
                    nonce = meta.subarray(entryStart + 44, entryStart + 56);
                    macTag = meta.subarray(entryStart + 56, entryStart + 72);
                    encVmk = meta.subarray(entryStart + 72, entryStart + 72 + 44);
                    break;
                }
            }
        }
        return {
            type: 'bitlocker',
            salt: salt.toString('base64'),
            encryptedVmk: encVmk.toString('base64'),
            nonce: nonce.toString('base64'),
            macTag: macTag.toString('base64'),
            iterations: 1_048_576,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            // Step 1: SHA-256(UTF-16LE(password))
            const passUtf16 = Buffer.from(password, 'utf-16le');
            let hash = crypto.createHash('sha256').update(passUtf16).digest();
            // Step 2: Key stretching — SHA-256(hash + salt + iteration_LE64) × iterations
            const salt = Buffer.from(p.salt, 'base64');
            for (let i = 0; i < p.iterations; i++) {
                const iterBuf = Buffer.alloc(8);
                iterBuf.writeUInt32LE(i, 0);
                hash = crypto.createHash('sha256').update(hash).update(salt).update(iterBuf).digest();
            }
            // Step 3: AES-CCM decrypt VMK
            const nonce = Buffer.from(p.nonce, 'base64');
            const encVmk = Buffer.from(p.encryptedVmk, 'base64');
            const macTag = Buffer.from(p.macTag, 'base64');
            if (encVmk.length < 4 || nonce.length < 12)
                return false;
            const decipher = crypto.createDecipheriv('aes-256-ccm', hash, nonce, {
                authTagLength: 16,
            });
            decipher.setAuthTag(macTag);
            const decrypted = decipher.update(encVmk);
            decipher.final();
            return true; // If final() doesn't throw, auth tag verified
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'BitLocker',
            description: `Windows BitLocker — ${p.iterations.toLocaleString()} stretch iterations`,
            kdf: `SHA-256 + stretch × ${p.iterations.toLocaleString()}`,
            cipher: 'AES-256-CCM',
            iterations: p.iterations,
            difficulty: 'extreme',
            estimatedSpeed: '~0.5-2/s',
        };
    },
};
//# sourceMappingURL=bitlocker.js.map