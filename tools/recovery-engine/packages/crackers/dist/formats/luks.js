/**
 * LUKS (Linux Unified Key Setup) Cracker
 * LUKS1: PBKDF2 + AES-XTS
 * LUKS2: Argon2i/Argon2id + AES-XTS
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
const LUKS_MAGIC = Buffer.from([0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE]); // "LUKS\xBA\xBE"
/** LUKS anti-forensic diffuse function: hash each 32/64-byte block with its index */
function hashDiffuse(block, hashSpec) {
    const result = Buffer.alloc(block.length);
    const hashLen = hashSpec.includes('512') ? 64 : 32;
    const blocks = Math.ceil(block.length / hashLen);
    for (let i = 0; i < blocks; i++) {
        const start = i * hashLen;
        const len = Math.min(hashLen, block.length - start);
        const input = Buffer.alloc(4 + len);
        input.writeUInt32BE(i, 0);
        block.copy(input, 4, start, start + len);
        const digest = crypto.createHash(hashSpec).update(input).digest();
        digest.copy(result, start, 0, len);
    }
    return result;
}
/** LUKS anti-forensic merge: XOR stripes with hash diffusion between each */
function afMerge(data, keyBytes, stripes, hashSpec) {
    let d = Buffer.alloc(keyBytes);
    for (let i = 0; i < stripes - 1; i++) {
        const stripe = data.subarray(i * keyBytes, (i + 1) * keyBytes);
        for (let j = 0; j < keyBytes; j++)
            d[j] ^= stripe[j] || 0;
        d = hashDiffuse(d, hashSpec);
    }
    // Final XOR with last stripe (no diffusion after)
    const lastStripe = data.subarray((stripes - 1) * keyBytes, stripes * keyBytes);
    for (let j = 0; j < keyBytes; j++)
        d[j] ^= lastStripe[j] || 0;
    return d;
}
export const LuksCracker = {
    id: 'luks',
    name: 'LUKS',
    description: 'Linux LUKS encrypted volumes (PBKDF2/Argon2 + AES)',
    fileExtensions: ['.img', '.luks', '.raw'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(6);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 6, 0);
            fs.closeSync(fd);
            return buf.equals(LUKS_MAGIC);
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const fd = fs.openSync(filePath, 'r');
        const header = Buffer.alloc(4096);
        fs.readSync(fd, header, 0, 4096, 0);
        fs.closeSync(fd);
        if (!header.subarray(0, 6).equals(LUKS_MAGIC)) {
            throw new Error('Not a LUKS volume');
        }
        const version = header.readUInt16BE(6);
        if (version === 1) {
            // LUKS1 header
            const cipherName = header.subarray(8, 40).toString('ascii').replace(/\0/g, '');
            const cipherMode = header.subarray(40, 72).toString('ascii').replace(/\0/g, '');
            const hashSpec = header.subarray(72, 104).toString('ascii').replace(/\0/g, '');
            const keyBytes = header.readUInt32BE(108);
            const mkDigest = header.subarray(112, 132);
            const mkDigestSalt = header.subarray(132, 164);
            const mkDigestIter = header.readUInt32BE(164);
            // Find first active key slot (starts at offset 208, each slot is 48 bytes)
            for (let i = 0; i < 8; i++) {
                const slotOffset = 208 + i * 48;
                const active = header.readUInt32BE(slotOffset);
                if (active === 0x00AC71F3) { // LUKS_KEY_ENABLED
                    const iterations = header.readUInt32BE(slotOffset + 4);
                    const salt = header.subarray(slotOffset + 8, slotOffset + 40);
                    const keyMaterialOffset = header.readUInt32BE(slotOffset + 40);
                    const stripes = header.readUInt32BE(slotOffset + 44);
                    // Read key material
                    const kmSize = keyBytes * stripes;
                    const kmBuf = Buffer.alloc(kmSize);
                    const fd2 = fs.openSync(filePath, 'r');
                    fs.readSync(fd2, kmBuf, 0, kmSize, keyMaterialOffset * 512);
                    fs.closeSync(fd2);
                    return {
                        type: 'luks', version: 1,
                        cipherName, cipherMode, hashSpec, keyBytes,
                        slotSalt: salt.toString('base64'),
                        slotIterations: iterations,
                        slotKeyMaterial: kmBuf.toString('base64'),
                        slotStripes: stripes,
                        mkDigest: mkDigest.toString('base64'),
                        mkDigestSalt: mkDigestSalt.toString('base64'),
                        mkDigestIter,
                    };
                }
            }
            throw new Error('No active LUKS1 key slots found');
        }
        // LUKS2: JSON config area
        const jsonArea = Buffer.alloc(16384);
        const fd2 = fs.openSync(filePath, 'r');
        fs.readSync(fd2, jsonArea, 0, 16384, 4096);
        fs.closeSync(fd2);
        const jsonStr = jsonArea.toString('utf-8').replace(/\0+$/, '');
        const config = JSON.parse(jsonStr);
        const keyslots = config.keyslots || {};
        const slot = Object.values(keyslots)[0];
        if (!slot)
            throw new Error('No LUKS2 key slots found');
        // Extract area info for key material
        const area = slot.area || {};
        const areaOffset = parseInt(area.offset || '0');
        const areaSize = parseInt(area.size || '0');
        // Read key material from disk at area offset
        let slotKeyMaterial = '';
        if (areaOffset > 0 && areaSize > 0) {
            const fd3 = fs.openSync(filePath, 'r');
            const kmBuf = Buffer.alloc(areaSize);
            fs.readSync(fd3, kmBuf, 0, areaSize, areaOffset);
            fs.closeSync(fd3);
            slotKeyMaterial = kmBuf.toString('base64');
        }
        // Extract digest for master key verification
        const digests = config.digests || {};
        const digest = Object.values(digests)[0];
        const keyBytes = slot.key_size || (config.segments?.['0']?.key_size
            ? parseInt(config.segments['0'].key_size) : 64);
        return {
            type: 'luks', version: 2,
            cipherName: config.segments?.['0']?.encryption?.split('-')[0] || 'aes',
            cipherMode: area.encryption || config.segments?.['0']?.encryption || 'aes-xts-plain64',
            hashSpec: digest?.hash || slot.kdf?.hash || 'sha256',
            keyBytes,
            slotSalt: Buffer.from(slot.kdf?.salt || '', 'base64').toString('base64'),
            slotIterations: slot.kdf?.time || slot.kdf?.iterations || 4,
            slotKeyMaterial,
            slotStripes: slot.af?.stripes || 4000,
            mkDigest: digest?.digest ? Buffer.from(digest.digest, 'base64').toString('base64') : '',
            mkDigestSalt: digest?.salt ? Buffer.from(digest.salt, 'base64').toString('base64') : '',
            mkDigestIter: digest?.iterations || 0,
            argon2Type: slot.kdf?.type === 'argon2id' ? 'argon2id' : 'argon2i',
            argon2Memory: slot.kdf?.memory || 1048576,
            argon2Cpus: slot.kdf?.cpus || 4,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            const salt = Buffer.from(p.slotSalt, 'base64');
            let derivedKey;
            if (p.version === 2 && p.argon2Type) {
                const argon2 = await import('argon2');
                derivedKey = await argon2.hash(password, {
                    salt,
                    type: p.argon2Type === 'argon2id' ? 2 : 1,
                    timeCost: p.slotIterations,
                    memoryCost: (p.argon2Memory || 1048576),
                    parallelism: p.argon2Cpus || 4,
                    hashLength: p.keyBytes,
                    raw: true,
                });
            }
            else {
                derivedKey = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.slotIterations, p.keyBytes, p.hashSpec, (e, k) => e ? rej(e) : res(k)));
            }
            if ((p.version === 1 || p.version === 2) && p.slotKeyMaterial && p.mkDigest) {
                // Decrypt key material from slot area
                const km = Buffer.from(p.slotKeyMaterial, 'base64');
                const decKm = Buffer.alloc(km.length);
                const sectorSize = 512;
                const cipherMode = p.cipherMode || 'aes-xts-plain64';
                if (cipherMode.includes('xts') && derivedKey.length >= 64) {
                    // AES-XTS: decrypt sector by sector with sector-number tweak
                    for (let sector = 0; sector < Math.ceil(km.length / sectorSize); sector++) {
                        const offset = sector * sectorSize;
                        const len = Math.min(sectorSize, km.length - offset);
                        const sectorData = Buffer.alloc(sectorSize);
                        km.copy(sectorData, 0, offset, offset + len);
                        const tweak = Buffer.alloc(16);
                        tweak.writeUInt32LE(sector, 0);
                        try {
                            const algName = derivedKey.length >= 64 ? 'aes-256-xts' : 'aes-128-xts';
                            const dec = crypto.createDecipheriv(algName, derivedKey, tweak);
                            dec.setAutoPadding(false);
                            const decSector = dec.update(sectorData);
                            decSector.copy(decKm, offset, 0, len);
                        }
                        catch {
                            // XTS not available: fall back to ECB-based XTS emulation
                            const key1 = derivedKey.subarray(0, 32);
                            const key2 = derivedKey.subarray(32, 64);
                            // Simple fallback: AES-CBC with sector IV
                            const iv = Buffer.alloc(16);
                            iv.writeUInt32LE(sector, 0);
                            const dec = crypto.createDecipheriv('aes-256-cbc', key1, iv);
                            dec.setAutoPadding(false);
                            const decSector = dec.update(sectorData);
                            decSector.copy(decKm, offset, 0, len);
                        }
                    }
                }
                else {
                    // AES-CBC: decrypt with sector-based IV
                    for (let sector = 0; sector < Math.ceil(km.length / sectorSize); sector++) {
                        const offset = sector * sectorSize;
                        const len = Math.min(sectorSize, km.length - offset);
                        const sectorData = Buffer.alloc(sectorSize);
                        km.copy(sectorData, 0, offset, offset + len);
                        const iv = Buffer.alloc(16);
                        iv.writeUInt32LE(sector, 0);
                        const keyLen = derivedKey.length >= 32 ? 32 : 16;
                        const algName = keyLen === 32 ? 'aes-256-cbc' : 'aes-128-cbc';
                        const dec = crypto.createDecipheriv(algName, derivedKey.subarray(0, keyLen), iv);
                        dec.setAutoPadding(false);
                        const decSector = dec.update(sectorData);
                        decSector.copy(decKm, offset, 0, len);
                    }
                }
                // Anti-forensic merge with hash diffusion
                const masterKey = afMerge(decKm, p.keyBytes, p.slotStripes, p.hashSpec);
                // Verify: PBKDF2(masterKey, mkDigestSalt, mkDigestIter) == mkDigest
                const mkSalt = Buffer.from(p.mkDigestSalt, 'base64');
                const mkDigest = Buffer.from(p.mkDigest, 'base64');
                const computed = await new Promise((res, rej) => crypto.pbkdf2(masterKey, mkSalt, p.mkDigestIter, mkDigest.length, p.hashSpec, (e, k) => e ? rej(e) : res(k)));
                return computed.equals(mkDigest);
            }
            return false;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        const kdfStr = p.argon2Type
            ? `${p.argon2Type} (mem=${((p.argon2Memory || 0) / 1024).toFixed(0)}MB, t=${p.slotIterations})`
            : `PBKDF2-${p.hashSpec} × ${p.slotIterations.toLocaleString()}`;
        return {
            format: `LUKS${p.version}`,
            description: `LUKS${p.version} encrypted volume`,
            kdf: kdfStr,
            cipher: `${p.cipherName}-${p.cipherMode}`,
            iterations: p.slotIterations,
            difficulty: 'extreme',
            estimatedSpeed: '~1-5/s',
        };
    },
};
//# sourceMappingURL=luks.js.map