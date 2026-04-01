/**
 * iPhone / iTunes Backup Cracker
 * Format: Manifest.plist (encrypted) + BackupKeyBag
 * KDF: PBKDF2-SHA256 (DPSL salt, DPIC iterations) or PBKDF2-SHA1 (legacy)
 * Verification: unwrap class keys in keybag
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
/** Parse binary keybag */
function parseKeyBag(data) {
    const result = [];
    let dpsl;
    let dpic;
    let offset = 0;
    let currentUuid = '';
    let currentClass = 0;
    let currentWrap = 0;
    let currentKey = Buffer.alloc(0);
    while (offset < data.length - 8) {
        const tag = data.subarray(offset, offset + 4).toString('ascii');
        const length = data.readUInt32BE(offset + 4);
        const value = data.subarray(offset + 8, offset + 8 + length);
        offset += 8 + length;
        switch (tag) {
            case 'UUID':
                if (currentUuid && currentKey.length > 0 && currentWrap >= 2) {
                    result.push({
                        uuid: currentUuid,
                        class: currentClass,
                        wrappedKey: currentKey.toString('base64'),
                        wrapType: currentWrap,
                    });
                }
                currentUuid = value.toString('hex');
                currentClass = 0;
                currentWrap = 0;
                currentKey = Buffer.alloc(0);
                break;
            case 'CLAS':
                currentClass = value.readUInt32BE(0);
                break;
            case 'WRAP':
                currentWrap = value.readUInt32BE(0);
                break;
            case 'WPKY':
                currentKey = Buffer.from(value);
                break;
            case 'DPSL':
                dpsl = Buffer.from(value);
                break;
            case 'DPIC':
                dpic = value.readUInt32BE(0);
                break;
        }
    }
    // Don't forget last entry
    if (currentUuid && currentKey.length > 0 && currentWrap >= 2) {
        result.push({
            uuid: currentUuid,
            class: currentClass,
            wrappedKey: currentKey.toString('base64'),
            wrapType: currentWrap,
        });
    }
    return { dpsl, dpic, classKeys: result };
}
export const IPhoneBackupCracker = {
    id: 'iphone-backup',
    name: 'iPhone Backup',
    description: 'iTunes/Finder encrypted iPhone backups (PBKDF2 + AES)',
    fileExtensions: ['.plist', '.mdbackup'],
    async detect(filePath) {
        try {
            // Check for Manifest.plist with encryption flag
            const basename = path.basename(filePath);
            if (basename === 'Manifest.plist') {
                const data = fs.readFileSync(filePath);
                return data.includes(Buffer.from('IsEncrypted')) ||
                    data.includes(Buffer.from('BackupKeyBag'));
            }
            // Check if it's a backup directory with Manifest.plist
            const dir = filePath.endsWith('/') ? filePath : filePath;
            const manifest = path.join(dir, 'Manifest.plist');
            if (fs.existsSync(manifest)) {
                const data = fs.readFileSync(manifest);
                return data.includes(Buffer.from('BackupKeyBag'));
            }
            return false;
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        // Find Manifest.plist
        let manifestPath = filePath;
        if (!filePath.endsWith('Manifest.plist')) {
            manifestPath = path.join(filePath, 'Manifest.plist');
        }
        const data = fs.readFileSync(manifestPath);
        // Find BackupKeyBag in binary plist
        // Look for keybag data — it's between specific tags
        const keyBagStart = data.indexOf(Buffer.from('BackupKeyBag'));
        if (keyBagStart === -1)
            throw new Error('No BackupKeyBag found');
        // The keybag is in a <data> element after BackupKeyBag key
        // Binary plist has different structure — try to find the raw keybag data
        // Look for the keybag by scanning for known tags
        let keybagData = null;
        // Scan for keybag marker (DPSL, DPIC, UUID, CLAS patterns)
        for (let i = keyBagStart; i < data.length - 8; i++) {
            const tag = data.subarray(i, i + 4).toString('ascii');
            if (tag === 'DPSL' || tag === 'DPIC' || tag === 'VERS') {
                // Found start of keybag
                // Find the end (scan until we run out of valid tags or hit boundary)
                let end = i;
                while (end < data.length - 8) {
                    const t = data.subarray(end, end + 4).toString('ascii');
                    const l = data.readUInt32BE(end + 4);
                    if (l > 4096 || l < 0)
                        break; // Invalid length
                    end += 8 + l;
                }
                keybagData = data.subarray(i, end);
                break;
            }
        }
        if (!keybagData) {
            // Try XML plist fallback
            const xmlStr = data.toString('latin1');
            const b64Match = xmlStr.match(/BackupKeyBag[\s\S]*?<data>([\s\S]*?)<\/data>/);
            if (b64Match) {
                keybagData = Buffer.from(b64Match[1].replace(/\s/g, ''), 'base64');
            }
        }
        if (!keybagData)
            throw new Error('Could not extract BackupKeyBag data');
        const { dpsl, dpic, classKeys } = parseKeyBag(keybagData);
        if (classKeys.length === 0) {
            throw new Error('No password-protected class keys found in keybag');
        }
        return {
            type: 'iphone-backup',
            dpsl: dpsl?.toString('base64') || '',
            dpic: dpic || 10_000_000,
            classKeys,
        };
    },
    async tryPassword(password, params) {
        const p = params;
        try {
            // Step 1: Derive key using DPSL/DPIC
            const dpsl = Buffer.from(p.dpsl, 'base64');
            const passKey = await new Promise((res, rej) => crypto.pbkdf2(password, dpsl, p.dpic, 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            // Step 2: Second PBKDF2 round (iOS 10.2+)
            // PBKDF2(passKey, salt=dpsl, iterations=1, keyLen=32)
            const unwrapKey = await new Promise((res, rej) => crypto.pbkdf2(passKey, dpsl, 1, 32, 'sha1', (e, k) => e ? rej(e) : res(k)));
            // Step 3: Try to unwrap a class key using AES key wrap (RFC 3394)
            for (const ck of p.classKeys) {
                if (ck.wrapType < 2)
                    continue; // Skip UID-only keys
                const wrappedKey = Buffer.from(ck.wrappedKey, 'base64');
                if (wrappedKey.length < 24)
                    continue;
                // AES-256 Key Unwrap
                const unwrapped = aesKeyUnwrap(unwrapKey, wrappedKey);
                if (unwrapped)
                    return true;
            }
            return false;
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'iPhone Backup',
            description: `Encrypted iTunes/Finder backup — ${p.classKeys.length} class keys`,
            kdf: `PBKDF2-SHA256 × ${p.dpic.toLocaleString()}`,
            cipher: 'AES-256 Key Wrap',
            iterations: p.dpic,
            difficulty: p.dpic >= 10_000_000 ? 'extreme' : 'hard',
            estimatedSpeed: p.dpic >= 10_000_000 ? '~0.1-0.5/s' : '~5-20/s',
        };
    },
};
/**
 * AES Key Unwrap (RFC 3394) — simplified
 * Returns unwrapped key or null if verification fails
 */
function aesKeyUnwrap(kek, wrapped) {
    const n = wrapped.length / 8 - 1;
    if (n < 1)
        return null;
    let A = wrapped.subarray(0, 8);
    const R = [];
    for (let i = 0; i < n; i++) {
        R.push(Buffer.from(wrapped.subarray((i + 1) * 8, (i + 2) * 8)));
    }
    for (let j = 5; j >= 0; j--) {
        for (let i = n - 1; i >= 0; i--) {
            const tBytes = Buffer.alloc(8);
            const t = n * j + i + 1;
            tBytes.writeUInt32BE(t >>> 0, 4);
            // A ^ t
            const xored = Buffer.alloc(8);
            for (let k = 0; k < 8; k++)
                xored[k] = A[k] ^ tBytes[k];
            const input = Buffer.concat([xored, R[i]]);
            const decipher = crypto.createDecipheriv('aes-256-ecb', kek, null);
            decipher.setAutoPadding(false);
            const dec = decipher.update(input);
            A = dec.subarray(0, 8);
            R[i] = Buffer.from(dec.subarray(8, 16));
        }
    }
    // Check: A should be 0xA6A6A6A6A6A6A6A6
    const expected = Buffer.from([0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]);
    if (A.equals(expected)) {
        return Buffer.concat(R);
    }
    return null;
}
//# sourceMappingURL=iphone-backup.js.map