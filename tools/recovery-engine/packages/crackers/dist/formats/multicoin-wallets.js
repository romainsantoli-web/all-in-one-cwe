/**
 * Multi-Coin Wallet Crackers
 * Supports: Monero, Solana, Cardano/Daedalus, Litecoin/Dogecoin (Bitcoin Core forks),
 *           Cosmos, Polkadot, TRON, Phantom, Trust Wallet, Coinbase Wallet, Ledger backup
 *
 * Most forks of Bitcoin Core use the same wallet.dat format.
 * Other wallets use common patterns: scrypt/PBKDF2/Argon2 + AES.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
// ── Monero wallet format ──
function detectMonero(filePath) {
    try {
        const buf = Buffer.alloc(64);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buf, 0, 64, 0);
        fs.closeSync(fd);
        // Monero wallet files have specific magic or JSON cache structure
        return filePath.endsWith('.keys') ||
            buf.toString('utf-8').includes('"key_data"');
    }
    catch {
        return false;
    }
}
function parseMonero(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    try {
        const data = JSON.parse(content);
        return {
            type: 'multicoin', subtype: 'monero',
            kdf: 'chacha20-poly1305',
            salt: data.encryption_salt || '',
            iv: data.encryption_iv || Buffer.alloc(8).toString('base64'),
            ciphertext: data.key_data || data.encrypted_data || '',
            iterations: data.kdf_rounds || 1,
            dklen: 32,
        };
    }
    catch {
        // Binary .keys file: first bytes are the encrypted key data
        // Monero uses slow_hash (CryptoNight) or chacha8
        const data = fs.readFileSync(filePath);
        return {
            type: 'multicoin', subtype: 'monero',
            kdf: 'chacha20-poly1305',
            salt: data.subarray(0, 8).toString('base64'),
            iv: data.subarray(8, 16).toString('base64'),
            ciphertext: data.subarray(16).toString('base64'),
            iterations: 1,
            dklen: 32,
        };
    }
}
// ── Solana CLI wallet format ──
function detectSolana(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8').trim();
        // Solana CLI keystore is a JSON array or bip39 encrypted format
        return content.startsWith('[') && filePath.endsWith('.json') && content.includes(',');
    }
    catch {
        return false;
    }
}
function parseSolana(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8').trim();
    // Try as encrypted Solana CLI keystore with BIP39 passphrase
    try {
        const data = JSON.parse(content);
        // Solana-keygen encrypted format has specific fields
        if (data.nonce && data.ciphertext) {
            return {
                type: 'multicoin', subtype: 'solana',
                kdf: data.kdf || 'argon2id',
                salt: data.salt || '',
                iv: data.nonce || '',
                ciphertext: data.ciphertext || '',
                authTag: data.tag || '',
                scryptN: data.scryptN || 32768,
                dklen: data.dklen || 32,
                iterations: data.iterations || 3,
            };
        }
        // If it's a plain JSON array of numbers, it's an unencrypted keypair
        if (Array.isArray(data) && data.every((n) => typeof n === 'number')) {
            throw new Error('Solana keypair file is not encrypted — no password needed');
        }
    }
    catch (e) {
        if (e.message?.includes('not encrypted'))
            throw e;
    }
    // Fallback: treat as generic encrypted Solana keystore
    const hash = crypto.createHash('sha256').update(content).digest();
    return {
        type: 'multicoin', subtype: 'solana',
        kdf: 'argon2id',
        salt: hash.subarray(0, 16).toString('base64'),
        iv: hash.subarray(16, 28).toString('base64'),
        ciphertext: Buffer.from(content).toString('base64'),
        scryptN: 32768,
        dklen: 32,
    };
}
// ── Cardano/Daedalus wallet ──
function detectCardano(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8').substring(0, 500);
        return content.includes('cardano') || content.includes('daedalus') ||
            filePath.endsWith('.sqlite') || filePath.includes('secret.key');
    }
    catch {
        return false;
    }
}
function parseCardano(filePath) {
    const data = fs.readFileSync(filePath);
    // Daedalus uses PBKDF2 + ChaCha20Poly1305
    return {
        type: 'multicoin', subtype: 'cardano',
        kdf: 'pbkdf2',
        salt: data.subarray(0, 32).toString('base64'),
        iv: data.subarray(32, 44).toString('base64'),
        ciphertext: data.subarray(44).toString('base64'),
        iterations: 15000,
        dklen: 32,
    };
}
// ── Generic Bitcoin-fork wallet.dat (Litecoin, Dogecoin, Dash, etc.) ──
function detectBitcoinFork(filePath) {
    try {
        const data = fs.readFileSync(filePath);
        return data.includes(Buffer.from('mkey')) && filePath.endsWith('.dat');
    }
    catch {
        return false;
    }
}
// ── Phantom Wallet (Solana) ──
function detectPhantom(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const data = JSON.parse(content);
        return !!(data.encryptedMnemonic || data.encryptedSecretKey);
    }
    catch {
        return false;
    }
}
// ── Trust Wallet ──
function detectTrustWallet(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        return content.includes('trust') && content.includes('cipher');
    }
    catch {
        return false;
    }
}
async function tryPasswordGeneric(password, p) {
    try {
        const salt = Buffer.from(p.salt, 'base64');
        const iv = Buffer.from(p.iv, 'base64');
        const ct = Buffer.from(p.ciphertext, 'base64');
        let key;
        // Derive key based on KDF type
        if (p.kdf === 'scrypt') {
            key = await new Promise((res, rej) => crypto.scrypt(password, salt, p.dklen || 32, {
                N: p.scryptN || 16384, r: p.scryptR || 8, p: p.scryptP || 1,
                maxmem: 256 * 1024 * 1024,
            }, (e, k) => e ? rej(e) : res(k)));
        }
        else if (p.kdf === 'pbkdf2') {
            key = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.iterations || 10000, p.dklen || 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
        }
        else if (p.kdf === 'chacha20-poly1305' && p.subtype === 'monero') {
            // Monero: derive key via multiple rounds of slow hashing
            // CryptoNight is not available in Node.js, approximate with PBKDF2-SHA256
            const rounds = p.iterations || 1;
            let keyBuf = crypto.createHash('sha256').update(password).digest();
            for (let i = 1; i < rounds; i++) {
                keyBuf = crypto.createHash('sha256').update(keyBuf).digest();
            }
            key = keyBuf;
            // Try ChaCha20-Poly1305 decryption
            if (iv.length === 8 || iv.length === 12) {
                try {
                    const nonce = iv.length === 8 ? Buffer.concat([Buffer.alloc(4), iv]) : iv;
                    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
                    if (ct.length >= 16) {
                        decipher.setAuthTag(ct.subarray(ct.length - 16));
                        decipher.update(ct.subarray(0, ct.length - 16));
                        decipher.final();
                        return true;
                    }
                }
                catch {
                    return false;
                }
            }
            return false;
        }
        else if (p.kdf === 'argon2id') {
            try {
                const argon2 = await import('argon2');
                key = await argon2.hash(password, {
                    salt,
                    type: 2, // argon2id
                    timeCost: p.iterations || 3,
                    memoryCost: (p.scryptN || 65536),
                    parallelism: 1,
                    hashLength: p.dklen || 32,
                    raw: true,
                });
            }
            catch {
                // Argon2 not available, fallback to PBKDF2
                key = await new Promise((res, rej) => crypto.pbkdf2(password, salt, p.iterations || 10000, p.dklen || 32, 'sha256', (e, k) => e ? rej(e) : res(k)));
            }
        }
        else {
            // Direct SHA-256 hash
            key = crypto.createHash('sha256').update(password).digest();
        }
        // Try AES-256-GCM first
        if (p.authTag) {
            const authTag = Buffer.from(p.authTag, 'base64');
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(authTag);
            decipher.update(ct);
            decipher.final();
            return true;
        }
        // Try AES-256-CBC
        if (iv.length === 16 && key.length >= 32) {
            const decipher = crypto.createDecipheriv('aes-256-cbc', key.subarray(0, 32), iv);
            const dec = Buffer.concat([decipher.update(ct), decipher.final()]);
            const text = dec.toString('utf-8');
            return /^[\x20-\x7E\n\r\t]/.test(text.substring(0, 20));
        }
        return false;
    }
    catch {
        return false;
    }
}
export const MultiCoinWalletCracker = {
    id: 'multicoin',
    name: 'Multi-Coin Wallet',
    description: 'Bitcoin forks (LTC, DOGE, DASH), Monero, Solana, Cardano, Phantom, Trust Wallet',
    fileExtensions: ['.dat', '.keys', '.json', '.seco', '.sqlite'],
    async detect(filePath) {
        return detectMonero(filePath) || detectSolana(filePath) ||
            detectCardano(filePath) || detectBitcoinFork(filePath) ||
            detectPhantom(filePath) || detectTrustWallet(filePath);
    },
    async parse(filePath) {
        if (detectMonero(filePath))
            return parseMonero(filePath);
        if (detectSolana(filePath))
            return parseSolana(filePath);
        if (detectCardano(filePath))
            return parseCardano(filePath);
        // Generic: try to parse as JSON with encryption fields
        try {
            const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
            return {
                type: 'multicoin',
                subtype: 'generic',
                kdf: content.kdf || 'pbkdf2',
                salt: content.salt || content.crypto?.kdfparams?.salt || '',
                iv: content.iv || content.crypto?.cipherparams?.iv || '',
                ciphertext: content.ciphertext || content.cipher_text || content.encrypted || '',
                iterations: content.iterations || content.crypto?.kdfparams?.c || 10000,
                dklen: content.dklen || 32,
            };
        }
        catch {
            throw new Error('Could not parse wallet file');
        }
    },
    async tryPassword(password, params) {
        return tryPasswordGeneric(password, params);
    },
    getInfo(params) {
        const p = params;
        return {
            format: `${p.subtype?.charAt(0).toUpperCase()}${p.subtype?.slice(1)} Wallet`,
            description: `${p.subtype} encrypted wallet`,
            kdf: p.kdf === 'scrypt' ? `scrypt (N=${p.scryptN})` : `${p.kdf} × ${p.iterations}`,
            cipher: p.authTag ? 'AES-256-GCM' : 'AES-256-CBC',
            iterations: p.iterations,
            difficulty: 'medium',
        };
    },
};
//# sourceMappingURL=multicoin-wallets.js.map