/**
 * Wordlist Manager
 *
 * Downloads, indexes, and manages popular wordlists for password cracking.
 * Supports streaming large files without loading entirely into memory.
 *
 * Built-in wordlists:
 * - RockYou (14.3M passwords)
 * - SecLists common passwords (various sizes)
 * - CrackStation (real-world)
 * - Custom user wordlists
 */
import fs from 'node:fs';
import path from 'node:path';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createGunzip } from 'node:zlib';
const DEFAULT_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '/tmp', '.mm-recovery', 'wordlists');
/** Known wordlists registry */
const WORDLISTS = [
    {
        id: 'rockyou',
        name: 'RockYou',
        description: 'Classic RockYou breach — 14.3M passwords',
        url: 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
        compressed: false,
        estimatedSize: '134 MB',
        estimatedLines: 14_344_391,
    },
    {
        id: 'seclists-1m',
        name: 'SecLists Top 1M',
        description: 'Top 1 million common passwords from SecLists',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
        compressed: false,
        estimatedSize: '9 MB',
        estimatedLines: 999_999,
    },
    {
        id: 'seclists-100k',
        name: 'SecLists Top 100K',
        description: 'Top 100K common passwords from SecLists',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt',
        compressed: false,
        estimatedSize: '1 MB',
        estimatedLines: 100_000,
    },
    {
        id: 'seclists-10k',
        name: 'SecLists Top 10K',
        description: 'Top 10K common passwords from SecLists',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt',
        compressed: false,
        estimatedSize: '95 KB',
        estimatedLines: 10_000,
    },
    {
        id: 'seclists-wifi',
        name: 'SecLists WiFi',
        description: 'Common WiFi passwords from SecLists',
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt',
        compressed: false,
        estimatedSize: '50 KB',
        estimatedLines: 4_800,
    },
    {
        id: 'crypto-specific',
        name: 'Crypto-Specific',
        description: 'Cryptocurrency-related terms and patterns (built-in)',
        url: '',
        compressed: false,
        estimatedSize: '5 KB',
        estimatedLines: 500,
    },
];
/** Built-in crypto-specific wordlist */
const CRYPTO_WORDS = [
    'metamask', 'ethereum', 'bitcoin', 'crypto', 'blockchain', 'wallet', 'defi',
    'hodl', 'moonlambo', 'satoshi', 'nakamoto', 'vitalik', 'buterin', 'web3',
    'nft', 'token', 'solana', 'cardano', 'polkadot', 'avalanche', 'polygon',
    'matic', 'chainlink', 'uniswap', 'aave', 'compound', 'maker', 'dai',
    'usdc', 'usdt', 'tether', 'binance', 'coinbase', 'phantom', 'trustwallet',
    'ledger', 'trezor', 'mnemonic', 'seedphrase', 'privatekey', 'recovery',
    'decentralized', 'staking', 'yield', 'liquidity', 'farm', 'mining',
    'proof', 'consensus', 'gas', 'gwei', 'wei', 'ether', 'bitcoin',
    'lightning', 'layer2', 'rollup', 'zksync', 'arbitrum', 'optimism',
    'passw0rd', 'p@ssword', 'password', 'letmein', 'welcome', 'admin',
    'master', 'access', 'secret', 'secure', 'login', 'changeme',
];
export class WordlistManager {
    dir;
    constructor(options = {}) {
        this.dir = options.directory || DEFAULT_DIR;
        fs.mkdirSync(this.dir, { recursive: true });
    }
    /**
     * List all available wordlists (built-in + downloaded).
     */
    list() {
        return WORDLISTS.map((wl) => {
            const localPath = path.join(this.dir, `${wl.id}.txt`);
            return {
                ...wl,
                localPath,
                downloaded: fs.existsSync(localPath),
            };
        });
    }
    /**
     * Download a wordlist by ID.
     */
    async download(id, onProgress) {
        const wl = WORDLISTS.find((w) => w.id === id);
        if (!wl)
            throw new Error(`Unknown wordlist: ${id}`);
        if (wl.id === 'crypto-specific') {
            // Built-in: write directly
            const outPath = path.join(this.dir, `${id}.txt`);
            fs.writeFileSync(outPath, CRYPTO_WORDS.join('\n') + '\n', 'utf-8');
            return outPath;
        }
        if (!wl.url)
            throw new Error(`No download URL for wordlist: ${id}`);
        const outPath = path.join(this.dir, `${id}.txt`);
        onProgress?.(0, `Downloading ${wl.name}...`);
        const response = await fetch(wl.url);
        if (!response.ok)
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        const contentLength = parseInt(response.headers.get('content-length') || '0');
        const body = response.body;
        if (!body)
            throw new Error('No response body');
        const writer = fs.createWriteStream(outPath);
        const reader = body.getReader();
        let downloaded = 0;
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done)
                    break;
                writer.write(Buffer.from(value));
                downloaded += value.length;
                if (contentLength > 0) {
                    const pct = Math.round((downloaded / contentLength) * 100);
                    onProgress?.(pct, `${formatBytes(downloaded)} / ${formatBytes(contentLength)}`);
                }
                else {
                    onProgress?.(-1, `${formatBytes(downloaded)} downloaded`);
                }
            }
        }
        finally {
            writer.end();
        }
        // Wait for write to finish
        await new Promise((resolve) => writer.on('finish', resolve));
        onProgress?.(100, `Done — saved to ${outPath}`);
        return outPath;
    }
    /**
     * Stream passwords from a wordlist file (memory-efficient).
     * Handles plain text and .gz files.
     */
    async *streamWords(idOrPath) {
        let filePath;
        // Check if it's a known wordlist ID
        const wl = WORDLISTS.find((w) => w.id === idOrPath);
        if (wl) {
            filePath = path.join(this.dir, `${idOrPath}.txt`);
            if (!fs.existsSync(filePath)) {
                throw new Error(`Wordlist "${idOrPath}" not downloaded. Run: mm-recover-v4 wordlist download ${idOrPath}`);
            }
        }
        else {
            filePath = idOrPath;
        }
        if (!fs.existsSync(filePath)) {
            throw new Error(`File not found: ${filePath}`);
        }
        let input = createReadStream(filePath);
        if (filePath.endsWith('.gz')) {
            input = input.pipe(createGunzip());
        }
        const rl = createInterface({ input, crlfDelay: Infinity });
        for await (const line of rl) {
            const trimmed = line.trim();
            if (trimmed)
                yield trimmed;
        }
    }
    /**
     * Load a wordlist into memory (for small/medium lists).
     */
    async loadWords(idOrPath, minLength = 0) {
        const words = [];
        for await (const word of this.streamWords(idOrPath)) {
            if (word.length >= minLength) {
                words.push(word);
            }
        }
        return words;
    }
    /**
     * Stream words in batches (for worker distribution).
     */
    async *streamBatches(idOrPath, batchSize = 64, minLength = 8) {
        let batch = [];
        for await (const word of this.streamWords(idOrPath)) {
            if (word.length >= minLength) {
                batch.push(word);
                if (batch.length >= batchSize) {
                    yield batch;
                    batch = [];
                }
            }
        }
        if (batch.length > 0)
            yield batch;
    }
    /**
     * Count lines in a wordlist file.
     */
    async countWords(idOrPath) {
        let count = 0;
        for await (const _ of this.streamWords(idOrPath)) {
            count++;
        }
        return count;
    }
    /**
     * Get the storage directory path.
     */
    getDirectory() {
        return this.dir;
    }
    /**
     * Download all built-in wordlists.
     */
    async downloadAll(onProgress) {
        for (const wl of WORDLISTS) {
            const localPath = path.join(this.dir, `${wl.id}.txt`);
            if (!fs.existsSync(localPath)) {
                await this.download(wl.id, (pct, msg) => onProgress?.(wl.id, pct, msg));
            }
        }
    }
}
function formatBytes(bytes) {
    if (bytes < 1024)
        return `${bytes} B`;
    if (bytes < 1024 * 1024)
        return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024)
        return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}
//# sourceMappingURL=wordlist-manager.js.map