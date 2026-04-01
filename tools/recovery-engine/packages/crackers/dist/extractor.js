/**
 * Universal File Extractor
 *
 * Automatically finds encrypted files on the local system
 * based on known default installation paths for each format.
 *
 * macOS + Linux + Windows paths supported.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
// ── Path Definitions ──
const HOME = os.homedir();
const platform = os.platform();
const FORMAT_PATHS = [
    // ── Crypto Wallets ──
    {
        id: 'metamask',
        name: 'MetaMask',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/Library/Application Support/Google/Chrome/Profile */Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/Library/Application Support/Microsoft Edge/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/Library/Application Support/Vivaldi/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/Library/Application Support/Opera/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
        ] : platform === 'linux' ? [
            `${HOME}/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
        ] : [
            `${HOME}/AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
            `${HOME}/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn`,
        ],
        note: 'LevelDB — use `extract` command to read vault',
    },
    {
        id: 'bitcoin-core',
        name: 'Bitcoin Core',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Application Support/Bitcoin`,
        ] : platform === 'linux' ? [
            `${HOME}/.bitcoin`,
        ] : [
            `${HOME}/AppData/Roaming/Bitcoin`,
        ],
        filePatterns: ['wallet.dat', 'wallets/*/wallet.dat'],
        isEncrypted: (fp) => {
            try {
                const buf = fs.readFileSync(fp);
                return buf.includes(Buffer.from('mkey'));
            }
            catch {
                return false;
            }
        },
    },
    {
        id: 'ethereum-keystore',
        name: 'Ethereum (Geth)',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Ethereum/keystore`,
            `${HOME}/Library/Application Support/io.parity.ethereum/keys/ethereum`,
        ] : platform === 'linux' ? [
            `${HOME}/.ethereum/keystore`,
            `${HOME}/.local/share/io.parity.ethereum/keys/ethereum`,
        ] : [
            `${HOME}/AppData/Roaming/Ethereum/keystore`,
        ],
        filePatterns: ['UTC--*', '*.json'],
        isEncrypted: (fp) => {
            try {
                const data = fs.readFileSync(fp, 'utf-8');
                return data.includes('"crypto"') || data.includes('"Crypto"');
            }
            catch {
                return false;
            }
        },
    },
    {
        id: 'electrum',
        name: 'Electrum',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/.electrum/wallets`,
        ] : platform === 'linux' ? [
            `${HOME}/.electrum/wallets`,
        ] : [
            `${HOME}/AppData/Roaming/Electrum/wallets`,
        ],
        filePatterns: ['default_wallet', '*'],
    },
    {
        id: 'exodus',
        name: 'Exodus',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Application Support/Exodus/exodus.wallet`,
        ] : platform === 'linux' ? [
            `${HOME}/.config/Exodus/exodus.wallet`,
        ] : [
            `${HOME}/AppData/Roaming/Exodus/exodus.wallet`,
        ],
        filePatterns: ['seed.seco', '*.seco'],
        isEncrypted: (fp) => {
            try {
                const buf = Buffer.alloc(4);
                const fd = fs.openSync(fp, 'r');
                fs.readSync(fd, buf, 0, 4, 0);
                fs.closeSync(fd);
                return buf.toString('ascii') === 'exo\0' || buf.toString('ascii') === 'exod';
            }
            catch {
                return false;
            }
        },
    },
    {
        id: 'multicoin',
        name: 'Monero',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/Monero/wallets`,
            `${HOME}/Library/Application Support/monero-project`,
        ] : platform === 'linux' ? [
            `${HOME}/Monero/wallets`,
            `${HOME}/.bitmonero`,
        ] : [
            `${HOME}/Documents/Monero/wallets`,
        ],
        filePatterns: ['*.keys'],
    },
    {
        id: 'multicoin',
        name: 'Solana CLI',
        category: 'wallet',
        paths: [
            `${HOME}/.config/solana`,
        ],
        filePatterns: ['id.json', '*.json'],
    },
    {
        id: 'multicoin',
        name: 'Cardano / Daedalus',
        category: 'wallet',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Application Support/Daedalus Mainnet/wallets`,
        ] : platform === 'linux' ? [
            `${HOME}/.local/share/Daedalus/mainnet/wallets`,
        ] : [
            `${HOME}/AppData/Roaming/Daedalus Mainnet/wallets`,
        ],
        filePatterns: ['*.sqlite', '*.json'],
    },
    // ── Password Managers ──
    {
        id: 'keepass',
        name: 'KeePass / KeePassXC',
        category: 'password-manager',
        paths: [
            `${HOME}/Documents`,
            `${HOME}/Desktop`,
            `${HOME}/Downloads`,
            ...(platform === 'darwin' ? [
                `${HOME}/Library/Application Support/KeePassXC`,
            ] : platform === 'linux' ? [
                `${HOME}/.config/keepassxc`,
            ] : [
                `${HOME}/AppData/Roaming/KeePassXC`,
            ]),
        ],
        filePatterns: ['*.kdbx', '*.kdb'],
    },
    {
        id: '1password',
        name: '1Password',
        category: 'password-manager',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Group Containers/2BUA8C4S2C.com.1password`,
            `${HOME}/Library/Application Support/1Password`,
            `${HOME}/Library/Application Support/1Password 4/Data`,
        ] : platform === 'linux' ? [
            `${HOME}/.config/1Password`,
            `${HOME}/.1password`,
        ] : [
            `${HOME}/AppData/Local/1Password`,
            `${HOME}/AppData/Roaming/1Password`,
        ],
        filePatterns: ['*.opvault', '*.agilekeychain', 'data.sqlite', '1password.sqlite'],
    },
    {
        id: 'bitwarden',
        name: 'Bitwarden',
        category: 'password-manager',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Application Support/Bitwarden`,
            `${HOME}/Downloads`,
        ] : platform === 'linux' ? [
            `${HOME}/.config/Bitwarden`,
            `${HOME}/Downloads`,
        ] : [
            `${HOME}/AppData/Roaming/Bitwarden`,
            `${HOME}/Downloads`,
        ],
        filePatterns: ['bitwarden_export*.json', 'bitwarden_encrypted_export*.json', 'data.json'],
        isEncrypted: (fp) => {
            try {
                const data = fs.readFileSync(fp, 'utf-8');
                return data.includes('"encrypted"') && data.includes('"encKeyValidation_DO_NOT_EDIT"');
            }
            catch {
                return false;
            }
        },
    },
    {
        id: 'lastpass',
        name: 'LastPass',
        category: 'password-manager',
        paths: [
            `${HOME}/Downloads`,
            `${HOME}/Documents`,
            ...(platform === 'darwin' ? [
                `${HOME}/Library/Application Support/Google/Chrome/Default/databases/chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0`,
                `${HOME}/Library/Application Support/LastPass`,
            ] : platform === 'linux' ? [
                `${HOME}/.lastpass`,
            ] : [
                `${HOME}/AppData/Local/LastPass`,
            ]),
        ],
        filePatterns: ['lastpass_export*.csv', 'lastpass_vault*.dat', 'lastpass*.csv', 'lastpass*.dat'],
        isEncrypted: (fp) => {
            try {
                const content = fs.readFileSync(fp, 'utf-8').slice(0, 500);
                // LastPass encrypted exports have a specific header
                return content.includes('url,username,password,') || content.includes('lastpass');
            }
            catch {
                return false;
            }
        },
    },
    // ── Disk Encryption ──
    {
        id: 'veracrypt',
        name: 'VeraCrypt / TrueCrypt',
        category: 'disk',
        paths: [
            `${HOME}/Documents`,
            `${HOME}/Desktop`,
            `${HOME}/Downloads`,
            `${HOME}`,
        ],
        filePatterns: ['*.hc', '*.tc', '*.vol'],
    },
    {
        id: 'dmg',
        name: 'macOS DMG',
        category: 'disk',
        paths: [
            `${HOME}/Downloads`,
            `${HOME}/Desktop`,
            `${HOME}/Documents`,
        ],
        filePatterns: ['*.dmg'],
        isEncrypted: (fp) => {
            try {
                // Read first bytes — encrypted DMGs have 'encrcdsa' or 'cdsaencr' marker
                const buf = Buffer.alloc(512);
                const fd = fs.openSync(fp, 'r');
                fs.readSync(fd, buf, 0, 512, 0);
                fs.closeSync(fd);
                return buf.includes(Buffer.from('encrcdsa')) || buf.includes(Buffer.from('cdsaencr'));
            }
            catch {
                return false;
            }
        },
    },
    {
        id: 'luks',
        name: 'LUKS',
        category: 'disk',
        paths: platform === 'linux' ? [
            '/dev',
            `${HOME}`,
        ] : [
            `${HOME}/Documents`,
            `${HOME}/Desktop`,
        ],
        filePatterns: ['*.luks', '*.img'],
    },
    // ── Network ──
    {
        id: 'wifi',
        name: 'WiFi WPA/WPA2',
        category: 'network',
        paths: [
            `${HOME}/Downloads`,
            `${HOME}/Documents`,
            `${HOME}/Desktop`,
        ],
        filePatterns: ['*.hccapx', '*.cap', '*.pcap', '*.pcapng'],
    },
    {
        id: 'ssh',
        name: 'SSH Private Keys',
        category: 'network',
        paths: [
            `${HOME}/.ssh`,
        ],
        filePatterns: ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '*.pem', '*.key'],
        isEncrypted: (fp) => {
            try {
                const head = fs.readFileSync(fp, 'utf-8').substring(0, 500);
                return head.includes('ENCRYPTED') || head.includes('BEGIN OPENSSH PRIVATE KEY');
            }
            catch {
                return false;
            }
        },
    },
    // ── Mobile ──
    {
        id: 'iphone-backup',
        name: 'iPhone / iTunes Backup',
        category: 'mobile',
        paths: platform === 'darwin' ? [
            `${HOME}/Library/Application Support/MobileSync/Backup`,
        ] : platform === 'linux' ? [
            `${HOME}/.local/share/libimobiledevice/backup`,
        ] : [
            `${HOME}/AppData/Roaming/Apple Computer/MobileSync/Backup`,
            `${HOME}/Apple/MobileSync/Backup`,
        ],
        filePatterns: ['*/Manifest.plist'],
        isEncrypted: (fp) => {
            try {
                const data = fs.readFileSync(fp);
                return data.includes(Buffer.from('IsEncrypted')) || data.includes(Buffer.from('BackupKeyBag'));
            }
            catch {
                return false;
            }
        },
    },
];
// ── Helpers ──
/**
 * Expand simple glob patterns ('*' in directory names and file patterns).
 */
function expandGlob(dirPath) {
    if (!dirPath.includes('*'))
        return [dirPath];
    const parts = dirPath.split(path.sep);
    let current = [parts[0] === '' ? '/' : parts[0]];
    for (let i = 1; i < parts.length; i++) {
        const part = parts[i];
        if (!part.includes('*')) {
            current = current.map(c => path.join(c, part));
        }
        else {
            // Expand wildcard by listing parent directories
            const expanded = [];
            for (const parent of current) {
                try {
                    const entries = fs.readdirSync(parent, { withFileTypes: true });
                    const regex = new RegExp('^' + part.replace(/\*/g, '.*') + '$');
                    for (const entry of entries) {
                        if (entry.isDirectory() && regex.test(entry.name)) {
                            expanded.push(path.join(parent, entry.name));
                        }
                    }
                }
                catch { }
            }
            current = expanded;
        }
    }
    return current;
}
/**
 * Find files matching patterns in a directory (non-recursive by default).
 */
function findFiles(dir, patterns) {
    const results = [];
    for (const pattern of patterns) {
        if (pattern.includes('/')) {
            // Pattern with subdirectory (e.g. "wallets/*/wallet.dat")
            const subParts = pattern.split('/');
            let dirs = [dir];
            for (let i = 0; i < subParts.length - 1; i++) {
                const p = subParts[i];
                const nextDirs = [];
                for (const d of dirs) {
                    if (p === '*' || p.includes('*')) {
                        try {
                            const entries = fs.readdirSync(d, { withFileTypes: true });
                            const regex = new RegExp('^' + p.replace(/\*/g, '.*') + '$');
                            for (const e of entries) {
                                if (e.isDirectory() && regex.test(e.name)) {
                                    nextDirs.push(path.join(d, e.name));
                                }
                            }
                        }
                        catch { }
                    }
                    else {
                        nextDirs.push(path.join(d, p));
                    }
                }
                dirs = nextDirs;
            }
            const filePattern = subParts[subParts.length - 1];
            const regex = new RegExp('^' + filePattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
            for (const d of dirs) {
                try {
                    const entries = fs.readdirSync(d, { withFileTypes: true });
                    for (const e of entries) {
                        if (e.isFile() && regex.test(e.name)) {
                            results.push(path.join(d, e.name));
                        }
                    }
                }
                catch { }
            }
        }
        else {
            // Simple file pattern in the directory
            const regex = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const e of entries) {
                    if (e.isFile() && regex.test(e.name)) {
                        results.push(path.join(dir, e.name));
                    }
                }
            }
            catch { }
        }
    }
    return results;
}
// ── Public API ──
/**
 * Get all known search paths for a format.
 */
export function getFormatPaths(formatId) {
    return FORMAT_PATHS.filter(fp => fp.id === formatId);
}
/**
 * Get all known search paths grouped by category.
 */
export function getPathsByCategory(category) {
    if (category)
        return FORMAT_PATHS.filter(fp => fp.category === category);
    return [...FORMAT_PATHS];
}
/**
 * Scan the system for a specific format and return found files.
 */
export function scanFormat(formatId) {
    const formatDefs = FORMAT_PATHS.filter(fp => fp.id === formatId);
    if (formatDefs.length === 0) {
        return { formatId, formatName: formatId, found: [], searchedPaths: [] };
    }
    const found = [];
    const searchedPaths = [];
    for (const def of formatDefs) {
        for (const rawPath of def.paths) {
            const expandedDirs = expandGlob(rawPath);
            for (const dir of expandedDirs) {
                searchedPaths.push(dir);
                if (!fs.existsSync(dir))
                    continue;
                const stat = fs.statSync(dir);
                if (stat.isFile()) {
                    // Path is a file directly
                    addFile(found, def, dir);
                }
                else if (stat.isDirectory()) {
                    if (def.filePatterns) {
                        const files = findFiles(dir, def.filePatterns);
                        for (const fp of files)
                            addFile(found, def, fp);
                    }
                    else {
                        // For formats like MetaMask where the directory IS the target
                        found.push({
                            formatId: def.id,
                            formatName: def.name,
                            category: def.category,
                            filePath: dir,
                            size: 0,
                            modified: stat.mtime,
                            encrypted: true,
                            note: def.note,
                        });
                    }
                }
            }
        }
    }
    // Deduplicate by filePath
    const unique = [...new Map(found.map(f => [f.filePath, f])).values()];
    return {
        formatId,
        formatName: formatDefs[0].name,
        found: unique,
        searchedPaths,
    };
}
/**
 * Scan ALL formats and return everything found on the system.
 */
export function scanAll() {
    const formatIds = [...new Set(FORMAT_PATHS.map(fp => fp.id))];
    return formatIds.map(id => scanFormat(id));
}
/**
 * Scan a specific category.
 */
export function scanCategory(category) {
    const formatIds = [...new Set(FORMAT_PATHS.filter(fp => fp.category === category).map(fp => fp.id))];
    return formatIds.map(id => scanFormat(id));
}
/**
 * Copy a found file to a working directory for cracking.
 */
export function extractFile(source, outputDir, formatId) {
    fs.mkdirSync(outputDir, { recursive: true });
    const basename = path.basename(source);
    const prefix = formatId ? `${formatId}_` : '';
    const destName = `${prefix}${basename}`;
    const dest = path.join(outputDir, destName);
    fs.copyFileSync(source, dest);
    return dest;
}
/**
 * Get all supported categories.
 */
export function getCategories() {
    return [
        { id: 'wallet', name: 'Crypto Wallets', formats: ['metamask', 'bitcoin-core', 'ethereum-keystore', 'electrum', 'exodus', 'multicoin'] },
        { id: 'password-manager', name: 'Password Managers', formats: ['keepass', '1password', 'bitwarden', 'lastpass'] },
        { id: 'archive', name: 'Archives', formats: ['zip', 'rar', '7zip'] },
        { id: 'document', name: 'Documents', formats: ['pdf', 'office'] },
        { id: 'disk', name: 'Disk Encryption', formats: ['veracrypt', 'dmg', 'luks', 'filevault', 'bitlocker'] },
        { id: 'network', name: 'Network', formats: ['wifi', 'ssh'] },
        { id: 'mobile', name: 'Mobile', formats: ['iphone-backup'] },
    ];
}
// ── Internal ──
function addFile(found, def, filePath) {
    try {
        const stat = fs.statSync(filePath);
        const encrypted = def.isEncrypted ? def.isEncrypted(filePath) : true;
        found.push({
            formatId: def.id,
            formatName: def.name,
            category: def.category,
            filePath,
            size: stat.size,
            modified: stat.mtime,
            encrypted,
            note: def.note,
        });
    }
    catch { }
}
//# sourceMappingURL=extractor.js.map