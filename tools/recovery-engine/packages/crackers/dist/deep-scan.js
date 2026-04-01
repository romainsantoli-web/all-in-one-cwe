/**
 * Deep Recovery Scanner
 *
 * Forensic-grade scanner that searches beyond default paths:
 * - Time Machine backups
 * - Chrome / Brave / Firefox Sync data
 * - iCloud Drive
 * - Mounted external volumes
 * - Spotlight / mdfind (macOS)
 * - Old user profiles
 * - Trash
 * - USB drives & external disks
 *
 * Designed for the scenario: "I changed computers and lost my vault"
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';
const HOME = os.homedir();
const platform = os.platform();
const DEFAULT_OPTIONS = {
    formats: [],
    maxDepth: 6,
    timeMachine: true,
    externalVolumes: true,
    icloud: true,
    trash: true,
    spotlight: true,
    firefox: true,
    allProfiles: true,
    onProgress: () => { },
};
const VAULT_SIGNATURES = [
    // MetaMask (LevelDB directory)
    {
        formatId: 'metamask',
        name: 'MetaMask Vault',
        fileNames: ['nkbihfbeogaeaoehlefnkodbefgpgknn'],
        isDirectory: true,
    },
    // Bitcoin Core
    {
        formatId: 'bitcoin-core',
        name: 'Bitcoin Core Wallet',
        fileNames: ['wallet.dat'],
        parentDirNames: ['Bitcoin', '.bitcoin', 'wallets'],
        magicBytes: [Buffer.from('mkey')],
    },
    // Ethereum keystore
    {
        formatId: 'ethereum-keystore',
        name: 'Ethereum Keystore',
        fileNames: [], // UUIDs, matched by content
        parentDirNames: ['keystore', 'keystores'],
        textMarkers: ['"crypto"', '"kdf"', '"ciphertext"'],
    },
    // Electrum
    {
        formatId: 'electrum',
        name: 'Electrum Wallet',
        fileNames: ['default_wallet', 'electrum.dat'],
        parentDirNames: ['Electrum', 'electrum', '.electrum'],
    },
    // Exodus
    {
        formatId: 'exodus',
        name: 'Exodus Wallet',
        fileNames: ['seed.seco', 'passphrase.seco'],
        parentDirNames: ['Exodus', 'exodus'],
    },
    // KeePass
    {
        formatId: 'keepass',
        name: 'KeePass Database',
        fileNames: ['*.kdbx', '*.kdb'],
        magicBytes: [Buffer.from([0x03, 0xd9, 0xa2, 0x9a])],
    },
    // 1Password
    {
        formatId: '1password',
        name: '1Password Vault',
        fileNames: ['*.opvault', '*.agilekeychain', '1password.sqlite'],
        parentDirNames: ['1Password', '1password'],
    },
    // Bitwarden
    {
        formatId: 'bitwarden',
        name: 'Bitwarden Vault',
        fileNames: ['data.json', 'bitwarden_export*.json'],
        parentDirNames: ['Bitwarden', 'bitwarden'],
        textMarkers: ['"encKeyValidation_DO_NOT_EDIT"'],
    },
    // LastPass
    {
        formatId: 'lastpass',
        name: 'LastPass Export',
        fileNames: ['lastpass_export*.csv', 'lastpass_vault*.dat'],
    },
    // SSH keys
    {
        formatId: 'ssh',
        name: 'SSH Private Key',
        fileNames: ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '*.pem'],
        parentDirNames: ['.ssh'],
        textMarkers: ['ENCRYPTED'],
    },
    // VeraCrypt
    {
        formatId: 'veracrypt',
        name: 'VeraCrypt Container',
        fileNames: ['*.hc', '*.tc', '*.vol'],
    },
    // iPhone backup
    {
        formatId: 'iphone-backup',
        name: 'iPhone Backup',
        fileNames: ['Manifest.plist', 'Manifest.db'],
        parentDirNames: ['MobileSync', 'Backup'],
        textMarkers: ['BackupKeyBag'],
    },
    // ZIP encrypted
    {
        formatId: 'zip',
        name: 'Encrypted ZIP',
        fileNames: ['*.zip'],
        magicBytes: [Buffer.from([0x50, 0x4b, 0x03, 0x04])],
    },
];
// ── Core Deep Scanner ──
export class DeepScanner {
    opts;
    results = [];
    visited = new Set();
    constructor(options) {
        this.opts = { ...DEFAULT_OPTIONS, ...options };
    }
    /**
     * Run the full deep scan. Returns all found vault/wallet files.
     */
    async scan() {
        this.results = [];
        this.visited.clear();
        // 1. Time Machine
        if (this.opts.timeMachine && platform === 'darwin') {
            this.emit('🕐 Scanning Time Machine backups...');
            this.scanTimeMachine();
        }
        // 2. All Chrome/Brave profiles (not just Default)
        if (this.opts.allProfiles) {
            this.emit('🌐 Scanning all browser profiles...');
            this.scanAllBrowserProfiles();
        }
        // 3. Firefox profiles
        if (this.opts.firefox) {
            this.emit('🦊 Scanning Firefox profiles...');
            this.scanFirefoxProfiles();
        }
        // 4. iCloud
        if (this.opts.icloud && platform === 'darwin') {
            this.emit('☁️  Scanning iCloud Drive...');
            this.scanICloud();
        }
        // 5. External volumes
        if (this.opts.externalVolumes) {
            this.emit('💾 Scanning external volumes...');
            this.scanExternalVolumes();
        }
        // 6. Trash
        if (this.opts.trash) {
            this.emit('🗑️  Scanning Trash...');
            this.scanTrash();
        }
        // 7. Spotlight (macOS only — fast indexed search)
        if (this.opts.spotlight && platform === 'darwin') {
            this.emit('🔍 Spotlight search for known vault files...');
            this.scanSpotlight();
        }
        // 8. Old user profiles on the same machine
        this.emit('👤 Scanning other user profiles...');
        this.scanOldProfiles();
        // 9. Local backup directories
        this.emit('📂 Scanning common backup locations...');
        this.scanLocalBackups();
        // Deduplicate
        const unique = this.dedup();
        return unique;
    }
    // ── Time Machine ──
    scanTimeMachine() {
        // Time Machine backup paths on macOS
        const tmPaths = [
            '/Volumes/Time Machine Backups',
            '/Volumes/TimeMachine',
        ];
        // Also check tmutil to find the backup destination
        try {
            const tmDest = execSync('tmutil destinationinfo 2>/dev/null', { encoding: 'utf-8' });
            const mountMatch = tmDest.match(/Mount Point\s*:\s*(.+)/);
            if (mountMatch) {
                tmPaths.push(mountMatch[1].trim());
            }
        }
        catch { }
        // Find actual backup root
        try {
            const latestLink = execSync('tmutil latestbackup 2>/dev/null', { encoding: 'utf-8' }).trim();
            if (latestLink && fs.existsSync(latestLink)) {
                this.emit(`  Time Machine latest: ${latestLink}`);
                this.scanTimeMachineBackup(latestLink, 'latest');
            }
        }
        catch { }
        // List all backups
        try {
            const allBackups = execSync('tmutil listbackups 2>/dev/null', { encoding: 'utf-8' })
                .trim().split('\n').filter(Boolean);
            // Scan last 5 backups max to keep it reasonable
            const recentBackups = allBackups.slice(-5);
            for (const backup of recentBackups) {
                if (fs.existsSync(backup)) {
                    const dateMatch = backup.match(/(\d{4}-\d{2}-\d{2})/);
                    const label = dateMatch ? dateMatch[1] : path.basename(backup);
                    this.emit(`  Scanning backup: ${label}`);
                    this.scanTimeMachineBackup(backup, label);
                }
            }
        }
        catch { }
        // Manually scan known TM volume paths
        for (const tmRoot of tmPaths) {
            if (!fs.existsSync(tmRoot))
                continue;
            try {
                // Look for Backups.backupdb/<hostname>/
                const backupDb = path.join(tmRoot, 'Backups.backupdb');
                if (fs.existsSync(backupDb)) {
                    const hosts = safeReaddir(backupDb);
                    for (const host of hosts) {
                        const hostDir = path.join(backupDb, host);
                        if (!fs.statSync(hostDir).isDirectory())
                            continue;
                        const snapshots = safeReaddir(hostDir).slice(-3); // last 3
                        for (const snap of snapshots) {
                            const snapDir = path.join(hostDir, snap);
                            this.scanTimeMachineBackup(snapDir, `${host}/${snap}`);
                        }
                    }
                }
            }
            catch { }
        }
    }
    scanTimeMachineBackup(backupRoot, label) {
        // Inside a TM backup, the structure mirrors the original filesystem
        // Look for the user's home directory within the backup
        const username = path.basename(HOME);
        const possibleHomes = [
            path.join(backupRoot, 'Macintosh HD', 'Users', username),
            path.join(backupRoot, 'Macintosh HD - Data', 'Users', username),
            path.join(backupRoot, 'Data', 'Users', username),
            path.join(backupRoot, 'Users', username),
        ];
        for (const homeDir of possibleHomes) {
            if (!fs.existsSync(homeDir))
                continue;
            // Chrome / Brave / Edge MetaMask extension data
            const browserPaths = [
                'Library/Application Support/Google/Chrome',
                'Library/Application Support/BraveSoftware/Brave-Browser',
                'Library/Application Support/Microsoft Edge',
                'Library/Application Support/Vivaldi',
                'Library/Application Support/Opera',
            ];
            for (const browserRel of browserPaths) {
                const browserDir = path.join(homeDir, browserRel);
                if (!fs.existsSync(browserDir))
                    continue;
                // Scan all profiles in this browser
                const profiles = safeReaddir(browserDir).filter(p => p === 'Default' || p.startsWith('Profile '));
                for (const profile of profiles) {
                    const mmDir = path.join(browserDir, profile, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn');
                    if (fs.existsSync(mmDir)) {
                        this.addResult({
                            filePath: mmDir,
                            source: `Time Machine ${label} → ${path.basename(path.dirname(path.dirname(browserDir)))}/${profile}`,
                            sourceType: 'time-machine',
                            formatHint: 'metamask',
                            backupDate: parseDate(label),
                            encrypted: true,
                            confidence: 'high',
                            note: 'LevelDB vault in Time Machine backup',
                        });
                    }
                }
            }
            // Bitcoin Core
            const btcDir = path.join(homeDir, 'Library/Application Support/Bitcoin');
            if (fs.existsSync(btcDir)) {
                this.scanDirForSignature(btcDir, 'bitcoin-core', `Time Machine ${label}`, 'time-machine');
            }
            // Electrum
            const electrumDir = path.join(homeDir, 'Library/Application Support/Electrum');
            if (fs.existsSync(electrumDir)) {
                this.scanDirForSignature(electrumDir, 'electrum', `Time Machine ${label}`, 'time-machine');
            }
            // Exodus
            const exodusDir = path.join(homeDir, 'Library/Application Support/Exodus');
            if (fs.existsSync(exodusDir)) {
                this.scanDirForSignature(exodusDir, 'exodus', `Time Machine ${label}`, 'time-machine');
            }
            // KeePass databases
            for (const dir of ['Documents', 'Desktop', 'Downloads']) {
                const target = path.join(homeDir, dir);
                if (fs.existsSync(target)) {
                    this.scanDirForSignature(target, 'keepass', `Time Machine ${label}`, 'time-machine');
                }
            }
            // SSH keys
            const sshDir = path.join(homeDir, '.ssh');
            if (fs.existsSync(sshDir)) {
                this.scanDirForSignature(sshDir, 'ssh', `Time Machine ${label}`, 'time-machine');
            }
            // iPhone backups
            const iphoneDir = path.join(homeDir, 'Library/Application Support/MobileSync/Backup');
            if (fs.existsSync(iphoneDir)) {
                this.scanDirForSignature(iphoneDir, 'iphone-backup', `Time Machine ${label}`, 'time-machine');
            }
            // Ethereum keystore
            const ethDir = path.join(homeDir, 'Library/Ethereum/keystore');
            if (fs.existsSync(ethDir)) {
                this.scanDirForSignature(ethDir, 'ethereum-keystore', `Time Machine ${label}`, 'time-machine');
            }
        }
    }
    // ── All Browser Profiles ──
    scanAllBrowserProfiles() {
        const browsers = platform === 'darwin' ? [
            { name: 'Chrome', dir: `${HOME}/Library/Application Support/Google/Chrome` },
            { name: 'Brave', dir: `${HOME}/Library/Application Support/BraveSoftware/Brave-Browser` },
            { name: 'Edge', dir: `${HOME}/Library/Application Support/Microsoft Edge` },
            { name: 'Vivaldi', dir: `${HOME}/Library/Application Support/Vivaldi` },
            { name: 'Opera', dir: `${HOME}/Library/Application Support/Opera` },
            { name: 'Chromium', dir: `${HOME}/Library/Application Support/Chromium` },
        ] : platform === 'linux' ? [
            { name: 'Chrome', dir: `${HOME}/.config/google-chrome` },
            { name: 'Brave', dir: `${HOME}/.config/BraveSoftware/Brave-Browser` },
            { name: 'Edge', dir: `${HOME}/.config/microsoft-edge` },
            { name: 'Chromium', dir: `${HOME}/.config/chromium` },
        ] : [
            { name: 'Chrome', dir: `${HOME}/AppData/Local/Google/Chrome/User Data` },
            { name: 'Brave', dir: `${HOME}/AppData/Local/BraveSoftware/Brave-Browser/User Data` },
            { name: 'Edge', dir: `${HOME}/AppData/Local/Microsoft/Edge/User Data` },
        ];
        for (const browser of browsers) {
            if (!fs.existsSync(browser.dir))
                continue;
            const entries = safeReaddir(browser.dir);
            const profiles = entries.filter(e => e === 'Default' || e.startsWith('Profile ') || e === 'Guest Profile');
            for (const profile of profiles) {
                // MetaMask
                const mmDir = path.join(browser.dir, profile, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn');
                if (fs.existsSync(mmDir)) {
                    this.addResult({
                        filePath: mmDir,
                        source: `${browser.name} / ${profile}`,
                        sourceType: 'chrome-sync',
                        formatHint: 'metamask',
                        encrypted: true,
                        confidence: 'high',
                        note: `LevelDB in ${browser.name} ${profile}`,
                    });
                }
                // Other Chromium wallet extensions
                const walletExtensions = {
                    // Phantom
                    'bfnaelmomeimhlpmgjnjophhpkkoljpa': 'Phantom',
                    // Trust Wallet
                    'egjidjbpglichdcondbcbdnbeeppgdph': 'Trust Wallet',
                    // Coinbase
                    'hnfanknocfeofbddgcijnmhnfnkdnaad': 'Coinbase Wallet',
                    // Rabby
                    'acmacodkjbdgmoleebolmdjonilkdbch': 'Rabby Wallet',
                };
                const extSettingsDir = path.join(browser.dir, profile, 'Local Extension Settings');
                if (fs.existsSync(extSettingsDir)) {
                    for (const [extId, name] of Object.entries(walletExtensions)) {
                        const extDir = path.join(extSettingsDir, extId);
                        if (fs.existsSync(extDir)) {
                            this.addResult({
                                filePath: extDir,
                                source: `${browser.name} / ${profile}`,
                                sourceType: 'chrome-sync',
                                formatHint: 'metamask', // Same LevelDB vault format
                                encrypted: true,
                                confidence: 'high',
                                note: `${name} extension in ${browser.name} ${profile}`,
                            });
                        }
                    }
                }
                // Bitwarden extension
                const bwDir = path.join(browser.dir, profile, 'Local Extension Settings', 'nngceckbapebfimnlniiiahkandclblb');
                if (fs.existsSync(bwDir)) {
                    this.addResult({
                        filePath: bwDir,
                        source: `${browser.name} / ${profile}`,
                        sourceType: 'chrome-sync',
                        formatHint: 'bitwarden',
                        encrypted: true,
                        confidence: 'medium',
                        note: `Bitwarden extension in ${browser.name}`,
                    });
                }
            }
        }
    }
    // ── Firefox ──
    scanFirefoxProfiles() {
        const ffDir = platform === 'darwin'
            ? `${HOME}/Library/Application Support/Firefox/Profiles`
            : platform === 'linux'
                ? `${HOME}/.mozilla/firefox`
                : `${HOME}/AppData/Roaming/Mozilla/Firefox/Profiles`;
        if (!fs.existsSync(ffDir))
            return;
        const profiles = safeReaddir(ffDir);
        for (const profile of profiles) {
            const profileDir = path.join(ffDir, profile);
            if (!safeStat(profileDir)?.isDirectory())
                continue;
            // Firefox wallet extensions (MetaMask for Firefox)
            // MetaMask stores data in browser extension storage
            const extStorageDir = path.join(profileDir, 'storage', 'default');
            if (fs.existsSync(extStorageDir)) {
                const mmFirefoxIds = [
                    'moz-extension', // generic prefix
                    'webextension@metamask.io',
                ];
                const extDirs = safeReaddir(extStorageDir);
                for (const d of extDirs) {
                    if (d.includes('metamask') || d.includes('webextension')) {
                        const idbDir = path.join(extStorageDir, d, 'idb');
                        if (fs.existsSync(idbDir)) {
                            this.addResult({
                                filePath: idbDir,
                                source: `Firefox / ${profile}`,
                                sourceType: 'firefox-profile',
                                formatHint: 'metamask',
                                encrypted: true,
                                confidence: 'medium',
                                note: 'MetaMask Firefox extension IndexedDB',
                            });
                        }
                    }
                }
            }
            // Firefox logins.json (encrypted passwords)
            const loginsJson = path.join(profileDir, 'logins.json');
            if (fs.existsSync(loginsJson)) {
                this.addResult({
                    filePath: loginsJson,
                    source: `Firefox / ${profile}`,
                    sourceType: 'firefox-profile',
                    formatHint: 'firefox-logins',
                    encrypted: true,
                    confidence: 'medium',
                    note: 'Firefox encrypted passwords (key4.db required)',
                });
            }
            // key4.db (Firefox master password / encryption key)
            const key4 = path.join(profileDir, 'key4.db');
            if (fs.existsSync(key4)) {
                this.addResult({
                    filePath: key4,
                    source: `Firefox / ${profile}`,
                    sourceType: 'firefox-profile',
                    formatHint: 'firefox-key4',
                    encrypted: true,
                    confidence: 'medium',
                    note: 'Firefox master key database',
                });
            }
        }
    }
    // ── iCloud ──
    scanICloud() {
        const icloudDirs = [
            `${HOME}/Library/Mobile Documents/com~apple~CloudDocs`,
            `${HOME}/Library/Mobile Documents`,
            `${HOME}/iCloud Drive`,
        ];
        for (const icloudDir of icloudDirs) {
            if (!fs.existsSync(icloudDir))
                continue;
            this.recursiveScan(icloudDir, 'iCloud Drive', 'icloud', 0);
        }
    }
    // ── External Volumes ──
    scanExternalVolumes() {
        const volumePaths = platform === 'darwin'
            ? ['/Volumes']
            : platform === 'linux'
                ? ['/mnt', '/media', `/media/${path.basename(HOME)}`]
                : ['D:', 'E:', 'F:', 'G:', 'H:'];
        for (const volumeRoot of volumePaths) {
            if (!fs.existsSync(volumeRoot))
                continue;
            if (platform === 'darwin') {
                // Skip the main volume (Macintosh HD)
                const volumes = safeReaddir(volumeRoot).filter(v => v !== 'Macintosh HD' && v !== 'Macintosh HD - Data' && v !== 'Recovery');
                for (const vol of volumes) {
                    const volPath = path.join(volumeRoot, vol);
                    if (!safeStat(volPath)?.isDirectory())
                        continue;
                    this.emit(`  Volume: ${vol}`);
                    this.recursiveScan(volPath, `Volume: ${vol}`, 'external-volume', 0);
                    // Check if it has a Users directory (old Mac drive)
                    const usersDir = path.join(volPath, 'Users');
                    if (fs.existsSync(usersDir)) {
                        const users = safeReaddir(usersDir);
                        for (const user of users) {
                            if (user === 'Shared' || user.startsWith('.'))
                                continue;
                            this.scanHomeDir(path.join(usersDir, user), `Volume: ${vol} / ${user}`, 'external-volume');
                        }
                    }
                }
            }
            else {
                // Linux: scan each mount point
                const mounts = safeReaddir(volumeRoot);
                for (const m of mounts) {
                    const mountPath = path.join(volumeRoot, m);
                    if (safeStat(mountPath)?.isDirectory()) {
                        this.emit(`  Mount: ${mountPath}`);
                        this.recursiveScan(mountPath, `Mount: ${m}`, 'external-volume', 0);
                    }
                }
            }
        }
    }
    // ── Trash ──
    scanTrash() {
        const trashDirs = platform === 'darwin'
            ? [`${HOME}/.Trash`]
            : platform === 'linux'
                ? [`${HOME}/.local/share/Trash/files`]
                : [`${HOME}/AppData/Local/Microsoft/Windows/Explorer`]; // Simplified
        for (const trashDir of trashDirs) {
            if (!fs.existsSync(trashDir))
                continue;
            this.recursiveScan(trashDir, 'Trash', 'trash', 0);
        }
    }
    // ── Spotlight (macOS fast indexed search) ──
    scanSpotlight() {
        // Use mdfind to quickly locate vault-related files
        const queries = [
            { q: 'kMDItemFSName == "nkbihfbeogaeaoehlefnkodbefgpgknn"', fmt: 'metamask', name: 'MetaMask LevelDB' },
            { q: 'kMDItemFSName == "wallet.dat"', fmt: 'bitcoin-core', name: 'Bitcoin wallet.dat' },
            { q: 'kMDItemFSName == "*.kdbx"wc', fmt: 'keepass', name: 'KeePass' },
            { q: 'kMDItemFSName == "seed.seco"', fmt: 'exodus', name: 'Exodus seed' },
            { q: 'kMDItemFSName == "default_wallet" && kMDItemContentType != "public.folder"', fmt: 'electrum', name: 'Electrum wallet' },
            { q: 'kMDItemFSName == "Manifest.plist" && kMDItemFSName == "*BackupKeyBag*"', fmt: 'iphone-backup', name: 'iPhone backup' },
            { q: 'kMDItemFSName == "*.opvault"', fmt: '1password', name: '1Password vault' },
        ];
        // Also search by extension
        const extQueries = [
            { ext: 'kdbx', fmt: 'keepass', name: 'KeePass Database' },
            { ext: 'opvault', fmt: '1password', name: '1Password Vault' },
            { ext: 'seco', fmt: 'exodus', name: 'Exodus Seed' },
            { ext: 'hc', fmt: 'veracrypt', name: 'VeraCrypt Container' },
            { ext: 'tc', fmt: 'veracrypt', name: 'TrueCrypt Container' },
        ];
        for (const eq of extQueries) {
            try {
                const output = execSync(`mdfind "kMDItemFSName == '*.${eq.ext}'" 2>/dev/null`, {
                    encoding: 'utf-8',
                    timeout: 5000,
                }).trim();
                if (!output)
                    continue;
                const files = output.split('\n').filter(Boolean);
                for (const f of files) {
                    if (!fs.existsSync(f))
                        continue;
                    this.addResult({
                        filePath: f,
                        source: `Spotlight: *.${eq.ext}`,
                        sourceType: 'spotlight',
                        formatHint: eq.fmt,
                        encrypted: true,
                        confidence: 'medium',
                        note: eq.name,
                    });
                }
            }
            catch { }
        }
        // Search for MetaMask extension ID anywhere on disk
        try {
            const mmResults = execSync('mdfind "kMDItemFSName == nkbihfbeogaeaoehlefnkodbefgpgknn" 2>/dev/null', { encoding: 'utf-8', timeout: 10000 }).trim();
            if (mmResults) {
                for (const f of mmResults.split('\n').filter(Boolean)) {
                    if (!fs.existsSync(f))
                        continue;
                    this.addResult({
                        filePath: f,
                        source: 'Spotlight: MetaMask extension ID',
                        sourceType: 'spotlight',
                        formatHint: 'metamask',
                        encrypted: true,
                        confidence: 'high',
                        note: 'MetaMask LevelDB found via Spotlight',
                    });
                }
            }
        }
        catch { }
        // Search for wallet.dat
        try {
            const walletResults = execSync('mdfind "kMDItemFSName == wallet.dat" 2>/dev/null', { encoding: 'utf-8', timeout: 10000 }).trim();
            if (walletResults) {
                for (const f of walletResults.split('\n').filter(Boolean)) {
                    if (!fs.existsSync(f))
                        continue;
                    // Check if it's actually a Bitcoin wallet
                    try {
                        const buf = fs.readFileSync(f);
                        if (buf.includes(Buffer.from('mkey'))) {
                            this.addResult({
                                filePath: f,
                                source: 'Spotlight: wallet.dat',
                                sourceType: 'spotlight',
                                formatHint: 'bitcoin-core',
                                encrypted: true,
                                confidence: 'high',
                                note: 'Encrypted Bitcoin Core wallet',
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }
    // ── Old User Profiles ──
    scanOldProfiles() {
        if (platform === 'darwin' || platform === 'linux') {
            const usersDir = platform === 'darwin' ? '/Users' : '/home';
            if (!fs.existsSync(usersDir))
                return;
            const currentUser = path.basename(HOME);
            const users = safeReaddir(usersDir).filter(u => u !== currentUser && u !== 'Shared' && u !== 'Guest' && !u.startsWith('.'));
            for (const user of users) {
                const userHome = path.join(usersDir, user);
                this.scanHomeDir(userHome, `User: ${user}`, 'old-profile');
            }
        }
    }
    // ── Local Backup Directories ──
    scanLocalBackups() {
        const backupDirs = [
            `${HOME}/Desktop`,
            `${HOME}/Documents`,
            `${HOME}/Downloads`,
            `${HOME}/Documents/Backups`,
            `${HOME}/Documents/backup`,
            `${HOME}/Documents/crypto`,
            `${HOME}/Documents/wallets`,
            `${HOME}/Desktop/backup`,
            `${HOME}/Desktop/crypto`,
            `${HOME}/Desktop/wallets`,
        ];
        for (const dir of backupDirs) {
            if (!fs.existsSync(dir))
                continue;
            this.recursiveScan(dir, `Local: ${path.basename(dir)}`, 'local-backup', 0);
        }
    }
    // ── Helper: scan a home directory for known vault locations ──
    scanHomeDir(homeDir, source, sourceType) {
        if (!fs.existsSync(homeDir))
            return;
        // Browser profiles
        const browserPaths = platform === 'darwin' ? [
            'Library/Application Support/Google/Chrome',
            'Library/Application Support/BraveSoftware/Brave-Browser',
            'Library/Application Support/Microsoft Edge',
        ] : platform === 'linux' ? [
            '.config/google-chrome',
            '.config/BraveSoftware/Brave-Browser',
        ] : [
            'AppData/Local/Google/Chrome/User Data',
        ];
        for (const bp of browserPaths) {
            const browserDir = path.join(homeDir, bp);
            if (!fs.existsSync(browserDir))
                continue;
            const profiles = safeReaddir(browserDir).filter(p => p === 'Default' || p.startsWith('Profile '));
            for (const profile of profiles) {
                const mmDir = path.join(browserDir, profile, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn');
                if (fs.existsSync(mmDir)) {
                    this.addResult({
                        filePath: mmDir,
                        source: `${source} → ${path.basename(bp).split('/')[0]}/${profile}`,
                        sourceType,
                        formatHint: 'metamask',
                        encrypted: true,
                        confidence: 'high',
                        note: 'MetaMask LevelDB vault',
                    });
                }
            }
        }
        // Crypto wallets
        const walletPaths = platform === 'darwin' ? [
            { rel: 'Library/Application Support/Bitcoin', fmt: 'bitcoin-core' },
            { rel: 'Library/Application Support/Electrum', fmt: 'electrum' },
            { rel: 'Library/Application Support/Exodus', fmt: 'exodus' },
            { rel: 'Library/Ethereum/keystore', fmt: 'ethereum-keystore' },
            { rel: 'Library/Application Support/MobileSync/Backup', fmt: 'iphone-backup' },
        ] : [
            { rel: '.bitcoin', fmt: 'bitcoin-core' },
            { rel: '.electrum', fmt: 'electrum' },
            { rel: '.config/Exodus', fmt: 'exodus' },
            { rel: '.ethereum/keystore', fmt: 'ethereum-keystore' },
        ];
        for (const wp of walletPaths) {
            const dir = path.join(homeDir, wp.rel);
            if (fs.existsSync(dir)) {
                this.scanDirForSignature(dir, wp.fmt, source, sourceType);
            }
        }
        // SSH keys
        const sshDir = path.join(homeDir, '.ssh');
        if (fs.existsSync(sshDir)) {
            this.scanDirForSignature(sshDir, 'ssh', source, sourceType);
        }
    }
    // ── Recursive scanner with signature matching ──
    recursiveScan(dir, source, sourceType, depth) {
        if (depth > this.opts.maxDepth)
            return;
        if (this.visited.has(dir))
            return;
        this.visited.add(dir);
        let entries;
        try {
            entries = fs.readdirSync(dir);
        }
        catch {
            return;
        }
        for (const entry of entries) {
            // Skip hidden dirs (except .ssh, .bitcoin, .electrum, etc.)
            if (entry.startsWith('.') && !['.ssh', '.bitcoin', '.electrum', '.ethereum', '.gnupg', '.lastpass', '.config'].includes(entry))
                continue;
            // Skip node_modules, .git, etc.
            if (['node_modules', '.git', '.Spotlight-V100', '.fseventsd', '__pycache__'].includes(entry))
                continue;
            const fullPath = path.join(dir, entry);
            const stat = safeStat(fullPath);
            if (!stat)
                continue;
            // Check against all signatures
            for (const sig of VAULT_SIGNATURES) {
                // Filter by requested formats
                if (this.opts.formats.length > 0 && !this.opts.formats.includes(sig.formatId))
                    continue;
                if (sig.isDirectory && stat.isDirectory()) {
                    // Directory match (e.g., MetaMask extension ID)
                    if (matchFileName(entry, sig.fileNames)) {
                        this.addResult({
                            filePath: fullPath,
                            source,
                            sourceType,
                            formatHint: sig.formatId,
                            encrypted: true,
                            confidence: 'high',
                            note: sig.name,
                        });
                    }
                }
                else if (stat.isFile()) {
                    if (matchFileName(entry, sig.fileNames)) {
                        // Name match — verify content if possible
                        const confidence = this.verifyFile(fullPath, sig);
                        this.addResult({
                            filePath: fullPath,
                            source,
                            sourceType,
                            formatHint: sig.formatId,
                            encrypted: true,
                            confidence,
                            note: sig.name,
                        });
                    }
                }
            }
            // Recurse into subdirectories
            if (stat.isDirectory()) {
                this.recursiveScan(fullPath, source, sourceType, depth + 1);
            }
        }
    }
    // ── Scan a directory for files matching a format signature ──
    scanDirForSignature(dir, formatId, source, sourceType) {
        const sig = VAULT_SIGNATURES.find(s => s.formatId === formatId);
        if (!sig)
            return;
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (sig.isDirectory && entry.isDirectory() && matchFileName(entry.name, sig.fileNames)) {
                    this.addResult({ filePath: fullPath, source, sourceType, formatHint: formatId, encrypted: true, confidence: 'high', note: sig.name });
                }
                else if (entry.isFile() && matchFileName(entry.name, sig.fileNames)) {
                    const confidence = this.verifyFile(fullPath, sig);
                    this.addResult({ filePath: fullPath, source, sourceType, formatHint: formatId, encrypted: true, confidence, note: sig.name });
                }
                else if (entry.isDirectory() && !entry.name.startsWith('.')) {
                    // One level deeper
                    try {
                        const subEntries = fs.readdirSync(fullPath, { withFileTypes: true });
                        for (const sub of subEntries) {
                            if (sub.isFile() && matchFileName(sub.name, sig.fileNames)) {
                                const subPath = path.join(fullPath, sub.name);
                                const confidence = this.verifyFile(subPath, sig);
                                this.addResult({ filePath: subPath, source, sourceType, formatHint: formatId, encrypted: true, confidence, note: sig.name });
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }
    // ── Verify a file matches the expected signature ──
    verifyFile(filePath, sig) {
        try {
            // Check magic bytes
            if (sig.magicBytes) {
                const fd = fs.openSync(filePath, 'r');
                const buf = Buffer.alloc(4096);
                const bytesRead = fs.readSync(fd, buf, 0, 4096, 0);
                fs.closeSync(fd);
                const content = buf.subarray(0, bytesRead);
                for (const magic of sig.magicBytes) {
                    if (content.includes(magic))
                        return 'high';
                }
            }
            // Check text markers
            if (sig.textMarkers) {
                const stat = fs.statSync(filePath);
                if (stat.size < 10 * 1024 * 1024) { // Only read files < 10MB
                    const content = fs.readFileSync(filePath, 'utf-8').slice(0, 50000);
                    for (const marker of sig.textMarkers) {
                        if (content.includes(marker))
                            return 'high';
                    }
                }
            }
            // Check parent directory name
            if (sig.parentDirNames) {
                const parentName = path.basename(path.dirname(filePath));
                if (sig.parentDirNames.includes(parentName))
                    return 'medium';
            }
            return 'low';
        }
        catch {
            return 'low';
        }
    }
    // ── Result management ──
    addResult(partial) {
        const stat = safeStat(partial.filePath);
        if (!stat)
            return;
        this.results.push({
            ...partial,
            size: stat.isDirectory() ? 0 : stat.size,
            modified: stat.mtime,
        });
    }
    dedup() {
        // Deduplicate by real path, keeping highest confidence
        const byPath = new Map();
        const confOrder = { high: 3, medium: 2, low: 1 };
        for (const r of this.results) {
            let realPath;
            try {
                realPath = fs.realpathSync(r.filePath);
            }
            catch {
                realPath = r.filePath;
            }
            const existing = byPath.get(realPath);
            if (!existing || confOrder[r.confidence] > confOrder[existing.confidence]) {
                byPath.set(realPath, r);
            }
        }
        return [...byPath.values()].sort((a, b) => {
            // Sort: high confidence first, then by format, then by date
            const cDiff = confOrder[b.confidence] - confOrder[a.confidence];
            if (cDiff !== 0)
                return cDiff;
            if (a.formatHint !== b.formatHint)
                return a.formatHint.localeCompare(b.formatHint);
            return b.modified.getTime() - a.modified.getTime();
        });
    }
    emit(msg) {
        this.opts.onProgress(msg);
    }
}
// ── Utilities ──
function safeReaddir(dir) {
    try {
        return fs.readdirSync(dir);
    }
    catch {
        return [];
    }
}
function safeStat(p) {
    try {
        return fs.lstatSync(p);
    }
    catch {
        return null;
    }
}
function matchFileName(name, patterns) {
    for (const pat of patterns) {
        if (pat.includes('*')) {
            const regex = new RegExp('^' + pat.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$', 'i');
            if (regex.test(name))
                return true;
        }
        else {
            if (name === pat)
                return true;
        }
    }
    return false;
}
function parseDate(label) {
    const match = label.match(/(\d{4}-\d{2}-\d{2})/);
    if (match)
        return new Date(match[1]);
    return undefined;
}
//# sourceMappingURL=deep-scan.js.map