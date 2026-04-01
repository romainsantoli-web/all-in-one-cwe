/**
 * Vault Extractor — Reads and parses MetaMask encrypted vaults.
 *
 * Supports:
 * - Reading vault JSON pasted manually
 * - Reading from Chrome extension local storage (LevelDB on disk)
 * - Reading from chrome.storage.local (in extension context)
 * - Auto-detecting iteration count (900k modern / 10k legacy)
 */
const MODERN_ITERATIONS = 900_000;
const LEGACY_ITERATIONS = 10_000;
/** Default Chrome extension IDs for MetaMask */
const METAMASK_EXTENSION_IDS = [
    'nkbihfbeogaeaoehlefnkodbefgpgknn', // Chrome Web Store
    'ejbalbakoplchlghecdalmeeeajnimhm', // Flask (dev)
];
/** Default LevelDB paths per platform */
function getDefaultLevelDBPaths() {
    const paths = [];
    const home = typeof process !== 'undefined' ? process.env.HOME || process.env.USERPROFILE || '' : '';
    const platform = typeof process !== 'undefined' ? process.platform : '';
    for (const extId of METAMASK_EXTENSION_IDS) {
        if (platform === 'darwin') {
            paths.push(`${home}/Library/Application Support/Google/Chrome/Default/Local Extension Settings/${extId}`);
            paths.push(`${home}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Extension Settings/${extId}`);
        }
        else if (platform === 'win32') {
            const appData = process.env.LOCALAPPDATA || '';
            paths.push(`${appData}\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\${extId}`);
            paths.push(`${appData}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Extension Settings\\${extId}`);
        }
        else {
            // Linux
            paths.push(`${home}/.config/google-chrome/Default/Local Extension Settings/${extId}`);
            paths.push(`${home}/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/${extId}`);
        }
    }
    return paths;
}
export class VaultExtractor {
    /**
     * Parse a raw vault JSON string into a structured VaultData object.
     */
    static parseVaultJSON(jsonString) {
        let raw;
        try {
            raw = JSON.parse(jsonString);
        }
        catch {
            throw new Error('Invalid vault JSON: failed to parse');
        }
        if (!raw.data || !raw.iv || !raw.salt) {
            throw new Error('Invalid vault JSON: missing required fields (data, iv, salt)');
        }
        // Auto-detect iterations: check root-level field first, then keyMetadata, then fallback
        const rootIterations = typeof raw.iterations === 'number' && raw.iterations > 0
            ? raw.iterations
            : undefined;
        const metadataIterations = raw.keyMetadata?.params?.iterations;
        const iterations = rootIterations ?? metadataIterations ?? LEGACY_ITERATIONS;
        const isLegacy = iterations <= LEGACY_ITERATIONS;
        return {
            data: raw.data,
            iv: raw.iv,
            salt: raw.salt,
            iterations,
            isLegacy,
        };
    }
    /**
     * Extract the vault from a MetaMask state object.
     * The state is typically at: data.KeyringController.vault
     */
    static extractFromState(state) {
        // Try various paths where the vault can be found
        const paths = [
            ['data', 'KeyringController', 'vault'],
            ['KeyringController', 'vault'],
            ['vault'],
        ];
        for (const path of paths) {
            let current = state;
            let found = true;
            for (const key of path) {
                if (current && typeof current === 'object' && key in current) {
                    current = current[key];
                }
                else {
                    found = false;
                    break;
                }
            }
            if (found && typeof current === 'string') {
                return VaultExtractor.parseVaultJSON(current);
            }
        }
        throw new Error('Could not find vault in state object. Expected at data.KeyringController.vault');
    }
    /**
     * Read the vault from LevelDB files on disk (CLI only).
     * Requires 'classic-level' to be installed.
     */
    static async extractFromLevelDB(dbPath) {
        // Dynamic import so this module can also be used in browser context
        const { ClassicLevel } = await import('classic-level');
        const pathsToTry = dbPath ? [dbPath] : getDefaultLevelDBPaths();
        const errors = [];
        for (const path of pathsToTry) {
            try {
                const db = new ClassicLevel(path, { valueEncoding: 'utf8' });
                await db.open();
                try {
                    // MetaMask stores state under the 'data' key
                    const rawData = await db.get('data');
                    await db.close();
                    const state = JSON.parse(rawData);
                    return VaultExtractor.extractFromState(state);
                }
                catch (innerErr) {
                    await db.close().catch(() => { });
                    throw innerErr;
                }
            }
            catch (err) {
                errors.push(`${path}: ${err.message}`);
                continue;
            }
        }
        throw new Error(`Could not extract vault from LevelDB. Tried:\n${errors.join('\n')}`);
    }
    /**
     * Extract vault from Chrome extension storage (in extension context only).
     * Must be called from a Chrome extension with 'storage' permission.
     */
    static async extractFromExtensionStorage() {
        const chromeGlobal = globalThis.chrome;
        if (!chromeGlobal?.storage?.local) {
            throw new Error('chrome.storage.local not available — are you in a Chrome extension context?');
        }
        return new Promise((resolve, reject) => {
            chromeGlobal.storage.local.get('data', (result) => {
                if (chromeGlobal.runtime.lastError) {
                    reject(new Error(`Chrome storage error: ${chromeGlobal.runtime.lastError.message}`));
                    return;
                }
                if (!result.data) {
                    reject(new Error('No MetaMask data found in chrome.storage.local'));
                    return;
                }
                try {
                    const state = typeof result.data === 'string' ? JSON.parse(result.data) : result.data;
                    resolve(VaultExtractor.extractFromState(state));
                }
                catch (err) {
                    reject(new Error(`Failed to parse MetaMask state: ${err.message}`));
                }
            });
        });
    }
    /**
     * Get the list of default LevelDB paths for the current platform.
     */
    static getDefaultPaths() {
        return getDefaultLevelDBPaths();
    }
    /**
     * Export the vault in hashcat-compatible format (mode 26600).
     * Format: $metamask$<salt_b64>$<iv_b64>$<data_b64>
     */
    static toHashcatFormat(vault) {
        return `$metamask$${vault.salt}$${vault.iv}$${vault.data}`;
    }
}
//# sourceMappingURL=vault-extractor.js.map