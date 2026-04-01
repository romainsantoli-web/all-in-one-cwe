/**
 * Vault Extractor — Reads and parses MetaMask encrypted vaults.
 *
 * Supports:
 * - Reading vault JSON pasted manually
 * - Reading from Chrome extension local storage (LevelDB on disk)
 * - Reading from chrome.storage.local (in extension context)
 * - Auto-detecting iteration count (900k modern / 10k legacy)
 */
/** Parsed vault structure ready for decryption */
export interface VaultData {
    /** Base64-encoded AES-GCM ciphertext (includes 16-byte auth tag) */
    data: string;
    /** Base64-encoded 16-byte initialization vector */
    iv: string;
    /** Base64-encoded 32-byte PBKDF2 salt */
    salt: string;
    /** Number of PBKDF2-SHA256 iterations */
    iterations: number;
    /** Whether this is a legacy vault (10k iterations) */
    isLegacy: boolean;
}
/** Raw vault JSON as stored by MetaMask */
export interface RawVault {
    data: string;
    iv: string;
    salt: string;
    /** Root-level iterations (newer MetaMask format, e.g. 600k) */
    iterations?: number;
    keyMetadata?: {
        algorithm: string;
        params: {
            iterations: number;
        };
    };
}
export declare class VaultExtractor {
    /**
     * Parse a raw vault JSON string into a structured VaultData object.
     */
    static parseVaultJSON(jsonString: string): VaultData;
    /**
     * Extract the vault from a MetaMask state object.
     * The state is typically at: data.KeyringController.vault
     */
    static extractFromState(state: Record<string, unknown>): VaultData;
    /**
     * Read the vault from LevelDB files on disk (CLI only).
     * Requires 'classic-level' to be installed.
     */
    static extractFromLevelDB(dbPath?: string): Promise<VaultData>;
    /**
     * Extract vault from Chrome extension storage (in extension context only).
     * Must be called from a Chrome extension with 'storage' permission.
     */
    static extractFromExtensionStorage(): Promise<VaultData>;
    /**
     * Get the list of default LevelDB paths for the current platform.
     */
    static getDefaultPaths(): string[];
    /**
     * Export the vault in hashcat-compatible format (mode 26600).
     * Format: $metamask$<salt_b64>$<iv_b64>$<data_b64>
     */
    static toHashcatFormat(vault: VaultData): string;
}
//# sourceMappingURL=vault-extractor.d.ts.map