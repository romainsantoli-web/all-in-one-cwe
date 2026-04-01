/**
 * Vault Decryptor — Attempts to decrypt a MetaMask vault with a given password.
 *
 * Pipeline: password → PBKDF2-SHA256(salt, iterations) → AES-256-GCM decrypt
 *
 * Works in both Node.js (using crypto module) and browser (using Web Crypto API).
 */
import type { VaultData } from './vault-extractor.js';
/** Result of a successful decryption */
export interface DecryptedVault {
    /** The BIP-39 mnemonic seed phrase */
    mnemonic: string;
    /** Number of accounts derived */
    numberOfAccounts: number;
    /** HD derivation path */
    hdPath: string;
    /** Raw decrypted JSON content */
    raw: string;
}
/** Result of a decryption attempt */
export interface DecryptionResult {
    success: boolean;
    password?: string;
    vault?: DecryptedVault;
    error?: string;
}
export declare class VaultDecryptor {
    private readonly isNode;
    constructor();
    /**
     * Attempt to decrypt a vault with a single password.
     * Returns a DecryptionResult indicating success or failure.
     */
    tryPassword(password: string, vault: VaultData): Promise<DecryptionResult>;
    /**
     * Try a batch of passwords against a vault.
     * Returns the first successful result, or a failure if none matched.
     */
    tryBatch(passwords: string[], vault: VaultData): Promise<DecryptionResult>;
    /**
     * Benchmark: measure how many attempts per second on this machine.
     * Creates a test vault and times decryption attempts.
     */
    benchmark(iterations?: number): Promise<{
        attemptsPerSecond: number;
    }>;
}
//# sourceMappingURL=decryptor.d.ts.map