/**
 * Crack Orchestrator — Coordinates the full recovery pipeline.
 *
 * Cascade: Profile → Dictionary+Mutations → Brute-force
 * Each level runs until exhausted, then falls through to the next.
 *
 * Supports checkpoint/resume for brute-force.
 */
import type { VaultData } from './vault-extractor.js';
import type { DecryptedVault } from './decryptor.js';
import type { UserProfile, Strategy } from './password-generator.js';
import { type CrackResult } from './worker-pool.js';
import { type GpuOptions } from './gpu-accelerator.js';
export interface OrchestratorOptions {
    /** User profile for targeted generation */
    profile?: UserProfile;
    /** Number of parallel workers */
    numWorkers?: number;
    /** Passwords per batch per worker */
    batchSize?: number;
    /** Use GPU if available */
    useGpu?: boolean;
    /** GPU options */
    gpuOptions?: GpuOptions;
    /** Strategy override (default: 'all' = cascading) */
    strategy?: Strategy;
    /** Brute-force charset */
    bruteforceCharset?: string;
    /** Min password length */
    minLength?: number;
    /** Max password length */
    maxLength?: number;
    /** Resume brute-force from checkpoint */
    resumeFrom?: bigint;
    /** Checkpoint file path (auto-saves progress) */
    checkpointPath?: string;
    /** Checkpoint interval in seconds (default: 300 = 5 min) */
    checkpointInterval?: number;
}
export interface ProgressInfo {
    /** Current strategy being executed */
    currentStrategy: Strategy;
    /** Total attempts so far */
    totalAttempts: number;
    /** Current speed (attempts/sec) */
    speed: number;
    /** Elapsed time in milliseconds */
    elapsedMs: number;
    /** Whether the password was found */
    found: boolean;
    /** The found password (if any) */
    password?: string;
}
interface Checkpoint {
    strategy: Strategy;
    totalAttempts: number;
    bruteforceIndex: bigint;
    timestamp: string;
}
export declare class CrackOrchestrator {
    private options;
    private pool;
    private gpu;
    private aborted;
    private totalAttempts;
    private startTime;
    constructor(options: OrchestratorOptions);
    /**
     * Run the full recovery pipeline against a vault.
     */
    run(vault: VaultData, onProgress?: (info: ProgressInfo) => void): Promise<CrackResult & {
        decryptedVault?: DecryptedVault;
    }>;
    /**
     * Stop the recovery process.
     */
    abort(): void;
    /**
     * Save a checkpoint for resuming later.
     */
    saveCheckpoint(strategy: Strategy, bruteforceIndex: bigint): Promise<void>;
    /**
     * Load a checkpoint for resume.
     */
    loadCheckpoint(): Promise<Checkpoint | null>;
    private getSpeed;
}
export {};
//# sourceMappingURL=orchestrator.d.ts.map