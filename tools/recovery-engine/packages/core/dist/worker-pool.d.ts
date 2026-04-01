/**
 * Worker Pool — Parallelizes PBKDF2 + AES-GCM decryption across threads.
 *
 * - Node.js: uses worker_threads
 * - Browser: uses Web Workers
 *
 * Each worker receives a batch of password candidates and the vault data,
 * tries each one, and reports back success/failure.
 */
import type { VaultData } from './vault-extractor.js';
import type { DecryptionResult } from './decryptor.js';
export interface WorkerPoolOptions {
    /** Number of parallel workers (default: navigator.hardwareConcurrency or os.cpus().length) */
    numWorkers?: number;
    /** Number of passwords per batch sent to each worker */
    batchSize?: number;
}
export interface CrackResult {
    found: boolean;
    password?: string;
    vault?: DecryptionResult['vault'];
    totalAttempts: number;
    elapsedMs: number;
    speed: number;
}
/**
 * Worker message protocol
 */
export interface WorkerRequest {
    type: 'crack';
    passwords: string[];
    vault: VaultData;
}
export interface WorkerResponse {
    type: 'result';
    found: boolean;
    password?: string;
    vault?: DecryptionResult['vault'];
    tried: number;
}
export declare class WorkerPool {
    private numWorkers;
    private batchSize;
    private aborted;
    constructor(options?: WorkerPoolOptions);
    /**
     * Stop all workers.
     */
    abort(): void;
    /**
     * Crack a vault using Node.js worker_threads.
     * Distributes batches of passwords across workers.
     */
    crackWithNodeWorkers(candidateIterator: Generator<string[]>, vault: VaultData, onProgress?: (info: {
        attempts: number;
        speed: number;
        currentBatch: string[];
    }) => void): Promise<CrackResult>;
    /**
     * Crack using a single thread (no workers). Simpler, used for small candidate sets.
     */
    crackSingleThread(candidateIterator: Generator<string[]>, vault: VaultData, onProgress?: (info: {
        attempts: number;
        speed: number;
        currentBatch: string[];
    }) => void): Promise<CrackResult>;
    get workerCount(): number;
}
//# sourceMappingURL=worker-pool.d.ts.map