/**
 * V2 Vectorized Crack Engine
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────┐
 * │ Main Thread (Orchestrator)                       │
 * │  - Password generator (lazy iterator)            │
 * │  - Batch dispatcher                              │
 * │  - Progress tracking                             │
 * └───────┬───────┬───────┬───────┬───────┬────────┘
 *         │       │       │       │       │
 *    ┌────▼──┐ ┌──▼───┐ ┌▼────┐ ┌▼────┐ ┌▼────┐
 *    │Worker1│ │Worker2│ │  ...│ │  N-1│ │  N  │   (N = CPU cores)
 *    │       │ │       │ │     │ │     │ │     │
 *    │ 8 ×   │ │ 8 ×   │ │ 8 ×│ │ 8 ×│ │ 8 ×│   (concurrent PBKDF2/worker)
 *    │PBKDF2 │ │PBKDF2 │ │    │ │    │ │    │
 *    └───────┘ └───────┘ └─────┘ └─────┘ └─────┘
 *
 * Total parallel: N × 8 = 80 simultaneous PBKDF2 on M4 10-core
 *
 * UV_THREADPOOL_SIZE is set to 16 per worker to ensure enough
 * libuv threads for the concurrent crypto operations.
 */
export interface VaultData {
    data: string;
    iv: string;
    salt: string;
    iterations: number;
    isLegacy?: boolean;
}
export interface V2Options {
    /** Number of worker threads (default: CPU cores) */
    numWorkers?: number;
    /** Concurrent PBKDF2 calls per worker (default: 8) */
    concurrentPerWorker?: number;
    /** Progress callback */
    onProgress?: (info: ProgressInfo) => void;
}
export interface ProgressInfo {
    totalAttempts: number;
    speed: number;
    elapsedMs: number;
    currentStrategy: string;
    found: boolean;
    password?: string;
}
export interface CrackResult {
    found: boolean;
    password?: string;
    mnemonic?: string;
    totalAttempts: number;
    elapsedMs: number;
    speed: number;
}
export declare class VectorizedCrackEngine {
    private vault;
    private options;
    private numWorkers;
    private concurrentPerWorker;
    private aborted;
    constructor(vault: VaultData, options?: V2Options);
    get batchSize(): number;
    get totalParallel(): number;
    abort(): void;
    /**
     * Run the vectorized cracking engine.
     * Takes a generator of password batches and distributes across workers.
     */
    crack(batchIterator: Generator<string[]>, strategyName?: string): Promise<CrackResult>;
}
//# sourceMappingURL=vectorized-engine.d.ts.map