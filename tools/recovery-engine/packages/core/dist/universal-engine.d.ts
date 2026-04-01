/**
 * Universal Crack Engine
 *
 * Generic multi-threaded cracking engine that works with ANY format
 * supported by the crackers package. Same architecture as VectorizedCrackEngine
 * but delegates password verification to the universal worker.
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────┐
 * │ Main Thread (Orchestrator)                       │
 * │  - Password generator (lazy iterator)            │
 * │  - Batch dispatcher                              │
 * │  - Format detection + param extraction           │
 * └───────┬───────┬───────┬───────┬───────┬────────┘
 *         │       │       │       │       │
 *    ┌────▼──┐ ┌──▼───┐ ┌▼────┐ ┌▼────┐ ┌▼────┐
 *    │Worker1│ │Worker2│ │  ...│ │  N-1│ │  N  │   (N = CPU cores)
 *    │       │ │       │ │     │ │     │ │     │
 *    │ tryPw │ │ tryPw │ │ tryP│ │tryPw│ │tryPw│   (universal cracker)
 *    └───────┘ └───────┘ └─────┘ └─────┘ └─────┘
 */
export interface CrackerParams {
    type: string;
    [key: string]: unknown;
}
export interface UniversalOptions {
    /** Number of worker threads (default: CPU cores) */
    numWorkers?: number;
    /** Concurrent attempts per worker (default: 8) */
    concurrentPerWorker?: number;
    /** Progress callback */
    onProgress?: (info: UniversalProgressInfo) => void;
}
export interface UniversalProgressInfo {
    totalAttempts: number;
    speed: number;
    elapsedMs: number;
    currentStrategy: string;
    found: boolean;
    password?: string;
}
export interface UniversalCrackResult {
    found: boolean;
    password?: string;
    raw?: string;
    totalAttempts: number;
    elapsedMs: number;
    speed: number;
}
export declare class UniversalCrackEngine {
    private params;
    private options;
    private numWorkers;
    private concurrentPerWorker;
    private aborted;
    constructor(params: CrackerParams, options?: UniversalOptions);
    get batchSize(): number;
    get totalParallel(): number;
    abort(): void;
    /**
     * Run the universal cracking engine.
     * Takes a generator of password batches and distributes across workers.
     */
    crack(batchIterator: Generator<string[]>, strategyName?: string): Promise<UniversalCrackResult>;
}
//# sourceMappingURL=universal-engine.d.ts.map