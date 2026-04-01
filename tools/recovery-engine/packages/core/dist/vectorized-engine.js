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
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
function parseDecryptedContent(raw) {
    try {
        const keyrings = JSON.parse(raw);
        const hd = Array.isArray(keyrings) ? keyrings.find((k) => k.type === 'HD Key Tree') : null;
        if (hd?.data) {
            let mnemonic;
            if (typeof hd.data.mnemonic === 'string') {
                mnemonic = hd.data.mnemonic;
            }
            else if (Array.isArray(hd.data.mnemonic)) {
                mnemonic = Buffer.from(hd.data.mnemonic).toString('utf-8');
            }
            else if (hd.data.mnemonic?.type === 'Buffer') {
                mnemonic = Buffer.from(hd.data.mnemonic.data).toString('utf-8');
            }
            else {
                mnemonic = String(hd.data.mnemonic);
            }
            return { mnemonic: mnemonic.trim() };
        }
    }
    catch { }
    return { mnemonic: '[parse error]' };
}
export class VectorizedCrackEngine {
    vault;
    options;
    numWorkers;
    concurrentPerWorker;
    aborted = false;
    constructor(vault, options = {}) {
        this.vault = vault;
        this.options = options;
        this.numWorkers = options.numWorkers ?? os.cpus().length;
        this.concurrentPerWorker = options.concurrentPerWorker ?? 8;
    }
    get batchSize() {
        return this.concurrentPerWorker;
    }
    get totalParallel() {
        return this.numWorkers * this.concurrentPerWorker;
    }
    abort() {
        this.aborted = true;
    }
    /**
     * Run the vectorized cracking engine.
     * Takes a generator of password batches and distributes across workers.
     */
    async crack(batchIterator, strategyName = 'unknown') {
        this.aborted = false;
        const startTime = performance.now();
        let totalAttempts = 0;
        // Resolve worker script path
        const workerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'vectorized-worker.js');
        // Spawn worker pool — each worker gets the vault data via workerData
        const workers = [];
        for (let i = 0; i < this.numWorkers; i++) {
            const w = new Worker(workerPath, {
                workerData: { vault: this.vault },
                env: {
                    ...process.env,
                    // Maximize libuv thread pool per worker for concurrent PBKDF2
                    UV_THREADPOOL_SIZE: String(Math.max(this.concurrentPerWorker + 4, 16)),
                },
            });
            workers.push(w);
        }
        try {
            const result = await new Promise((resolve) => {
                let pendingWorkers = 0;
                let iteratorDone = false;
                const dispatchNext = (worker) => {
                    if (this.aborted || iteratorDone) {
                        pendingWorkers--;
                        if (pendingWorkers <= 0) {
                            const ms = performance.now() - startTime;
                            resolve({
                                found: false,
                                totalAttempts,
                                elapsedMs: ms,
                                speed: totalAttempts / (ms / 1000),
                            });
                        }
                        return;
                    }
                    const next = batchIterator.next();
                    if (next.done) {
                        iteratorDone = true;
                        pendingWorkers--;
                        if (pendingWorkers <= 0) {
                            const ms = performance.now() - startTime;
                            resolve({
                                found: false,
                                totalAttempts,
                                elapsedMs: ms,
                                speed: totalAttempts / (ms / 1000),
                            });
                        }
                        return;
                    }
                    worker.postMessage({ type: 'crack', passwords: next.value });
                };
                for (const worker of workers) {
                    worker.on('message', (msg) => {
                        totalAttempts += msg.tried;
                        if (msg.found) {
                            this.aborted = true;
                            const ms = performance.now() - startTime;
                            const parsed = msg.raw ? parseDecryptedContent(msg.raw) : { mnemonic: '' };
                            resolve({
                                found: true,
                                password: msg.password,
                                mnemonic: parsed.mnemonic,
                                totalAttempts,
                                elapsedMs: ms,
                                speed: totalAttempts / (ms / 1000),
                            });
                            return;
                        }
                        // Report progress
                        const ms = performance.now() - startTime;
                        this.options.onProgress?.({
                            totalAttempts,
                            speed: totalAttempts / (ms / 1000),
                            elapsedMs: ms,
                            currentStrategy: strategyName,
                            found: false,
                        });
                        dispatchNext(worker);
                    });
                    worker.on('error', (err) => {
                        console.error('Worker error:', err.message);
                        dispatchNext(worker);
                    });
                    pendingWorkers++;
                    dispatchNext(worker);
                }
            });
            return result;
        }
        finally {
            // Terminate all workers
            await Promise.all(workers.map((w) => w.terminate()));
        }
    }
}
//# sourceMappingURL=vectorized-engine.js.map