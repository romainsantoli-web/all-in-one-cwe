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
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
export class UniversalCrackEngine {
    params;
    options;
    numWorkers;
    concurrentPerWorker;
    aborted = false;
    constructor(params, options = {}) {
        this.params = params;
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
     * Run the universal cracking engine.
     * Takes a generator of password batches and distributes across workers.
     */
    async crack(batchIterator, strategyName = 'unknown') {
        this.aborted = false;
        const startTime = performance.now();
        let totalAttempts = 0;
        // Resolve universal worker script path
        const workerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'universal-worker.js');
        // Spawn worker pool — each worker gets the cracker params via workerData
        const workers = [];
        for (let i = 0; i < this.numWorkers; i++) {
            const w = new Worker(workerPath, {
                workerData: { params: this.params },
                env: {
                    ...process.env,
                    UV_THREADPOOL_SIZE: String(Math.max(this.concurrentPerWorker + 4, 16)),
                },
            });
            workers.push(w);
        }
        try {
            const result = await new Promise((resolve) => {
                let pendingWorkers = 0;
                let iteratorDone = false;
                const finish = (found, password, raw) => {
                    const ms = performance.now() - startTime;
                    resolve({
                        found,
                        password,
                        raw,
                        totalAttempts,
                        elapsedMs: ms,
                        speed: totalAttempts / (ms / 1000),
                    });
                };
                const dispatchNext = (worker) => {
                    if (this.aborted || iteratorDone) {
                        pendingWorkers--;
                        if (pendingWorkers <= 0)
                            finish(false);
                        return;
                    }
                    const next = batchIterator.next();
                    if (next.done) {
                        iteratorDone = true;
                        pendingWorkers--;
                        if (pendingWorkers <= 0)
                            finish(false);
                        return;
                    }
                    worker.postMessage({ type: 'crack', passwords: next.value });
                };
                for (const worker of workers) {
                    worker.on('message', (msg) => {
                        totalAttempts += msg.tried;
                        if (msg.found) {
                            this.aborted = true;
                            finish(true, msg.password, msg.raw);
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
            await Promise.all(workers.map((w) => w.terminate()));
        }
    }
}
//# sourceMappingURL=universal-engine.js.map