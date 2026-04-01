/**
 * Worker Pool — Parallelizes PBKDF2 + AES-GCM decryption across threads.
 *
 * - Node.js: uses worker_threads
 * - Browser: uses Web Workers
 *
 * Each worker receives a batch of password candidates and the vault data,
 * tries each one, and reports back success/failure.
 */
// ---------- Node.js Worker Pool ----------
export class WorkerPool {
    numWorkers;
    batchSize;
    aborted = false;
    constructor(options = {}) {
        this.batchSize = options.batchSize ?? 20;
        if (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) {
            this.numWorkers = options.numWorkers ?? navigator.hardwareConcurrency;
        }
        else if (typeof process !== 'undefined') {
            const os = await_os();
            this.numWorkers = options.numWorkers ?? (os ? os.cpus().length : 4);
        }
        else {
            this.numWorkers = options.numWorkers ?? 4;
        }
    }
    /**
     * Stop all workers.
     */
    abort() {
        this.aborted = true;
    }
    /**
     * Crack a vault using Node.js worker_threads.
     * Distributes batches of passwords across workers.
     */
    async crackWithNodeWorkers(candidateIterator, vault, onProgress) {
        const { Worker } = await import('node:worker_threads');
        const { fileURLToPath } = await import('node:url');
        const path = await import('node:path');
        const workerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'worker-thread.js');
        const startTime = performance.now();
        let totalAttempts = 0;
        this.aborted = false;
        // Create worker pool
        const workers = [];
        for (let i = 0; i < this.numWorkers; i++) {
            workers.push(new Worker(workerPath));
        }
        try {
            const result = await new Promise((resolve) => {
                let pendingWorkers = 0;
                let iteratorDone = false;
                const dispatchNext = (worker) => {
                    if (this.aborted || iteratorDone) {
                        pendingWorkers--;
                        if (pendingWorkers <= 0) {
                            resolve({
                                found: false,
                                totalAttempts,
                                elapsedMs: performance.now() - startTime,
                                speed: totalAttempts / ((performance.now() - startTime) / 1000),
                            });
                        }
                        return;
                    }
                    const next = candidateIterator.next();
                    if (next.done) {
                        iteratorDone = true;
                        pendingWorkers--;
                        if (pendingWorkers <= 0) {
                            resolve({
                                found: false,
                                totalAttempts,
                                elapsedMs: performance.now() - startTime,
                                speed: totalAttempts / ((performance.now() - startTime) / 1000),
                            });
                        }
                        return;
                    }
                    const batch = next.value;
                    const msg = { type: 'crack', passwords: batch, vault };
                    worker.postMessage(msg);
                };
                for (const worker of workers) {
                    worker.on('message', (msg) => {
                        totalAttempts += msg.tried;
                        if (msg.found) {
                            this.aborted = true;
                            resolve({
                                found: true,
                                password: msg.password,
                                vault: msg.vault,
                                totalAttempts,
                                elapsedMs: performance.now() - startTime,
                                speed: totalAttempts / ((performance.now() - startTime) / 1000),
                            });
                            return;
                        }
                        onProgress?.({
                            attempts: totalAttempts,
                            speed: totalAttempts / ((performance.now() - startTime) / 1000),
                            currentBatch: [],
                        });
                        dispatchNext(worker);
                    });
                    worker.on('error', (err) => {
                        console.error('Worker error:', err);
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
            for (const worker of workers) {
                worker.terminate();
            }
        }
    }
    /**
     * Crack using a single thread (no workers). Simpler, used for small candidate sets.
     */
    async crackSingleThread(candidateIterator, vault, onProgress) {
        const { VaultDecryptor } = await import('./decryptor.js');
        const decryptor = new VaultDecryptor();
        const startTime = performance.now();
        let totalAttempts = 0;
        for (const batch of candidateIterator) {
            if (this.aborted)
                break;
            for (const password of batch) {
                totalAttempts++;
                const result = await decryptor.tryPassword(password, vault);
                if (result.success) {
                    const elapsedMs = performance.now() - startTime;
                    return {
                        found: true,
                        password: result.password,
                        vault: result.vault,
                        totalAttempts,
                        elapsedMs,
                        speed: totalAttempts / (elapsedMs / 1000),
                    };
                }
            }
            onProgress?.({
                attempts: totalAttempts,
                speed: totalAttempts / ((performance.now() - startTime) / 1000),
                currentBatch: batch,
            });
        }
        const elapsedMs = performance.now() - startTime;
        return {
            found: false,
            totalAttempts,
            elapsedMs,
            speed: totalAttempts / (elapsedMs / 1000),
        };
    }
    get workerCount() {
        return this.numWorkers;
    }
}
/** Safely get the os module (Node.js only) */
function await_os() {
    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        return require('node:os');
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=worker-pool.js.map