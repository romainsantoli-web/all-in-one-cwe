/**
 * Crack Orchestrator — Coordinates the full recovery pipeline.
 *
 * Cascade: Profile → Dictionary+Mutations → Brute-force
 * Each level runs until exhausted, then falls through to the next.
 *
 * Supports checkpoint/resume for brute-force.
 */
import { PasswordGenerator } from './password-generator.js';
import { WorkerPool } from './worker-pool.js';
import { GpuAccelerator } from './gpu-accelerator.js';
export class CrackOrchestrator {
    options;
    pool;
    gpu;
    aborted = false;
    totalAttempts = 0;
    startTime = 0;
    constructor(options) {
        this.options = options;
        this.pool = new WorkerPool({
            numWorkers: options.numWorkers,
            batchSize: options.batchSize,
        });
        this.gpu = new GpuAccelerator(options.gpuOptions);
    }
    /**
     * Run the full recovery pipeline against a vault.
     */
    async run(vault, onProgress) {
        this.startTime = performance.now();
        this.totalAttempts = 0;
        this.aborted = false;
        const strategies = this.options.strategy === 'all'
            ? ['profile', 'dictionary', 'bruteforce']
            : [this.options.strategy ?? 'all'];
        // Check GPU availability
        let gpuAvailable = false;
        if (this.options.useGpu) {
            const availability = await this.gpu.isAvailable();
            gpuAvailable = availability.hashcat || availability.webgpu;
            if (gpuAvailable) {
                console.log(`[GPU] Acceleration available: hashcat=${availability.hashcat}, webgpu=${availability.webgpu}`);
            }
        }
        for (const strategy of strategies) {
            if (this.aborted)
                break;
            console.log(`\n[*] Starting strategy: ${strategy.toUpperCase()}`);
            onProgress?.({
                currentStrategy: strategy,
                totalAttempts: this.totalAttempts,
                speed: this.getSpeed(),
                elapsedMs: performance.now() - this.startTime,
                found: false,
            });
            const generator = new PasswordGenerator({
                strategy,
                profile: this.options.profile,
                bruteforceCharset: this.options.bruteforceCharset,
                minLength: this.options.minLength,
                maxLength: this.options.maxLength,
                resumeFrom: strategy === 'bruteforce' ? (this.options.resumeFrom ?? 0n) : 0n,
            });
            const batchIterator = generator.batches(this.options.batchSize ?? 20);
            const result = await this.pool.crackSingleThread(batchIterator, vault, (info) => {
                this.totalAttempts += info.attempts - this.totalAttempts;
                onProgress?.({
                    currentStrategy: strategy,
                    totalAttempts: this.totalAttempts,
                    speed: info.speed,
                    elapsedMs: performance.now() - this.startTime,
                    found: false,
                });
            });
            this.totalAttempts = result.totalAttempts;
            if (result.found) {
                onProgress?.({
                    currentStrategy: strategy,
                    totalAttempts: this.totalAttempts,
                    speed: result.speed,
                    elapsedMs: performance.now() - this.startTime,
                    found: true,
                    password: result.password,
                });
                return {
                    ...result,
                    decryptedVault: result.vault,
                };
            }
            console.log(`[*] Strategy ${strategy} exhausted. Tried ${result.totalAttempts} passwords in ${(result.elapsedMs / 1000).toFixed(1)}s`);
        }
        // Not found
        const elapsedMs = performance.now() - this.startTime;
        return {
            found: false,
            totalAttempts: this.totalAttempts,
            elapsedMs,
            speed: this.totalAttempts / (elapsedMs / 1000),
        };
    }
    /**
     * Stop the recovery process.
     */
    abort() {
        this.aborted = true;
        this.pool.abort();
    }
    /**
     * Save a checkpoint for resuming later.
     */
    async saveCheckpoint(strategy, bruteforceIndex) {
        if (!this.options.checkpointPath)
            return;
        const fs = await import('node:fs');
        const checkpoint = {
            strategy,
            totalAttempts: this.totalAttempts,
            bruteforceIndex,
            timestamp: new Date().toISOString(),
        };
        fs.writeFileSync(this.options.checkpointPath, JSON.stringify(checkpoint, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
    }
    /**
     * Load a checkpoint for resume.
     */
    async loadCheckpoint() {
        if (!this.options.checkpointPath)
            return null;
        try {
            const fs = await import('node:fs');
            const data = fs.readFileSync(this.options.checkpointPath, 'utf-8');
            const parsed = JSON.parse(data);
            parsed.bruteforceIndex = BigInt(parsed.bruteforceIndex);
            return parsed;
        }
        catch {
            return null;
        }
    }
    getSpeed() {
        const elapsed = (performance.now() - this.startTime) / 1000;
        return elapsed > 0 ? this.totalAttempts / elapsed : 0;
    }
}
//# sourceMappingURL=orchestrator.js.map