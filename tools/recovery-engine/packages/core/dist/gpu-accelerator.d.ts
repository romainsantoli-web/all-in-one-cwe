/**
 * GPU Accelerator — Provides GPU-accelerated PBKDF2 cracking.
 *
 * Two modes:
 * 1. WebGPU compute shaders (browser extension context)
 * 2. Hashcat integration (CLI context, subprocess)
 *
 * Falls back gracefully to CPU if GPU is unavailable.
 */
import type { VaultData } from './vault-extractor.js';
import type { CrackResult } from './worker-pool.js';
export interface GpuOptions {
    /** Preferred GPU backend */
    backend?: 'webgpu' | 'hashcat' | 'auto';
    /** Path to hashcat binary (CLI only) */
    hashcatPath?: string;
    /** Path to write temporary files for hashcat */
    tempDir?: string;
}
export declare class GpuAccelerator {
    private options;
    constructor(options?: GpuOptions);
    /**
     * Check if GPU acceleration is available.
     */
    isAvailable(): Promise<{
        webgpu: boolean;
        hashcat: boolean;
    }>;
    /**
     * Run hashcat against the vault with a wordlist file.
     * CLI only — spawns hashcat as a subprocess.
     */
    crackWithHashcat(vault: VaultData, wordlistPath: string, onProgress?: (info: {
        speed: number;
        progress: string;
    }) => void): Promise<CrackResult>;
    /**
     * Generate a wordlist file from a password generator for use with hashcat.
     */
    generateWordlist(candidates: Generator<string>, outputPath: string, maxCandidates?: number): Promise<number>;
    private checkWebGPU;
    private checkHashcat;
}
//# sourceMappingURL=gpu-accelerator.d.ts.map