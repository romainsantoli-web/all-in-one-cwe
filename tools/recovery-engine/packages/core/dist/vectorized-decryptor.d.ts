/**
 * Vectorized PBKDF2 Decryptor — V2 High-Performance Engine
 *
 * Key optimizations over V1:
 * 1. Concurrent async PBKDF2: fires N parallel crypto.pbkdf2() calls per worker
 * 2. Worker threads: distributes across all CPU cores (10 on Apple M4)
 * 3. UV_THREADPOOL_SIZE maximized: more libuv threads for async crypto ops
 * 4. Pre-computed salt/iv buffers: avoid re-parsing base64 per attempt
 * 5. Batch pipelining: next batch prepared while current one runs
 * 6. Zero-copy buffer reuse where possible
 *
 * Expected speedup: 8-15x over single-threaded V1
 */
interface VaultData {
    data: string;
    iv: string;
    salt: string;
    iterations: number;
}
interface DecryptResult {
    found: boolean;
    password?: string;
    decrypted?: string;
    tried: number;
}
declare function initVaultBuffers(vault: VaultData): void;
/**
 * Try a single password — async, non-blocking.
 * Uses pre-cached buffers to avoid repeated base64 decoding.
 */
declare function tryPasswordAsync(password: string): Promise<{
    success: boolean;
    raw?: string;
}>;
/**
 * VECTORIZED BATCH: Try N passwords CONCURRENTLY.
 *
 * This is the core speedup — fires all PBKDF2 calls at once.
 * Node's crypto.pbkdf2 is async and runs on libuv's thread pool.
 * With UV_THREADPOOL_SIZE set high, all calls run in parallel on separate OS threads.
 */
declare function tryBatchConcurrent(passwords: string[]): Promise<{
    found: boolean;
    password?: string;
    raw?: string;
    tried: number;
}>;
export { initVaultBuffers, tryPasswordAsync, tryBatchConcurrent, type VaultData, type DecryptResult };
//# sourceMappingURL=vectorized-decryptor.d.ts.map