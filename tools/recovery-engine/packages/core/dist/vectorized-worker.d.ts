/**
 * V2 Vectorized Worker Thread
 *
 * Each worker thread has its own libuv thread pool.
 * Inside each worker, we fire CONCURRENT_PER_WORKER parallel PBKDF2 calls.
 * This means: 10 workers × 8 concurrent = 80 parallel PBKDF2 operations.
 *
 * The libuv pool is sized via UV_THREADPOOL_SIZE (set by parent).
 */
export {};
//# sourceMappingURL=vectorized-worker.d.ts.map