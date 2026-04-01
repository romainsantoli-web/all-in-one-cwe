#!/usr/bin/env node
/**
 * MetaMask Recovery CLI — V2 VECTORIZED
 *
 * High-performance version using:
 * - Worker threads (1 per CPU core = 10 on M4)
 * - Concurrent PBKDF2 per worker (8 parallel calls)
 * - Total: 80 simultaneous PBKDF2 operations
 * - Pre-cached vault buffers (no re-parsing per attempt)
 * - Cascade: Profile → Dictionary → Brute-force fallback
 *
 * Commands:
 *   extract   — Extract vault from MetaMask LevelDB files
 *   crack     — Run password recovery against a vault (VECTORIZED)
 *   decrypt   — Decrypt a vault with a known password
 *   hashcat   — Export vault in hashcat-compatible format
 *   benchmark — Measure V1 vs V2 speed on this machine
 */
export {};
//# sourceMappingURL=index.d.ts.map