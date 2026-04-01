/**
 * ETA Estimator
 *
 * Provides accurate time-remaining estimates based on:
 * - Current speed (passwords/second), smoothed over a sliding window
 * - Known keyspace size (exact for mask attacks, estimated for rules)
 * - Already-completed attempts
 *
 * Supports:
 * - Adaptive speed tracking (exponential moving average)
 * - Multiple display formats (human-readable, compact, raw)
 * - Probability-based ETA (e.g., "50% chance in 2h")
 */
export interface ETAInfo {
    /** Total keyspace (if known) */
    totalKeyspace: bigint;
    /** Candidates already processed */
    processed: bigint;
    /** Remaining candidates */
    remaining: bigint;
    /** Current speed (pwd/sec) — smoothed */
    speed: number;
    /** Estimated seconds remaining */
    etaSeconds: number;
    /** Human-readable ETA string */
    etaStr: string;
    /** Percentage complete (0-100) */
    percentComplete: number;
    /** Progress bar string (e.g., "████████░░ 80%") */
    progressBar: string;
}
export declare class ETAEstimator {
    private totalKeyspace;
    private processed;
    private speedSamples;
    private maxSamples;
    private startTime;
    private previousElapsedMs;
    constructor(totalKeyspace: bigint, previousElapsedMs?: number, previousProcessed?: bigint);
    /**
     * Update with new progress data.
     */
    update(processed: bigint, currentSpeed: number): void;
    /**
     * Get smoothed speed (exponential moving average).
     */
    getSmoothedSpeed(): number;
    /**
     * Get full ETA information.
     */
    getETA(): ETAInfo;
    /**
     * Get total elapsed time (previous sessions + current).
     */
    getTotalElapsedMs(): number;
    /**
     * Set the total keyspace (if discovered later).
     */
    setTotalKeyspace(keyspace: bigint): void;
}
/**
 * Format seconds into human-readable duration.
 */
export declare function formatDuration(seconds: number): string;
/**
 * Format speed with SI prefix.
 */
export declare function formatSpeed(speed: number): string;
/**
 * Format a large number compactly.
 */
export declare function formatNumber(n: bigint | number): string;
//# sourceMappingURL=eta-estimator.d.ts.map