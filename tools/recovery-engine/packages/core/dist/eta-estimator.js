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
export class ETAEstimator {
    totalKeyspace;
    processed = 0n;
    speedSamples = [];
    maxSamples = 30; // ~30 data points for smoothing
    startTime;
    previousElapsedMs;
    constructor(totalKeyspace, previousElapsedMs = 0, previousProcessed = 0n) {
        this.totalKeyspace = totalKeyspace;
        this.processed = previousProcessed;
        this.startTime = Date.now();
        this.previousElapsedMs = previousElapsedMs;
    }
    /**
     * Update with new progress data.
     */
    update(processed, currentSpeed) {
        this.processed = processed;
        this.speedSamples.push(currentSpeed);
        if (this.speedSamples.length > this.maxSamples) {
            this.speedSamples.shift();
        }
    }
    /**
     * Get smoothed speed (exponential moving average).
     */
    getSmoothedSpeed() {
        if (this.speedSamples.length === 0)
            return 0;
        // EMA with alpha=0.3 (more weight on recent)
        let ema = this.speedSamples[0];
        const alpha = 0.3;
        for (let i = 1; i < this.speedSamples.length; i++) {
            ema = alpha * this.speedSamples[i] + (1 - alpha) * ema;
        }
        return ema;
    }
    /**
     * Get full ETA information.
     */
    getETA() {
        const speed = this.getSmoothedSpeed();
        const remaining = this.totalKeyspace > this.processed
            ? this.totalKeyspace - this.processed
            : 0n;
        const etaSeconds = speed > 0 ? Number(remaining) / speed : Infinity;
        const percentComplete = this.totalKeyspace > 0n
            ? Number((this.processed * 10000n) / this.totalKeyspace) / 100
            : 0;
        return {
            totalKeyspace: this.totalKeyspace,
            processed: this.processed,
            remaining,
            speed,
            etaSeconds,
            etaStr: formatDuration(etaSeconds),
            percentComplete: Math.min(percentComplete, 100),
            progressBar: makeProgressBar(percentComplete, 30),
        };
    }
    /**
     * Get total elapsed time (previous sessions + current).
     */
    getTotalElapsedMs() {
        return this.previousElapsedMs + (Date.now() - this.startTime);
    }
    /**
     * Set the total keyspace (if discovered later).
     */
    setTotalKeyspace(keyspace) {
        this.totalKeyspace = keyspace;
    }
}
/**
 * Format seconds into human-readable duration.
 */
export function formatDuration(seconds) {
    if (!isFinite(seconds) || seconds < 0)
        return '∞';
    if (seconds < 1)
        return '<1s';
    if (seconds < 60)
        return `${Math.ceil(seconds)}s`;
    if (seconds < 3600) {
        const m = Math.floor(seconds / 60);
        const s = Math.ceil(seconds % 60);
        return `${m}m${s > 0 ? ` ${s}s` : ''}`;
    }
    if (seconds < 86400) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return `${h}h${m > 0 ? ` ${m}m` : ''}`;
    }
    if (seconds < 86400 * 365) {
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        return `${d}d${h > 0 ? ` ${h}h` : ''}`;
    }
    const y = Math.floor(seconds / (86400 * 365));
    const d = Math.floor((seconds % (86400 * 365)) / 86400);
    return `${y}y${d > 0 ? ` ${d}d` : ''}`;
}
/**
 * Format speed with SI prefix.
 */
export function formatSpeed(speed) {
    if (speed < 1)
        return `${speed.toFixed(2)} pwd/s`;
    if (speed < 1000)
        return `${speed.toFixed(0)} pwd/s`;
    if (speed < 1_000_000)
        return `${(speed / 1000).toFixed(1)}K pwd/s`;
    if (speed < 1_000_000_000)
        return `${(speed / 1_000_000).toFixed(1)}M pwd/s`;
    return `${(speed / 1_000_000_000).toFixed(1)}G pwd/s`;
}
/**
 * Make a visual progress bar.
 */
function makeProgressBar(percent, width = 30) {
    const filled = Math.round((percent / 100) * width);
    const empty = width - filled;
    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    return `${bar} ${percent.toFixed(1)}%`;
}
/**
 * Format a large number compactly.
 */
export function formatNumber(n) {
    const num = typeof n === 'bigint' ? Number(n) : n;
    if (num < 1_000)
        return num.toString();
    if (num < 1_000_000)
        return `${(num / 1_000).toFixed(1)}K`;
    if (num < 1_000_000_000)
        return `${(num / 1_000_000).toFixed(1)}M`;
    if (num < 1_000_000_000_000)
        return `${(num / 1_000_000_000).toFixed(1)}B`;
    return `${(num / 1_000_000_000_000).toFixed(1)}T`;
}
//# sourceMappingURL=eta-estimator.js.map