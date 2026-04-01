/**
 * Checkpoint / Resume System
 *
 * Saves cracking progress to disk so a session can survive crashes,
 * reboots, or intentional stops and resume from where it left off.
 *
 * Checkpoint file format (.mmck):
 * {
 *   version: 1,
 *   format: "rar",
 *   params: { ... },            // cracker params (hash of target)
 *   attack: "mask" | "wordlist" | "rules" | "hybrid" | "combinator",
 *   attackConfig: { ... },       // mask string, wordlist path, rules, etc.
 *   progress: {
 *     index: 123456n,           // global candidate index
 *     attempts: 123456,
 *     found: false,
 *     password: null,
 *     elapsedMs: 45000,
 *     speed: 2800,
 *   },
 *   timestamp: "2026-03-10T12:00:00Z",
 * }
 */
export interface CheckpointProgress {
    /** Global candidate index (resumable position) */
    index: string;
    /** Total attempts so far */
    attempts: number;
    /** Password found? */
    found: boolean;
    /** Found password (if any) */
    password?: string;
    /** Elapsed time in ms */
    elapsedMs: number;
    /** Current speed (pwd/s) */
    speed: number;
}
export interface CheckpointData {
    version: 1;
    /** Cracker format id */
    format: string;
    /** Hash of cracker params (to verify we're resuming the correct target) */
    paramsHash: string;
    /** Attack type */
    attack: 'mask' | 'wordlist' | 'rules' | 'hybrid' | 'combinator' | 'smart';
    /** Attack configuration for reproducibility */
    attackConfig: Record<string, unknown>;
    /** Current progress */
    progress: CheckpointProgress;
    /** Timestamp of last save */
    timestamp: string;
}
export interface CheckpointOptions {
    /** Directory to store checkpoints (default: cwd) */
    directory?: string;
    /** Auto-save interval in milliseconds (default: 30000 = 30s) */
    autoSaveIntervalMs?: number;
    /** Filename prefix (default: "crack") */
    prefix?: string;
}
export declare class CheckpointManager {
    private dir;
    private prefix;
    private autoSaveMs;
    private lastSaveTime;
    private data;
    private filePath;
    constructor(options?: CheckpointOptions);
    /**
     * Initialize a new checkpoint session.
     */
    init(format: string, params: Record<string, unknown>, attack: CheckpointData['attack'], attackConfig: Record<string, unknown>): void;
    /**
     * Try to load an existing checkpoint for the given params.
     * Returns the progress if found, null otherwise.
     */
    tryResume(format: string, params: Record<string, unknown>): CheckpointData | null;
    /**
     * Update progress. Auto-saves to disk if enough time has passed.
     */
    update(index: bigint, attempts: number, elapsedMs: number, speed: number): void;
    /**
     * Mark as found and save.
     */
    markFound(password: string): void;
    /**
     * Force save to disk.
     */
    save(): void;
    /**
     * Delete checkpoint (session complete or user wants fresh start).
     */
    delete(): void;
    /**
     * Get the current checkpoint file path.
     */
    getFilePath(): string | null;
    /**
     * Get current resume index as bigint.
     */
    getResumeIndex(): bigint;
    /**
     * Get total attempts so far.
     */
    getAttempts(): number;
    /**
     * Get elapsed time from previous sessions.
     */
    getPreviousElapsedMs(): number;
    /**
     * List all checkpoint files in the directory.
     */
    listCheckpoints(): {
        file: string;
        data: CheckpointData;
    }[];
}
//# sourceMappingURL=checkpoint.d.ts.map