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
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
/**
 * Hash the cracker params to create a unique session identifier.
 */
function hashParams(params) {
    const json = JSON.stringify(params, Object.keys(params).sort());
    return crypto.createHash('sha256').update(json).digest('hex').substring(0, 16);
}
export class CheckpointManager {
    dir;
    prefix;
    autoSaveMs;
    lastSaveTime = 0;
    data = null;
    filePath = null;
    constructor(options = {}) {
        this.dir = options.directory || process.cwd();
        this.prefix = options.prefix || 'crack';
        this.autoSaveMs = options.autoSaveIntervalMs ?? 30_000;
    }
    /**
     * Initialize a new checkpoint session.
     */
    init(format, params, attack, attackConfig) {
        const paramsHash = hashParams(params);
        this.filePath = path.join(this.dir, `${this.prefix}-${format}-${paramsHash}.mmck`);
        this.data = {
            version: 1,
            format,
            paramsHash,
            attack,
            attackConfig,
            progress: {
                index: '0',
                attempts: 0,
                found: false,
                elapsedMs: 0,
                speed: 0,
            },
            timestamp: new Date().toISOString(),
        };
    }
    /**
     * Try to load an existing checkpoint for the given params.
     * Returns the progress if found, null otherwise.
     */
    tryResume(format, params) {
        const paramsHash = hashParams(params);
        const candidateFile = path.join(this.dir, `${this.prefix}-${format}-${paramsHash}.mmck`);
        try {
            if (fs.existsSync(candidateFile)) {
                const raw = fs.readFileSync(candidateFile, 'utf-8');
                const data = JSON.parse(raw);
                if (data.version === 1 && data.paramsHash === paramsHash && !data.progress.found) {
                    this.data = data;
                    this.filePath = candidateFile;
                    return data;
                }
            }
        }
        catch { /* ignore corrupt files */ }
        return null;
    }
    /**
     * Update progress. Auto-saves to disk if enough time has passed.
     */
    update(index, attempts, elapsedMs, speed) {
        if (!this.data)
            return;
        this.data.progress.index = index.toString();
        this.data.progress.attempts = attempts;
        this.data.progress.elapsedMs = elapsedMs;
        this.data.progress.speed = speed;
        this.data.timestamp = new Date().toISOString();
        const now = Date.now();
        if (now - this.lastSaveTime >= this.autoSaveMs) {
            this.save();
        }
    }
    /**
     * Mark as found and save.
     */
    markFound(password) {
        if (!this.data)
            return;
        this.data.progress.found = true;
        this.data.progress.password = password;
        this.save();
    }
    /**
     * Force save to disk.
     */
    save() {
        if (!this.data || !this.filePath)
            return;
        try {
            // Atomic write: write to temp then rename
            const tmpPath = this.filePath + '.tmp';
            fs.writeFileSync(tmpPath, JSON.stringify(this.data, null, 2), 'utf-8');
            fs.renameSync(tmpPath, this.filePath);
            this.lastSaveTime = Date.now();
        }
        catch (e) {
            console.error('Checkpoint save failed:', e.message);
        }
    }
    /**
     * Delete checkpoint (session complete or user wants fresh start).
     */
    delete() {
        if (this.filePath) {
            try {
                fs.unlinkSync(this.filePath);
            }
            catch { /* ok */ }
            try {
                fs.unlinkSync(this.filePath + '.tmp');
            }
            catch { /* ok */ }
        }
        this.data = null;
        this.filePath = null;
    }
    /**
     * Get the current checkpoint file path.
     */
    getFilePath() {
        return this.filePath;
    }
    /**
     * Get current resume index as bigint.
     */
    getResumeIndex() {
        return BigInt(this.data?.progress.index || '0');
    }
    /**
     * Get total attempts so far.
     */
    getAttempts() {
        return this.data?.progress.attempts || 0;
    }
    /**
     * Get elapsed time from previous sessions.
     */
    getPreviousElapsedMs() {
        return this.data?.progress.elapsedMs || 0;
    }
    /**
     * List all checkpoint files in the directory.
     */
    listCheckpoints() {
        const results = [];
        try {
            const files = fs.readdirSync(this.dir).filter((f) => f.endsWith('.mmck'));
            for (const file of files) {
                try {
                    const raw = fs.readFileSync(path.join(this.dir, file), 'utf-8');
                    results.push({ file, data: JSON.parse(raw) });
                }
                catch { /* skip */ }
            }
        }
        catch { /* ok */ }
        return results;
    }
}
//# sourceMappingURL=checkpoint.js.map