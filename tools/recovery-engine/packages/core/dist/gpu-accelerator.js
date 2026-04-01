/**
 * GPU Accelerator — Provides GPU-accelerated PBKDF2 cracking.
 *
 * Two modes:
 * 1. WebGPU compute shaders (browser extension context)
 * 2. Hashcat integration (CLI context, subprocess)
 *
 * Falls back gracefully to CPU if GPU is unavailable.
 */
export class GpuAccelerator {
    options;
    constructor(options = {}) {
        this.options = {
            backend: options.backend ?? 'auto',
            hashcatPath: options.hashcatPath ?? 'hashcat',
            tempDir: options.tempDir ?? '/tmp/mm-recovery',
        };
    }
    /**
     * Check if GPU acceleration is available.
     */
    async isAvailable() {
        const webgpu = await this.checkWebGPU();
        const hashcat = await this.checkHashcat();
        return { webgpu, hashcat };
    }
    /**
     * Run hashcat against the vault with a wordlist file.
     * CLI only — spawns hashcat as a subprocess.
     */
    async crackWithHashcat(vault, wordlistPath, onProgress) {
        const fs = await import('node:fs');
        const path = await import('node:path');
        const { spawn } = await import('node:child_process');
        // Ensure temp directory exists
        fs.mkdirSync(this.options.tempDir, { recursive: true });
        // Write hash file in hashcat format
        // Mode 26600: $metamask$<salt>$<iv>$<data>
        const hashLine = `$metamask$${vault.salt}$${vault.iv}$${vault.data}`;
        const hashFile = path.join(this.options.tempDir, 'vault.hash');
        const outFile = path.join(this.options.tempDir, 'cracked.txt');
        fs.writeFileSync(hashFile, hashLine);
        return new Promise((resolve, reject) => {
            const startTime = performance.now();
            let totalAttempts = 0;
            const args = [
                '-m', '26600', // MetaMask mode
                '-a', '0', // Dictionary attack
                '--potfile-disable', // Don't use potfile
                '-o', outFile, // Output file
                '--outfile-format', '2', // Output just the password
                hashFile,
                wordlistPath,
            ];
            // If vault uses non-default iterations, we may need to adjust
            // hashcat mode 26600 expects the iteration count in the hash format
            const proc = spawn(this.options.hashcatPath, args, {
                stdio: ['pipe', 'pipe', 'pipe'],
            });
            let stdout = '';
            let stderr = '';
            proc.stdout.on('data', (data) => {
                const text = data.toString();
                stdout += text;
                // Parse hashcat progress output
                const speedMatch = text.match(/Speed\.#\d+\.*:\s+(\d+)\s+H\/s/);
                const progressMatch = text.match(/Progress\.*:\s+(\d+)\/(\d+)/);
                if (speedMatch) {
                    const speed = parseInt(speedMatch[1]);
                    onProgress?.({
                        speed,
                        progress: progressMatch ? `${progressMatch[1]}/${progressMatch[2]}` : 'running...',
                    });
                }
            });
            proc.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            proc.on('close', (code) => {
                const elapsedMs = performance.now() - startTime;
                // Check if we found the password
                try {
                    if (fs.existsSync(outFile)) {
                        const password = fs.readFileSync(outFile, 'utf-8').trim();
                        if (password) {
                            // Clean up
                            fs.unlinkSync(hashFile);
                            fs.unlinkSync(outFile);
                            resolve({
                                found: true,
                                password,
                                totalAttempts,
                                elapsedMs,
                                speed: totalAttempts / (elapsedMs / 1000),
                            });
                            return;
                        }
                    }
                }
                catch {
                    // file doesn't exist = not found
                }
                // Clean up
                try {
                    fs.unlinkSync(hashFile);
                }
                catch { }
                try {
                    fs.unlinkSync(outFile);
                }
                catch { }
                if (code !== 0 && code !== 1) {
                    // code 1 = exhausted (no match), which is expected
                    reject(new Error(`Hashcat exited with code ${code}: ${stderr}`));
                    return;
                }
                resolve({
                    found: false,
                    totalAttempts,
                    elapsedMs,
                    speed: totalAttempts / (elapsedMs / 1000),
                });
            });
        });
    }
    /**
     * Generate a wordlist file from a password generator for use with hashcat.
     */
    async generateWordlist(candidates, outputPath, maxCandidates = 10_000_000) {
        const fs = await import('node:fs');
        const writeStream = fs.createWriteStream(outputPath);
        let count = 0;
        for (const candidate of candidates) {
            if (count >= maxCandidates)
                break;
            writeStream.write(candidate + '\n');
            count++;
        }
        writeStream.end();
        await new Promise((resolve) => writeStream.on('finish', resolve));
        return count;
    }
    // ---------- Private ----------
    async checkWebGPU() {
        try {
            if (typeof navigator !== 'undefined' && 'gpu' in navigator) {
                const adapter = await navigator.gpu.requestAdapter();
                return !!adapter;
            }
        }
        catch { }
        return false;
    }
    async checkHashcat() {
        if (typeof process === 'undefined')
            return false;
        try {
            const { execSync } = await import('node:child_process');
            execSync(`${this.options.hashcatPath} --version`, { stdio: 'pipe' });
            return true;
        }
        catch {
            return false;
        }
    }
}
//# sourceMappingURL=gpu-accelerator.js.map