/**
 * Deep Recovery Scanner
 *
 * Forensic-grade scanner that searches beyond default paths:
 * - Time Machine backups
 * - Chrome / Brave / Firefox Sync data
 * - iCloud Drive
 * - Mounted external volumes
 * - Spotlight / mdfind (macOS)
 * - Old user profiles
 * - Trash
 * - USB drives & external disks
 *
 * Designed for the scenario: "I changed computers and lost my vault"
 */
export interface DeepScanResult {
    filePath: string;
    source: string;
    sourceType: DeepSource;
    formatHint: string;
    size: number;
    modified: Date;
    backupDate?: Date;
    profile?: string;
    encrypted: boolean;
    confidence: 'high' | 'medium' | 'low';
    note?: string;
}
export type DeepSource = 'time-machine' | 'chrome-sync' | 'icloud' | 'external-volume' | 'trash' | 'spotlight' | 'old-profile' | 'local-backup' | 'firefox-profile' | 'usb-drive';
export interface DeepScanOptions {
    /** Formats to search for (default: all) */
    formats?: string[];
    /** Maximum directory depth for recursive search */
    maxDepth?: number;
    /** Include Time Machine backups */
    timeMachine?: boolean;
    /** Include external/mounted volumes */
    externalVolumes?: boolean;
    /** Include iCloud */
    icloud?: boolean;
    /** Include Trash */
    trash?: boolean;
    /** Use Spotlight (mdfind) for fast indexed search */
    spotlight?: boolean;
    /** Include Firefox profiles */
    firefox?: boolean;
    /** Scan all Chrome/Brave profiles (not just Default) */
    allProfiles?: boolean;
    /** Progress callback */
    onProgress?: (msg: string) => void;
}
export declare class DeepScanner {
    private opts;
    private results;
    private visited;
    constructor(options?: DeepScanOptions);
    /**
     * Run the full deep scan. Returns all found vault/wallet files.
     */
    scan(): Promise<DeepScanResult[]>;
    private scanTimeMachine;
    private scanTimeMachineBackup;
    private scanAllBrowserProfiles;
    private scanFirefoxProfiles;
    private scanICloud;
    private scanExternalVolumes;
    private scanTrash;
    private scanSpotlight;
    private scanOldProfiles;
    private scanLocalBackups;
    private scanHomeDir;
    private recursiveScan;
    private scanDirForSignature;
    private verifyFile;
    private addResult;
    private dedup;
    private emit;
}
//# sourceMappingURL=deep-scan.d.ts.map