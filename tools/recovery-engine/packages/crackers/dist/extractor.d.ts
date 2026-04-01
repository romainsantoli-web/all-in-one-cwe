/**
 * Universal File Extractor
 *
 * Automatically finds encrypted files on the local system
 * based on known default installation paths for each format.
 *
 * macOS + Linux + Windows paths supported.
 */
export interface ExtractLocation {
    /** Cracker format id */
    formatId: string;
    /** Human-readable name */
    formatName: string;
    /** Category */
    category: 'wallet' | 'password-manager' | 'archive' | 'document' | 'disk' | 'network' | 'mobile';
    /** Full absolute path to the found file/directory */
    filePath: string;
    /** Size in bytes */
    size: number;
    /** Last modified */
    modified: Date;
    /** Whether the file appears encrypted */
    encrypted: boolean;
    /** Extra info */
    note?: string;
}
export interface ExtractResult {
    formatId: string;
    formatName: string;
    found: ExtractLocation[];
    searchedPaths: string[];
}
interface FormatPaths {
    id: string;
    name: string;
    category: ExtractLocation['category'];
    /** Glob-like patterns — we resolve them manually */
    paths: string[];
    /** File patterns to match inside directories */
    filePatterns?: string[];
    /** Quick check: is the found file actually encrypted? */
    isEncrypted?: (filePath: string) => boolean;
    note?: string;
}
/**
 * Get all known search paths for a format.
 */
export declare function getFormatPaths(formatId: string): FormatPaths[];
/**
 * Get all known search paths grouped by category.
 */
export declare function getPathsByCategory(category?: ExtractLocation['category']): FormatPaths[];
/**
 * Scan the system for a specific format and return found files.
 */
export declare function scanFormat(formatId: string): ExtractResult;
/**
 * Scan ALL formats and return everything found on the system.
 */
export declare function scanAll(): ExtractResult[];
/**
 * Scan a specific category.
 */
export declare function scanCategory(category: ExtractLocation['category']): ExtractResult[];
/**
 * Copy a found file to a working directory for cracking.
 */
export declare function extractFile(source: string, outputDir: string, formatId?: string): string;
/**
 * Get all supported categories.
 */
export declare function getCategories(): Array<{
    id: ExtractLocation['category'];
    name: string;
    formats: string[];
}>;
export {};
//# sourceMappingURL=extractor.d.ts.map