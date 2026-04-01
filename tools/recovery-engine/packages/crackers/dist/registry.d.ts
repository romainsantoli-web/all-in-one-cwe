/**
 * Format Registry — Auto-detection and cracker lookup
 */
import type { CrackerPlugin, CrackerParams } from './types.js';
/**
 * Get a cracker by its ID.
 */
export declare function getCracker(id: string): CrackerPlugin | undefined;
/**
 * Get all registered crackers.
 */
export declare function getAllCrackers(): CrackerPlugin[];
/**
 * Auto-detect the format of a file and return the matching cracker.
 */
export declare function detectFormat(filePath: string): Promise<CrackerPlugin | null>;
/**
 * Universal tryPassword dispatcher — called from workers.
 * Routes to the correct cracker based on params.type.
 */
export declare function tryPassword(password: string, params: CrackerParams): Promise<{
    success: boolean;
    raw?: string;
}>;
/**
 * List all supported formats with descriptions.
 */
export declare function listFormats(): Array<{
    id: string;
    name: string;
    description: string;
    extensions: string[];
}>;
//# sourceMappingURL=registry.d.ts.map