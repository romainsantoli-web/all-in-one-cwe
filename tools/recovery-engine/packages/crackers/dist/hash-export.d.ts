/**
 * Hash Export for Hashcat & John the Ripper
 *
 * Converts cracker params to standardized hash strings for external tools.
 * Supports all 23 formats with appropriate hashcat modes and JtR tags.
 */
import type { CrackerParams } from './types.js';
export interface HashExport {
    /** Hashcat-compatible hash string */
    hashcat: string;
    /** Hashcat mode number (-m flag) */
    hashcatMode: number;
    /** John the Ripper format tag */
    johnFormat: string;
    /** John the Ripper hash string */
    john: string;
    /** Human-readable description */
    description: string;
}
/**
 * Export cracker params as hashcat/john hash strings.
 */
export declare function exportHash(params: CrackerParams): HashExport;
//# sourceMappingURL=hash-export.d.ts.map