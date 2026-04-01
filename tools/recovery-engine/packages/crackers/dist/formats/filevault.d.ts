import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface FileVaultParams extends CrackerParams {
    type: 'filevault';
    salt: string;
    iterations: number;
    wrappedKey: string;
    keyBits: number;
}
export declare const FileVaultCracker: CrackerPlugin;
//# sourceMappingURL=filevault.d.ts.map