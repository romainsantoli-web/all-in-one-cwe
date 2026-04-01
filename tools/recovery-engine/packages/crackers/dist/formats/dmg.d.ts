import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface DmgParams extends CrackerParams {
    type: 'dmg';
    salt: string;
    iterations: number;
    keyBits: number;
    iv: string;
    encKeyBlob: string;
    hmacKey?: string;
}
export declare const DmgCracker: CrackerPlugin;
//# sourceMappingURL=dmg.d.ts.map