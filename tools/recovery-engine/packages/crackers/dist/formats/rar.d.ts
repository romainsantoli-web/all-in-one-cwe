import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface RarParams extends CrackerParams {
    type: 'rar';
    version: 3 | 5;
    salt?: string;
    kdfCount?: number;
    checkValue?: string;
    salt3?: string;
    encData3?: string;
}
export declare const RarCracker: CrackerPlugin;
//# sourceMappingURL=rar.d.ts.map