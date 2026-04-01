import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface BitLockerParams extends CrackerParams {
    type: 'bitlocker';
    salt: string;
    encryptedVmk: string;
    nonce: string;
    macTag: string;
    iterations: number;
}
export declare const BitLockerCracker: CrackerPlugin;
//# sourceMappingURL=bitlocker.d.ts.map