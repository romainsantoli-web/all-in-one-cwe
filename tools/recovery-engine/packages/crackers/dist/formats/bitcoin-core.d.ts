import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface BitcoinCoreParams extends CrackerParams {
    type: 'bitcoin-core';
    encryptedKey: string;
    salt: string;
    derivationMethod: number;
    iterations: number;
}
export declare const BitcoinCoreCracker: CrackerPlugin;
//# sourceMappingURL=bitcoin-core.d.ts.map