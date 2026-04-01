import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface MultiCoinParams extends CrackerParams {
    type: 'multicoin';
    subtype: string;
    kdf: string;
    salt: string;
    iv: string;
    ciphertext: string;
    authTag?: string;
    iterations?: number;
    scryptN?: number;
    scryptR?: number;
    scryptP?: number;
    dklen?: number;
}
export declare const MultiCoinWalletCracker: CrackerPlugin;
//# sourceMappingURL=multicoin-wallets.d.ts.map