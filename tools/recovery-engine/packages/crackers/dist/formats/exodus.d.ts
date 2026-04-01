import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface ExodusParams extends CrackerParams {
    type: 'exodus';
    salt: string;
    nonce: string;
    ciphertext: string;
    authTag: string;
    scryptN: number;
    scryptR: number;
    scryptP: number;
}
export declare const ExodusCracker: CrackerPlugin;
//# sourceMappingURL=exodus.d.ts.map