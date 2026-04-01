import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface LastPassParams extends CrackerParams {
    type: 'lastpass';
    iterations: number;
    salt: string;
    encryptedVault: string;
    isBase64: boolean;
}
export declare const LastPassCracker: CrackerPlugin;
//# sourceMappingURL=lastpass.d.ts.map