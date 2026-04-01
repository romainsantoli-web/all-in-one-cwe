import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface OnePasswordParams extends CrackerParams {
    type: '1password';
    format: 'opvault' | 'agilekeychain';
    salt: string;
    iterations: number;
    masterKey: string;
    masterKeyHmac: string;
    overviewKey?: string;
}
export declare const OnePasswordCracker: CrackerPlugin;
//# sourceMappingURL=onepassword.d.ts.map