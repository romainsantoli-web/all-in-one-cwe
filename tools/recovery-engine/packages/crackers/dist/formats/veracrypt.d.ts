import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface VeraCryptParams extends CrackerParams {
    type: 'veracrypt';
    header: string;
    backupHeader?: string;
    isTrueCrypt: boolean;
}
export declare const VeraCryptCracker: CrackerPlugin;
//# sourceMappingURL=veracrypt.d.ts.map