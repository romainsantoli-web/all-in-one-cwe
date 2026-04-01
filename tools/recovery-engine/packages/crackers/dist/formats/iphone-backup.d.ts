import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface IPhoneBackupParams extends CrackerParams {
    type: 'iphone-backup';
    uuid?: string;
    dpsl: string;
    dpic: number;
    classKeys: Array<{
        uuid: string;
        class: number;
        wrappedKey: string;
        wrapType: number;
    }>;
    legacySalt?: string;
    legacyIter?: number;
}
export declare const IPhoneBackupCracker: CrackerPlugin;
//# sourceMappingURL=iphone-backup.d.ts.map