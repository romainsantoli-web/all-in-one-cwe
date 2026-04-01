import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface SevenZipParams extends CrackerParams {
    type: '7zip';
    salt: string;
    iv: string;
    numCyclesPower: number;
    encBlock: string;
    crc32?: number;
    packSize: number;
    unpackSize: number;
}
export declare const SevenZipCracker: CrackerPlugin;
//# sourceMappingURL=sevenzip.d.ts.map