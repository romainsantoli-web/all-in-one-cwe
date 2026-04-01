import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface OfficeParams extends CrackerParams {
    type: 'office';
    version: '2010' | '2013+';
    hashAlgorithm: string;
    keyBits: number;
    saltValue: string;
    spinCount: number;
    encVerifierHashInput: string;
    encVerifierHashValue: string;
    blockSize: number;
}
export declare const OfficeCracker: CrackerPlugin;
//# sourceMappingURL=office.d.ts.map