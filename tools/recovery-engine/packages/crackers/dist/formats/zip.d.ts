import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface ZipParams extends CrackerParams {
    type: 'zip';
    method: 'zipcrypto' | 'aes128' | 'aes192' | 'aes256';
    encHeader?: string;
    checkByte?: number;
    crc32?: number;
    salt?: string;
    verifier?: string;
    strength?: number;
}
export declare const ZipCracker: CrackerPlugin;
//# sourceMappingURL=zip.d.ts.map