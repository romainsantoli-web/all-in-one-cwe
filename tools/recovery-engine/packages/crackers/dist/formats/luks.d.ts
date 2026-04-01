import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface LuksParams extends CrackerParams {
    type: 'luks';
    version: 1 | 2;
    cipherName: string;
    cipherMode: string;
    hashSpec: string;
    slotSalt: string;
    slotIterations: number;
    slotKeyMaterial: string;
    slotStripes: number;
    keyBytes: number;
    argon2Type?: 'argon2i' | 'argon2id';
    argon2Memory?: number;
    argon2Cpus?: number;
    mkDigest: string;
    mkDigestSalt: string;
    mkDigestIter: number;
}
export declare const LuksCracker: CrackerPlugin;
//# sourceMappingURL=luks.d.ts.map