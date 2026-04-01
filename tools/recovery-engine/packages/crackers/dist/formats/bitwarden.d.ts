import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface BitwardenParams extends CrackerParams {
    type: 'bitwarden';
    kdfType: 'pbkdf2' | 'argon2id';
    iterations: number;
    encType: number;
    iv: string;
    ct: string;
    mac: string;
    salt?: string;
    argon2Memory?: number;
    argon2Parallelism?: number;
}
export declare const BitwardenCracker: CrackerPlugin;
//# sourceMappingURL=bitwarden.d.ts.map