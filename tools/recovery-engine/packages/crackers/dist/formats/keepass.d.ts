import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface KeePassParams extends CrackerParams {
    type: 'keepass';
    kdbxVersion: 3 | 4;
    kdfType: 'aes-kdf' | 'argon2d' | 'argon2id';
    transformSeed?: string;
    transformRounds?: number;
    argon2Salt?: string;
    argon2Iterations?: number;
    argon2Memory?: number;
    argon2Parallelism?: number;
    argon2Version?: number;
    masterSeed: string;
    encryptionIV: string;
    streamStartBytes?: string;
    encryptedPayload?: string;
    headerSha256?: string;
    headerHmac?: string;
    headerBytes?: string;
}
export declare const KeePassCracker: CrackerPlugin;
//# sourceMappingURL=keepass.d.ts.map