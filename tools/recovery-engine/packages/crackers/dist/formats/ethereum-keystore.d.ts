import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface EthKeystoreParams extends CrackerParams {
    type: 'ethereum-keystore';
    kdf: 'scrypt' | 'pbkdf2';
    n?: number;
    r?: number;
    p?: number;
    c?: number;
    prf?: string;
    dklen: number;
    salt: string;
    iv: string;
    ciphertext: string;
    mac: string;
    cipher: string;
}
export declare const EthKeystoreCracker: CrackerPlugin;
//# sourceMappingURL=ethereum-keystore.d.ts.map