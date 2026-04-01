import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface SshParams extends CrackerParams {
    type: 'ssh';
    format: 'openssh' | 'pem-rsa' | 'pem-dsa' | 'pem-ec';
    cipherName: string;
    kdfName: string;
    salt: string;
    rounds: number;
    encData: string;
}
export declare const SshCracker: CrackerPlugin;
//# sourceMappingURL=ssh.d.ts.map