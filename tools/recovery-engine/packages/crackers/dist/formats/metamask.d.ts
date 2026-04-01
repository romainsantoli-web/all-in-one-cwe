import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface MetaMaskParams extends CrackerParams {
    type: 'metamask';
    data: string;
    iv: string;
    salt: string;
    iterations: number;
}
export declare const MetaMaskCracker: CrackerPlugin;
//# sourceMappingURL=metamask.d.ts.map