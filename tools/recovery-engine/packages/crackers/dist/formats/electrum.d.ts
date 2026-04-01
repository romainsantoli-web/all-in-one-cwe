import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface ElectrumParams extends CrackerParams {
    type: 'electrum';
    version: 1 | 2 | 4;
    encryptedData: string;
    iv?: string;
    iterations: number;
}
export declare const ElectrumCracker: CrackerPlugin;
//# sourceMappingURL=electrum.d.ts.map