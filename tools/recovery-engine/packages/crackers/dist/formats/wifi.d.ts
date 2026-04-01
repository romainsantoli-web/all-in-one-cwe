import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface WifiParams extends CrackerParams {
    type: 'wifi';
    ssid: string;
    bssid: string;
    clientMac: string;
    anonce: string;
    snonce: string;
    eapol: string;
    mic: string;
    keyVersion: number;
}
export declare const WifiCracker: CrackerPlugin;
//# sourceMappingURL=wifi.d.ts.map