/**
 * WiFi WPA/WPA2 Handshake Cracker
 * Format: pcap/hccapx file with EAPOL 4-way handshake
 * KDF: PBKDF2-SHA1 × 4096
 * Verification: compute PMK → PTK → MIC → compare
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
/** hccapx file magic */
const HCCAPX_MAGIC = 0x58504348; // "HCPX" LE
/** PRF-512 (HMAC-SHA1 based PRF for 802.11i) */
function prf512(key, prefix, data) {
    const result = [];
    const R = Buffer.alloc(1);
    const prefBuf = Buffer.from(prefix + '\0');
    for (let i = 0; i < 4; i++) {
        R[0] = i;
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(prefBuf);
        hmac.update(data);
        hmac.update(R);
        result.push(hmac.digest());
    }
    return Buffer.concat(result).subarray(0, 64); // 512 bits
}
export const WifiCracker = {
    id: 'wifi',
    name: 'WiFi WPA/WPA2',
    description: 'WPA/WPA2 handshake cracking (PBKDF2-SHA1 × 4096)',
    fileExtensions: ['.pcap', '.pcapng', '.hccapx', '.cap'],
    async detect(filePath) {
        try {
            const buf = Buffer.alloc(16);
            const fd = fs.openSync(filePath, 'r');
            fs.readSync(fd, buf, 0, 16, 0);
            fs.closeSync(fd);
            // Check hccapx magic
            if (buf.readUInt32LE(0) === HCCAPX_MAGIC)
                return true;
            // Check pcap magic (0xA1B2C3D4 or 0xD4C3B2A1)
            const pcapMagic = buf.readUInt32LE(0);
            if (pcapMagic === 0xA1B2C3D4 || pcapMagic === 0xD4C3B2A1)
                return true;
            // Check pcapng (0x0A0D0D0A Section Header Block)
            if (buf.readUInt32LE(0) === 0x0A0D0D0A)
                return true;
            return filePath.endsWith('.hccapx') || filePath.endsWith('.cap');
        }
        catch {
            return false;
        }
    },
    async parse(filePath) {
        const data = fs.readFileSync(filePath);
        // Try hccapx format first (hashcat standard)
        if (data.readUInt32LE(0) === HCCAPX_MAGIC) {
            const version = data.readUInt32LE(4);
            const msgPair = data[8];
            const essidLen = data[9];
            const essid = data.subarray(10, 10 + essidLen).toString('utf-8');
            const keyVersion = data[10 + 32]; // after essid (padded to 32)
            const ap_mac = data.subarray(59, 65);
            const sta_mac = data.subarray(65, 71);
            const anonce = data.subarray(71, 103);
            const snonce = data.subarray(103, 135);
            const eapolLen = data.readUInt16LE(135);
            const eapol = data.subarray(137, 137 + eapolLen);
            const mic = eapol.subarray(81, 97); // MIC is at offset 81 in EAPOL
            return {
                type: 'wifi',
                ssid: essid,
                bssid: ap_mac.toString('base64'),
                clientMac: sta_mac.toString('base64'),
                anonce: anonce.toString('base64'),
                snonce: snonce.toString('base64'),
                eapol: eapol.toString('base64'),
                mic: mic.toString('base64'),
                keyVersion: 2,
            };
        }
        // Simplified pcap parsing — look for EAPOL frames
        // In practice, tools like hcxpcapngtool convert pcap → hccapx
        throw new Error('Please convert pcap to hccapx format using hcxpcapngtool');
    },
    async tryPassword(password, params) {
        const p = params;
        // WPA passwords: 8-63 chars
        if (password.length < 8 || password.length > 63)
            return false;
        try {
            // Step 1: PMK = PBKDF2-SHA1(password, SSID, 4096, 32)
            const pmk = await new Promise((res, rej) => crypto.pbkdf2(password, p.ssid, 4096, 32, 'sha1', (e, k) => e ? rej(e) : res(k)));
            // Step 2: Construct PTK using PRF-512
            const bssid = Buffer.from(p.bssid, 'base64');
            const clientMac = Buffer.from(p.clientMac, 'base64');
            const anonce = Buffer.from(p.anonce, 'base64');
            const snonce = Buffer.from(p.snonce, 'base64');
            // MAC addresses and nonces must be in sorted order
            const macData = Buffer.alloc(12);
            const nonceData = Buffer.alloc(64);
            if (Buffer.compare(bssid, clientMac) < 0) {
                bssid.copy(macData, 0);
                clientMac.copy(macData, 6);
            }
            else {
                clientMac.copy(macData, 0);
                bssid.copy(macData, 6);
            }
            if (Buffer.compare(anonce, snonce) < 0) {
                anonce.copy(nonceData, 0);
                snonce.copy(nonceData, 32);
            }
            else {
                snonce.copy(nonceData, 0);
                anonce.copy(nonceData, 32);
            }
            const prfInput = Buffer.concat([macData, nonceData]);
            const ptk = prf512(pmk, 'Pairwise key expansion', prfInput);
            // Step 3: Compute MIC
            const eapol = Buffer.from(p.eapol, 'base64');
            const mic = Buffer.from(p.mic, 'base64');
            // Zero out MIC field in EAPOL for computation
            const eapolZeroed = Buffer.from(eapol);
            eapolZeroed.fill(0, 81, 97); // Zero MIC field
            // KCK = PTK[0..15]
            const kck = ptk.subarray(0, 16);
            let computedMic;
            if (p.keyVersion === 1) {
                // WPA: HMAC-MD5
                computedMic = crypto.createHmac('md5', kck).update(eapolZeroed).digest();
            }
            else {
                // WPA2: HMAC-SHA1 (truncated to 16 bytes)
                computedMic = crypto.createHmac('sha1', kck).update(eapolZeroed).digest().subarray(0, 16);
            }
            return computedMic.equals(mic);
        }
        catch {
            return false;
        }
    },
    getInfo(params) {
        const p = params;
        return {
            format: 'WiFi WPA/WPA2',
            description: `Network "${p.ssid}" — WPA${p.keyVersion === 2 ? '2' : ''} handshake`,
            kdf: 'PBKDF2-SHA1 × 4,096',
            cipher: p.keyVersion === 2 ? 'AES-CCMP' : 'TKIP',
            iterations: 4096,
            difficulty: 'easy',
            estimatedSpeed: '~500-1,000/s',
        };
    },
};
//# sourceMappingURL=wifi.js.map