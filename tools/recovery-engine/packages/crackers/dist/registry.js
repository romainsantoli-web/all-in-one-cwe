/**
 * Format Registry — Auto-detection and cracker lookup
 */
// Import all crackers
import { MetaMaskCracker } from './formats/metamask.js';
import { ZipCracker } from './formats/zip.js';
import { RarCracker } from './formats/rar.js';
import { SevenZipCracker } from './formats/sevenzip.js';
import { PdfCracker } from './formats/pdf.js';
import { OfficeCracker } from './formats/office.js';
import { KeePassCracker } from './formats/keepass.js';
import { OnePasswordCracker } from './formats/onepassword.js';
import { BitwardenCracker } from './formats/bitwarden.js';
import { LastPassCracker } from './formats/lastpass.js';
import { BitcoinCoreCracker } from './formats/bitcoin-core.js';
import { EthKeystoreCracker } from './formats/ethereum-keystore.js';
import { ElectrumCracker } from './formats/electrum.js';
import { ExodusCracker } from './formats/exodus.js';
import { MultiCoinWalletCracker } from './formats/multicoin-wallets.js';
import { VeraCryptCracker } from './formats/veracrypt.js';
import { DmgCracker } from './formats/dmg.js';
import { LuksCracker } from './formats/luks.js';
import { FileVaultCracker } from './formats/filevault.js';
import { BitLockerCracker } from './formats/bitlocker.js';
import { WifiCracker } from './formats/wifi.js';
import { SshCracker } from './formats/ssh.js';
import { IPhoneBackupCracker } from './formats/iphone-backup.js';
/** All registered crackers in priority order */
const ALL_CRACKERS = [
    // Crypto wallets (most common use case)
    MetaMaskCracker,
    BitcoinCoreCracker,
    EthKeystoreCracker,
    ElectrumCracker,
    ExodusCracker,
    MultiCoinWalletCracker,
    // Password managers
    KeePassCracker,
    OnePasswordCracker,
    BitwardenCracker,
    LastPassCracker,
    // Archives
    ZipCracker,
    RarCracker,
    SevenZipCracker,
    // Documents
    PdfCracker,
    OfficeCracker,
    // Disk / volume
    VeraCryptCracker,
    DmgCracker,
    LuksCracker,
    FileVaultCracker,
    BitLockerCracker,
    // Network
    WifiCracker,
    SshCracker,
    // Mobile
    IPhoneBackupCracker,
];
/**
 * Get a cracker by its ID.
 */
export function getCracker(id) {
    return ALL_CRACKERS.find((c) => c.id === id);
}
/**
 * Get all registered crackers.
 */
export function getAllCrackers() {
    return [...ALL_CRACKERS];
}
/**
 * Auto-detect the format of a file and return the matching cracker.
 */
export async function detectFormat(filePath) {
    for (const cracker of ALL_CRACKERS) {
        try {
            if (await cracker.detect(filePath)) {
                return cracker;
            }
        }
        catch {
            // Skip crackers that fail detection
        }
    }
    return null;
}
/**
 * Universal tryPassword dispatcher — called from workers.
 * Routes to the correct cracker based on params.type.
 */
export async function tryPassword(password, params) {
    const cracker = getCracker(params.type);
    if (!cracker) {
        throw new Error(`Unknown cracker type: ${params.type}`);
    }
    const success = await cracker.tryPassword(password, params);
    return { success };
}
/**
 * List all supported formats with descriptions.
 */
export function listFormats() {
    return ALL_CRACKERS.map((c) => ({
        id: c.id,
        name: c.name,
        description: c.description,
        extensions: c.fileExtensions,
    }));
}
//# sourceMappingURL=registry.js.map