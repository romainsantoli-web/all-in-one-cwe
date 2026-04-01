/**
 * @metamask-recovery/crackers — Universal Format Crackers
 *
 * Supports 23+ encrypted file formats:
 *  • Crypto wallets: MetaMask, Bitcoin Core, Ethereum, Electrum, Exodus, Monero, Solana, etc.
 *  • Password managers: KeePass, 1Password, Bitwarden, LastPass
 *  • Archives: ZIP, RAR, 7-Zip
 *  • Documents: PDF, Office (Word/Excel/PowerPoint)
 *  • Disk encryption: VeraCrypt/TrueCrypt, DMG, LUKS, FileVault, BitLocker
 *  • Network: WiFi WPA/WPA2, SSH private keys
 *  • Mobile: iPhone/iTunes backups
 */
export type { CrackerPlugin, CrackerParams, FormatInfo, TryResult } from './types.js';
export { getCracker, getAllCrackers, detectFormat, tryPassword, listFormats, } from './registry.js';
export { scanFormat, scanAll, scanCategory, extractFile, getFormatPaths, getPathsByCategory, getCategories, type ExtractLocation, type ExtractResult, } from './extractor.js';
export { DeepScanner, type DeepScanResult, type DeepScanOptions, type DeepSource } from './deep-scan.js';
export { exportHash, type HashExport } from './hash-export.js';
export { MetaMaskCracker } from './formats/metamask.js';
export { ZipCracker } from './formats/zip.js';
export { RarCracker } from './formats/rar.js';
export { SevenZipCracker } from './formats/sevenzip.js';
export { PdfCracker } from './formats/pdf.js';
export { OfficeCracker } from './formats/office.js';
export { KeePassCracker } from './formats/keepass.js';
export { OnePasswordCracker } from './formats/onepassword.js';
export { BitwardenCracker } from './formats/bitwarden.js';
export { LastPassCracker } from './formats/lastpass.js';
export { BitcoinCoreCracker } from './formats/bitcoin-core.js';
export { EthKeystoreCracker } from './formats/ethereum-keystore.js';
export { ElectrumCracker } from './formats/electrum.js';
export { ExodusCracker } from './formats/exodus.js';
export { MultiCoinWalletCracker } from './formats/multicoin-wallets.js';
export { VeraCryptCracker } from './formats/veracrypt.js';
export { DmgCracker } from './formats/dmg.js';
export { LuksCracker } from './formats/luks.js';
export { FileVaultCracker } from './formats/filevault.js';
export { BitLockerCracker } from './formats/bitlocker.js';
export { WifiCracker } from './formats/wifi.js';
export { SshCracker } from './formats/ssh.js';
export { IPhoneBackupCracker } from './formats/iphone-backup.js';
//# sourceMappingURL=index.d.ts.map