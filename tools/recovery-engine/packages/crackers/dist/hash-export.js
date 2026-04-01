/**
 * Hash Export for Hashcat & John the Ripper
 *
 * Converts cracker params to standardized hash strings for external tools.
 * Supports all 23 formats with appropriate hashcat modes and JtR tags.
 */
/**
 * Export cracker params as hashcat/john hash strings.
 */
export function exportHash(params) {
    const type = params.type;
    switch (type) {
        case 'metamask':
            return exportMetaMask(params);
        case 'bitcoin-core':
            return exportBitcoinCore(params);
        case 'ethereum-keystore':
            return exportEthKeystore(params);
        case 'electrum':
            return exportElectrum(params);
        case 'exodus':
            return exportExodus(params);
        case 'keepass':
            return exportKeePass(params);
        case '1password':
            return export1Password(params);
        case 'bitwarden':
            return exportBitwarden(params);
        case 'lastpass':
            return exportLastPass(params);
        case 'dashlane':
            return exportDashlane(params);
        case 'zip':
            return exportZip(params);
        case 'rar':
            return exportRar(params);
        case '7zip':
            return export7Zip(params);
        case 'pdf':
            return exportPdf(params);
        case 'ms-office':
            return exportMsOffice(params);
        case 'libreoffice':
            return exportLibreOffice(params);
        case 'luks':
            return exportLuks(params);
        case 'filevault2':
            return exportFileVault2(params);
        case 'veracrypt':
            return exportVeraCrypt(params);
        case 'ssh':
            return exportSsh(params);
        case 'pgp':
            return exportPgp(params);
        case 'wifi':
            return exportWifi(params);
        case 'multicoin':
            return exportMultiCoin(params);
        default:
            return {
                hashcat: `# Unsupported format: ${type}`,
                hashcatMode: 0,
                johnFormat: 'unknown',
                john: `# Unsupported format: ${type}`,
                description: `No hash export available for ${type}`,
            };
    }
}
// ── Format-specific exporters ──
function exportMetaMask(p) {
    // hashcat mode 26600
    const data = p.data || '';
    const iv = p.iv || '';
    const salt = p.salt || '';
    return {
        hashcat: `$metamask$${salt}$${iv}$${data}`,
        hashcatMode: 26600,
        johnFormat: 'MetaMask',
        john: `$metamask$${salt}$${iv}$${data}`,
        description: `MetaMask vault (PBKDF2 ${p.iterations || 600000} rounds)`,
    };
}
function exportBitcoinCore(p) {
    // hashcat mode 11300
    return {
        hashcat: `$bitcoin$${p.cry_rounds || 25000}$${p.cry_salt || ''}$${p.cry_master || ''}$${p.pub_key || ''}`,
        hashcatMode: 11300,
        johnFormat: 'Bitcoin',
        john: `$bitcoin$${p.cry_rounds || 25000}$${p.cry_salt || ''}$${p.cry_master || ''}`,
        description: `Bitcoin Core wallet.dat`,
    };
}
function exportEthKeystore(p) {
    // hashcat mode 15600 (scrypt) or 15700 (pbkdf2)
    const mode = p.kdf === 'scrypt' ? 15600 : 15700;
    if (p.kdf === 'scrypt') {
        return {
            hashcat: `$ethereum$s*${p.n || 262144}*${p.r || 8}*${p.p || 1}*${p.salt}*${p.ciphertext}*${p.mac}`,
            hashcatMode: mode,
            johnFormat: 'ethereum-scrypt',
            john: `$ethereum$s*${p.n || 262144}*${p.r || 8}*${p.p || 1}*${p.salt}*${p.ciphertext}*${p.mac}`,
            description: `Ethereum keystore (scrypt N=${p.n || 262144})`,
        };
    }
    return {
        hashcat: `$ethereum$p*${p.c || 262144}*${p.salt}*${p.ciphertext}*${p.mac}`,
        hashcatMode: mode,
        johnFormat: 'ethereum-pbkdf2',
        john: `$ethereum$p*${p.c || 262144}*${p.salt}*${p.ciphertext}*${p.mac}`,
        description: `Ethereum keystore (PBKDF2 c=${p.c || 262144})`,
    };
}
function exportElectrum(p) {
    // hashcat mode 16600
    return {
        hashcat: `$electrum$4*${p.salt || ''}*${p.data || ''}`,
        hashcatMode: 16600,
        johnFormat: 'electrum',
        john: `$electrum$4*${p.salt || ''}*${p.data || ''}`,
        description: `Electrum wallet`,
    };
}
function exportExodus(p) {
    return {
        hashcat: `$exodus$*${p.salt || ''}*${p.iv || ''}*${p.ct || ''}`,
        hashcatMode: 0,
        johnFormat: 'exodus',
        john: `$exodus$*${p.salt || ''}*${p.iv || ''}*${p.ct || ''}`,
        description: `Exodus wallet (scrypt)`,
    };
}
function exportKeePass(p) {
    // hashcat modes: 13400 (AES-KDF), 29000 (Argon2)
    const isArgon2 = p.kdfType?.includes('argon2');
    const mode = isArgon2 ? 29000 : 13400;
    return {
        hashcat: `$keepass$*2*${p.transformRounds || p.argon2Iterations || 0}*${p.kdbxVersion || 4}*${p.masterSeed || ''}*${p.transformSeed || p.argon2Salt || ''}*${p.encryptionIV || ''}*${p.headerHmac || p.streamStartBytes || ''}`,
        hashcatMode: mode,
        johnFormat: 'KeePass',
        john: `$keepass$*2*${p.transformRounds || p.argon2Iterations || 0}*${p.kdbxVersion || 4}*${p.masterSeed || ''}*${p.transformSeed || p.argon2Salt || ''}*${p.encryptionIV || ''}`,
        description: `KeePass KDBX${p.kdbxVersion || '?'} (${p.kdfType || 'unknown'})`,
    };
}
function export1Password(p) {
    // hashcat mode 8200
    return {
        hashcat: `$1password$*${p.iterations || 100000}*${p.salt || ''}*${p.iv || ''}*${p.ct || ''}`,
        hashcatMode: 8200,
        johnFormat: '1password',
        john: `$agilekeychain$*${p.iterations || 100000}*${p.salt || ''}*${p.iv || ''}*${p.ct || ''}`,
        description: `1Password vault`,
    };
}
function exportBitwarden(p) {
    // hashcat mode 31700 (Bitwarden)
    return {
        hashcat: `$bitwarden$2*${p.iterations || 600000}*${p.salt || ''}*${p.encKey || ''}`,
        hashcatMode: 31700,
        johnFormat: 'bitwarden',
        john: `$bitwarden$2*${p.iterations || 600000}*${p.salt || ''}*${p.encKey || ''}`,
        description: `Bitwarden vault (PBKDF2 ${p.iterations || 600000})`,
    };
}
function exportLastPass(p) {
    // hashcat mode 6800
    return {
        hashcat: `$lastpass$${p.iterations || 100100}$${p.hash || ''}`,
        hashcatMode: 6800,
        johnFormat: 'LastPass',
        john: `$lastpass$${p.iterations || 100100}$${p.hash || ''}`,
        description: `LastPass vault`,
    };
}
function exportDashlane(p) {
    return {
        hashcat: `$dashlane$*${p.salt || ''}*${p.iv || ''}*${p.ct || ''}`,
        hashcatMode: 0,
        johnFormat: 'dashlane',
        john: `$dashlane$*${p.salt || ''}*${p.iv || ''}*${p.ct || ''}`,
        description: `Dashlane vault`,
    };
}
function exportZip(p) {
    // hashcat modes: 13600 (WinZip AES), 17200 (PKZIP), 17210 (PKZIP2), 17220 (PKZIP3), 17225 (PKZIP4)
    const mode = p.encMethod === 'aes' ? 13600 : 17200;
    return {
        hashcat: `$zip2$*0*${p.compMethod || 8}*0*${p.salt || ''}*${p.verifier || ''}*${p.authCode || ''}*${p.data || ''}*$/zip2$`,
        hashcatMode: mode,
        johnFormat: 'ZIP',
        john: `$zip2$*0*${p.compMethod || 8}*0*${p.salt || ''}*${p.verifier || ''}*${p.authCode || ''}*${p.data || ''}*$/zip2$`,
        description: `ZIP archive (${p.encMethod || 'PKZIP'})`,
    };
}
function exportRar(p) {
    // hashcat modes: 12500 (RAR3), 13000 (RAR5)
    const mode = p.version === 5 ? 13000 : 12500;
    if (p.version === 5) {
        return {
            hashcat: `$rar5$16$${p.salt || ''}$${p.kdfCount || 15}$${p.checkValue || ''}`,
            hashcatMode: 13000,
            johnFormat: 'rar5',
            john: `$rar5$16$${p.salt || ''}$${p.kdfCount || 15}$${p.checkValue || ''}`,
            description: `RAR5 archive`,
        };
    }
    return {
        hashcat: `$RAR3$*0*${p.salt3 || ''}*${p.encData3 || ''}`,
        hashcatMode: 12500,
        johnFormat: 'rar',
        john: `$RAR3$*0*${p.salt3 || ''}*${p.encData3 || ''}`,
        description: `RAR3 archive`,
    };
}
function export7Zip(p) {
    // hashcat mode 11600
    return {
        hashcat: `$7z$0$${p.numCyclesPower || 19}$${p.salt || ''}$${p.iv || ''}$${p.crc32 || 0}$${p.packSize || 0}$${p.unpackSize || 0}$${p.encBlock || ''}`,
        hashcatMode: 11600,
        johnFormat: '7z',
        john: `$7z$0$${p.numCyclesPower || 19}$${p.salt || ''}$${p.iv || ''}$${p.crc32 || 0}$${p.packSize || 0}$${p.unpackSize || 0}$${p.encBlock || ''}`,
        description: `7-Zip archive (2^${p.numCyclesPower || 19} iterations)`,
    };
}
function exportPdf(p) {
    // hashcat modes: 10400 (PDF 1.1-1.3), 10500 (PDF 1.4-1.6), 10600 (PDF 1.7 L3), 10700 (PDF 1.7 L8)
    const mode = p.revision <= 3 ? 10400 : p.revision === 4 ? 10500 : 10700;
    return {
        hashcat: `$pdf$${p.version || 1}*${p.revision || 3}*128*${p.permissions || -3904}*1*16*${p.ownerHash || ''}*32*${p.userHash || ''}*32*${p.id || ''}`,
        hashcatMode: mode,
        johnFormat: 'PDF',
        john: `$pdf$${p.version || 1}*${p.revision || 3}*128*${p.permissions || -3904}*1*16*${p.ownerHash || ''}*32*${p.userHash || ''}*32*${p.id || ''}`,
        description: `PDF v${p.version || '?'} R${p.revision || '?'}`,
    };
}
function exportMsOffice(p) {
    // hashcat modes: 9400 (Office 2007), 9500 (Office 2010), 9600 (Office 2013), 25300 (Office 2016)
    const yearModes = { 2007: 9400, 2010: 9500, 2013: 9600, 2016: 25300 };
    const mode = yearModes[p.version || 2013] || 9600;
    return {
        hashcat: `$office$*${p.version || 2013}*${p.spinCount || 100000}*256*16*${p.salt || ''}*${p.encryptedVerifier || ''}*${p.encryptedVerifierHash || ''}`,
        hashcatMode: mode,
        johnFormat: 'Office',
        john: `$office$*${p.version || 2013}*${p.spinCount || 100000}*256*16*${p.salt || ''}*${p.encryptedVerifier || ''}*${p.encryptedVerifierHash || ''}`,
        description: `MS Office ${p.version || '?'}`,
    };
}
function exportLibreOffice(p) {
    return {
        hashcat: `$odf$*1*1*${p.iterations || 100000}*32*${p.salt || ''}*16*${p.iv || ''}*${p.checksum || ''}*${p.encData || ''}`,
        hashcatMode: 18400,
        johnFormat: 'ODF',
        john: `$odf$*1*1*${p.iterations || 100000}*32*${p.salt || ''}*16*${p.iv || ''}*${p.checksum || ''}*${p.encData || ''}`,
        description: `LibreOffice/ODF`,
    };
}
function exportLuks(p) {
    return {
        hashcat: `$luks$${p.version || 1}$${p.hashSpec || 'sha256'}$${p.slotIterations || 0}$${p.slotSalt || ''}$${p.mkDigest || ''}`,
        hashcatMode: 14600,
        johnFormat: 'LUKS',
        john: `$luks$${p.hashSpec || 'sha256'}$${p.slotSalt || ''}$${p.mkDigest || ''}`,
        description: `LUKS${p.version || '?'} (${p.argon2Type || 'PBKDF2'})`,
    };
}
function exportFileVault2(p) {
    // hashcat mode 16700
    return {
        hashcat: `$fvde$1$${p.kdfIterations || 0}$${p.salt || ''}$${p.wrappedKek || ''}`,
        hashcatMode: 16700,
        johnFormat: 'FVDE',
        john: `$fvde$1$${p.kdfIterations || 0}$${p.salt || ''}$${p.wrappedKek || ''}`,
        description: `FileVault 2 / APFS encrypted`,
    };
}
function exportVeraCrypt(p) {
    // hashcat modes: 13711-13773 depending on hash + PIM
    const mode = p.hashAlgo === 'sha512' ? 13721 : p.hashAlgo === 'whirlpool' ? 13731 : 13711;
    return {
        hashcat: Buffer.from(p.headerData || '', 'base64').toString('hex'),
        hashcatMode: mode,
        johnFormat: 'VeraCrypt',
        john: `$veracrypt$${p.headerData || ''}`,
        description: `VeraCrypt volume (${p.hashAlgo || 'unknown'})`,
    };
}
function exportSsh(p) {
    // hashcat mode 22911 (RSA), 22921 (DSA), 22931 (ECDSA), 22941 (ED25519)
    return {
        hashcat: `$sshng$${p.cipherName || '0'}$${p.kdfRounds || 16}$${p.salt || ''}$${p.encData || ''}`,
        hashcatMode: 22911,
        johnFormat: 'SSH',
        john: `$sshng$${p.cipherName || '0'}$${p.kdfRounds || 16}$${p.salt || ''}$${p.encData || ''}`,
        description: `SSH private key (${p.keyType || 'unknown'})`,
    };
}
function exportPgp(p) {
    // hashcat modes: 17010 (RSA), 17020 (DSA), 17030 (ECDSA)
    return {
        hashcat: `$gpg$*1*${p.hashAlgo || 2}*${p.cipherAlgo || 9}*${p.s2kType || 3}*${p.s2kHash || 2}*${p.s2kCount || 65536}*${p.salt || ''}*${p.iv || ''}*${p.encData || ''}`,
        hashcatMode: 17010,
        johnFormat: 'gpg',
        john: `$gpg$*1*${p.hashAlgo || 2}*${p.cipherAlgo || 9}*${p.s2kType || 3}*${p.s2kHash || 2}*${p.s2kCount || 65536}*${p.salt || ''}*${p.iv || ''}*${p.encData || ''}`,
        description: `PGP/GPG private key`,
    };
}
function exportWifi(p) {
    // hashcat mode 22000 (WPA-PBKDF2-PMKID+EAPOL)
    return {
        hashcat: `WPA*02*${p.pmkid || ''}*${p.bssid || ''}*${p.stmac || ''}*${p.essid || ''}*${p.anonce || ''}*${p.eapol || ''}*${p.messagePair || '00'}`,
        hashcatMode: 22000,
        johnFormat: 'wpapsk',
        john: `$WPAPSK$${p.essid || ''}#${p.pmkid || p.anonce || ''}`,
        description: `WiFi WPA/WPA2 (${p.essid || 'unknown SSID'})`,
    };
}
function exportMultiCoin(p) {
    return {
        hashcat: `$multicoin$*${p.subtype || 'generic'}*${p.kdf || 'pbkdf2'}*${p.iterations || 0}*${p.salt || ''}*${p.iv || ''}*${p.ciphertext || ''}`,
        hashcatMode: 0,
        johnFormat: 'multicoin',
        john: `$multicoin$*${p.subtype || 'generic'}*${p.kdf || 'pbkdf2'}*${p.iterations || 0}*${p.salt || ''}*${p.iv || ''}*${p.ciphertext || ''}`,
        description: `${p.subtype || 'Multi-coin'} wallet`,
    };
}
//# sourceMappingURL=hash-export.js.map