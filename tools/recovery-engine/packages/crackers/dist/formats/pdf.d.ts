import type { CrackerPlugin, CrackerParams } from '../types.js';
export interface PdfParams extends CrackerParams {
    type: 'pdf';
    revision: number;
    version: number;
    length: number;
    permissions: number;
    ownerPassword: string;
    userPassword: string;
    ownerEncrypt?: string;
    userEncrypt?: string;
    fileId: string;
    encryptMetadata: boolean;
}
export declare const PdfCracker: CrackerPlugin;
//# sourceMappingURL=pdf.d.ts.map