/**
 * Mask Attack Generator
 *
 * Generates password candidates from mask patterns (hashcat-compatible).
 *
 * Built-in charsets:
 *   ?l = lowercase (a-z)
 *   ?u = uppercase (A-Z)
 *   ?d = digit (0-9)
 *   ?s = special (!@#$%^&*…)
 *   ?a = all printable ASCII
 *   ?b = byte (0x00-0xFF)
 *   ?h = hex lowercase (0-9a-f)
 *   ?H = hex uppercase (0-9A-F)
 *
 * Custom charsets: ?1 ?2 ?3 ?4 (user-defined)
 *
 * Examples:
 *   "?u?l?l?l?l?d?d?d"          → Password123 style
 *   "pass?d?d?d?d"               → pass0000–pass9999
 *   "?1?1?1?1?d?d" --custom1 "aeiou"  → vowels + digits
 */
// ── Built-in charsets ──
const CHARSET_LOWER = 'abcdefghijklmnopqrstuvwxyz';
const CHARSET_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CHARSET_DIGIT = '0123456789';
const CHARSET_SPECIAL = '!@#$%^&*()-_=+[]{}|;:\'",.<>?/`~\\';
const CHARSET_ALL = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGIT + CHARSET_SPECIAL;
const CHARSET_HEX_LOWER = '0123456789abcdef';
const CHARSET_HEX_UPPER = '0123456789ABCDEF';
/**
 * Parse a mask string into an array of position descriptors.
 */
export function parseMask(mask, options = {}) {
    const positions = [];
    let i = 0;
    while (i < mask.length) {
        if (mask[i] === '?' && i + 1 < mask.length) {
            const code = mask[i + 1];
            let charset;
            switch (code) {
                case 'l':
                    charset = CHARSET_LOWER;
                    break;
                case 'u':
                    charset = CHARSET_UPPER;
                    break;
                case 'd':
                    charset = CHARSET_DIGIT;
                    break;
                case 's':
                    charset = CHARSET_SPECIAL;
                    break;
                case 'a':
                    charset = CHARSET_ALL;
                    break;
                case 'h':
                    charset = CHARSET_HEX_LOWER;
                    break;
                case 'H':
                    charset = CHARSET_HEX_UPPER;
                    break;
                case '1':
                    charset = options.custom1 || CHARSET_LOWER;
                    break;
                case '2':
                    charset = options.custom2 || CHARSET_UPPER;
                    break;
                case '3':
                    charset = options.custom3 || CHARSET_DIGIT;
                    break;
                case '4':
                    charset = options.custom4 || CHARSET_SPECIAL;
                    break;
                case '?': // Literal '?'
                    positions.push({ charset: '', isFixed: true, fixedChar: '?' });
                    i += 2;
                    continue;
                default:
                    // Unknown — treat as literal
                    positions.push({ charset: '', isFixed: true, fixedChar: mask[i] });
                    i += 1;
                    continue;
            }
            positions.push({ charset, isFixed: false });
            i += 2;
        }
        else {
            // Fixed literal character
            positions.push({ charset: '', isFixed: true, fixedChar: mask[i] });
            i += 1;
        }
    }
    return positions;
}
/**
 * Calculate total keyspace for a parsed mask.
 */
export function maskKeyspace(positions) {
    let total = 1n;
    for (const pos of positions) {
        if (!pos.isFixed) {
            total *= BigInt(pos.charset.length);
        }
    }
    return total;
}
/**
 * Generate all candidates from a mask pattern.
 * Yields one password at a time (lazy iterator).
 */
export function* maskGenerator(mask, options = {}) {
    const positions = parseMask(mask, options);
    const totalKeyspace = maskKeyspace(positions);
    if (totalKeyspace === 0n)
        return;
    const resumeFrom = options.resumeFrom ?? 0n;
    const maxCandidates = options.maxCandidates ?? 0n;
    let generated = 0n;
    // Collect variable-position charsets for index-to-password conversion
    const variablePositions = [];
    for (let i = 0; i < positions.length; i++) {
        if (!positions[i].isFixed) {
            variablePositions.push({
                index: i,
                charset: positions[i].charset,
                length: BigInt(positions[i].charset.length),
            });
        }
    }
    // Pre-allocate character array
    const chars = new Array(positions.length);
    for (let i = 0; i < positions.length; i++) {
        if (positions[i].isFixed) {
            chars[i] = positions[i].fixedChar;
        }
    }
    for (let idx = resumeFrom; idx < totalKeyspace; idx++) {
        // Convert flat index to per-position indices (mixed-radix)
        let remaining = idx;
        for (let v = variablePositions.length - 1; v >= 0; v--) {
            const vp = variablePositions[v];
            const charIdx = Number(remaining % vp.length);
            remaining = remaining / vp.length;
            chars[vp.index] = vp.charset[charIdx];
        }
        yield chars.join('');
        generated++;
        if (maxCandidates > 0n && generated >= maxCandidates)
            return;
    }
}
/**
 * Generate candidates in batches for multi-threaded consumption.
 */
export function* maskBatchGenerator(mask, batchSize = 64, options = {}) {
    let batch = [];
    for (const candidate of maskGenerator(mask, options)) {
        batch.push(candidate);
        if (batch.length >= batchSize) {
            yield batch;
            batch = [];
        }
    }
    if (batch.length > 0)
        yield batch;
}
/**
 * Incremental mask attack: try progressively longer masks.
 * Example: ?d?d?d?d?d?d?d?d → ?d?d?d?d?d?d?d?d?d → ?d?d?d?d?d?d?d?d?d?d
 */
export function* incrementalMaskGenerator(charsetCode = '?a', minLength = 8, maxLength = 12, options = {}) {
    for (let len = minLength; len <= maxLength; len++) {
        const mask = charsetCode.repeat(len);
        yield* maskGenerator(mask, options);
    }
}
/**
 * Hybrid attack: prepend/append wordlist entries with mask-generated parts.
 * Mode 6: wordlist + mask (word + maskPattern)
 * Mode 7: mask + wordlist (maskPattern + word)
 */
export function* hybridGenerator(words, mask, mode = 'append', options = {}) {
    const positions = parseMask(mask, options);
    const totalKeyspace = maskKeyspace(positions);
    for (const word of words) {
        // For each word, iterate all mask positions
        for (const maskPart of maskGenerator(mask, options)) {
            if (mode === 'append') {
                yield word + maskPart;
            }
            else {
                yield maskPart + word;
            }
        }
    }
}
/**
 * Combinatory attack: word1 + word2 from two wordlists.
 */
export function* combinatoryGenerator(words1, words2) {
    for (const w1 of words1) {
        for (const w2 of words2) {
            yield w1 + w2;
        }
    }
}
export function getMaskInfo(mask, options = {}) {
    const positions = parseMask(mask, options);
    const keyspace = maskKeyspace(positions);
    const posDesc = positions.map((p) => {
        if (p.isFixed)
            return `'${p.fixedChar}'`;
        if (p.charset === CHARSET_LOWER)
            return '?l(26)';
        if (p.charset === CHARSET_UPPER)
            return '?u(26)';
        if (p.charset === CHARSET_DIGIT)
            return '?d(10)';
        if (p.charset === CHARSET_SPECIAL)
            return `?s(${p.charset.length})`;
        if (p.charset === CHARSET_ALL)
            return `?a(${p.charset.length})`;
        return `??(${p.charset.length})`;
    });
    return {
        mask,
        length: positions.length,
        keyspace,
        keyspaceStr: formatBigInt(keyspace),
        positions: posDesc,
    };
}
function formatBigInt(n) {
    if (n < 1000n)
        return n.toString();
    if (n < 1000000n)
        return `${(Number(n) / 1_000).toFixed(1)}K`;
    if (n < 1000000000n)
        return `${(Number(n) / 1_000_000).toFixed(1)}M`;
    if (n < 1000000000000n)
        return `${(Number(n) / 1_000_000_000).toFixed(1)}B`;
    return `${(Number(n) / 1_000_000_000_000).toFixed(1)}T`;
}
//# sourceMappingURL=mask-generator.js.map