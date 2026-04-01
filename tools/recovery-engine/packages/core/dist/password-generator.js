/**
 * Password Generator — Produces password candidates in 3 cascading levels:
 *
 * Level 1: Profile-based (user's personal info → targeted combinations)
 * Level 2: Dictionary + smart mutations
 * Level 3: Brute-force (exhaustive, charset-based)
 *
 * All generators are lazy iterables to keep memory constant.
 */
// ---------- Common password suffixes / prefixes ----------
const COMMON_SUFFIXES = [
    '', '1', '2', '3', '12', '123', '1234', '12345', '123456',
    '!', '!!', '@', '#', '$', '!@#', '!@#$',
    '01', '07', '10', '11', '13', '21', '22', '69', '77', '88', '99',
    '00', '000', '007',
    '2020', '2021', '2022', '2023', '2024', '2025', '2026',
];
const COMMON_PREFIXES = ['', 'the', 'my', 'i', 'Mr', 'mr'];
// ---------- Leet speak substitutions ----------
const LEET_MAP = {
    a: ['@', '4'],
    e: ['3'],
    i: ['1', '!'],
    o: ['0'],
    s: ['$', '5'],
    t: ['7'],
    l: ['1'],
    b: ['8'],
    g: ['9'],
};
// ---------- Built-in common passwords (subset) ----------
const COMMON_PASSWORDS = [
    'password', 'metamask', 'ethereum', 'bitcoin', 'crypto',
    'blockchain', 'wallet', 'defi', 'hodl', 'moonlambo',
    'letmein', 'welcome', 'admin', 'login', 'master',
    'monkey', 'dragon', 'shadow', 'sunshine', 'trustno1',
    'iloveyou', 'princess', 'football', 'charlie', 'freedom',
    'whatever', 'qwerty', 'abc123', 'passw0rd', 'p@ssword',
    'p@ssw0rd', '12345678', '123456789', '1234567890',
    'azerty', 'azertyuiop', 'qwertyuiop', 'zxcvbnm',
    'changeme', 'secret', 'access', 'default', 'secure',
    'test1234', 'Pass1234', 'Password1', 'Password123',
    'Metamask1', 'MetaMask1', 'MetaMask123', 'Ethereum1',
    'Bitcoin1', 'Crypto123', 'MyWallet1', 'mywallet1',
];
// ---------- Mutation functions ----------
function* applyCapitalizations(word) {
    if (word.length === 0)
        return;
    yield word; // lowercase
    yield word.toUpperCase(); // UPPERCASE
    yield word.charAt(0).toUpperCase() + word.slice(1); // Capitalized
    if (word.length > 1) {
        yield word.charAt(0) + word.charAt(1).toUpperCase() + word.slice(2); // cApitalized
    }
}
function* applyLeetSpeak(word, maxDepth = 2) {
    yield word;
    // Find positions that can be leet-ified
    const positions = [];
    for (let i = 0; i < word.length; i++) {
        const lower = word[i].toLowerCase();
        if (LEET_MAP[lower]) {
            positions.push({ index: i, replacements: LEET_MAP[lower] });
        }
    }
    // Generate combinations up to maxDepth substitutions
    const depth = Math.min(maxDepth, positions.length);
    for (let d = 1; d <= depth; d++) {
        yield* leetCombinations(word, positions, 0, d);
    }
}
function* leetCombinations(word, positions, startIdx, remaining) {
    if (remaining === 0) {
        yield word;
        return;
    }
    for (let i = startIdx; i <= positions.length - remaining; i++) {
        const pos = positions[i];
        for (const replacement of pos.replacements) {
            const mutated = word.substring(0, pos.index) + replacement + word.substring(pos.index + 1);
            yield* leetCombinations(mutated, positions, i + 1, remaining - 1);
        }
    }
}
function* addSuffixes(word) {
    for (const suffix of COMMON_SUFFIXES) {
        const candidate = word + suffix;
        if (candidate.length >= 8) {
            yield candidate;
        }
    }
}
function* addPrefixes(word) {
    for (const prefix of COMMON_PREFIXES) {
        yield prefix + word;
    }
}
function* mutateWord(word) {
    const seen = new Set();
    for (const capitalized of applyCapitalizations(word)) {
        for (const leeted of applyLeetSpeak(capitalized)) {
            for (const suffixed of addSuffixes(leeted)) {
                if (suffixed.length >= 8 && !seen.has(suffixed)) {
                    seen.add(suffixed);
                    yield suffixed;
                }
            }
        }
    }
    // Reversed
    const reversed = word.split('').reverse().join('');
    if (reversed !== word) {
        for (const suffixed of addSuffixes(reversed)) {
            if (suffixed.length >= 8 && !seen.has(suffixed)) {
                seen.add(suffixed);
                yield suffixed;
            }
        }
    }
    // Doubled
    const doubled = word + word;
    if (doubled.length >= 8 && !seen.has(doubled)) {
        seen.add(doubled);
        yield doubled;
    }
}
// ---------- Level 1: Profile-based generator ----------
function* generateFromProfile(profile) {
    const seen = new Set();
    function* yieldUnique(candidate) {
        if (candidate.length >= 8 && !seen.has(candidate)) {
            seen.add(candidate);
            yield candidate;
        }
    }
    // 1. Try old passwords as-is first (highest probability)
    if (profile.oldPasswords) {
        for (const old of profile.oldPasswords) {
            yield* yieldUnique(old);
            // And mutations of old passwords
            for (const mutated of mutateWord(old)) {
                yield* yieldUnique(mutated);
            }
        }
    }
    // 2. Try partial passwords with completions
    if (profile.partials) {
        for (const partial of profile.partials) {
            yield* yieldUnique(partial);
            for (const suffix of COMMON_SUFFIXES) {
                yield* yieldUnique(partial + suffix);
            }
            for (const mutated of mutateWord(partial)) {
                yield* yieldUnique(mutated);
            }
        }
    }
    // Collect all tokens
    const tokens = [
        ...(profile.names || []),
        ...(profile.words || []),
        ...(profile.dates || []),
    ];
    // 3. Single tokens with mutations
    for (const token of tokens) {
        for (const mutated of mutateWord(token.toLowerCase())) {
            yield* yieldUnique(mutated);
        }
        for (const mutated of mutateWord(token)) {
            yield* yieldUnique(mutated);
        }
    }
    // 4. Date transformations
    if (profile.dates) {
        for (const date of profile.dates) {
            const digits = date.replace(/\D/g, '');
            // Try various date formats as suffixes/passwords
            const dateVariants = new Set([
                digits,
                digits.slice(-4), // year
                digits.slice(-2), // last 2 digits
                digits.slice(0, 4), // first 4 digits
            ]);
            for (const name of profile.names || []) {
                for (const dv of dateVariants) {
                    yield* yieldUnique(name.toLowerCase() + dv);
                    yield* yieldUnique(name.charAt(0).toUpperCase() + name.slice(1).toLowerCase() + dv);
                    yield* yieldUnique(name.toUpperCase() + dv);
                    yield* yieldUnique(dv + name.toLowerCase());
                    // With symbols
                    yield* yieldUnique(name.toLowerCase() + dv + '!');
                    yield* yieldUnique(name.charAt(0).toUpperCase() + name.slice(1).toLowerCase() + dv + '!');
                    yield* yieldUnique(name.toLowerCase() + '@' + dv);
                    yield* yieldUnique(name.charAt(0).toUpperCase() + name.slice(1).toLowerCase() + '#' + dv);
                }
            }
        }
    }
    // 5. Two-token combinations
    for (let i = 0; i < tokens.length; i++) {
        for (let j = 0; j < tokens.length; j++) {
            if (i === j)
                continue;
            const a = tokens[i].toLowerCase();
            const b = tokens[j].toLowerCase();
            yield* yieldUnique(a + b);
            yield* yieldUnique(a + '_' + b);
            yield* yieldUnique(a + '.' + b);
            yield* yieldUnique(a.charAt(0).toUpperCase() + a.slice(1) + b.charAt(0).toUpperCase() + b.slice(1));
            for (const suffix of COMMON_SUFFIXES.slice(0, 15)) {
                yield* yieldUnique(a + b + suffix);
                yield* yieldUnique(a.charAt(0).toUpperCase() + a.slice(1) + b.charAt(0).toUpperCase() + b.slice(1) + suffix);
            }
        }
    }
}
// ---------- Level 2: Dictionary + mutations ----------
function* generateFromDictionary(profile) {
    const seen = new Set();
    function* yieldUnique(candidate) {
        if (candidate.length >= 8 && !seen.has(candidate)) {
            seen.add(candidate);
            yield candidate;
        }
    }
    // Start with common passwords as-is
    for (const pw of COMMON_PASSWORDS) {
        yield* yieldUnique(pw);
    }
    // Then mutations of common passwords
    for (const pw of COMMON_PASSWORDS) {
        for (const mutated of mutateWord(pw)) {
            yield* yieldUnique(mutated);
        }
    }
    // Crypto-specific combinations
    const cryptoWords = [
        'metamask', 'ethereum', 'bitcoin', 'crypto', 'wallet', 'defi',
        'hodl', 'moon', 'lambo', 'nft', 'token', 'chain', 'block',
        'web3', 'satoshi', 'nakamoto', 'vitalik', 'buterin', 'ether',
        'sol', 'solana', 'bnb', 'binance', 'polygon', 'matic',
        'avalanche', 'avax', 'cardano', 'ada', 'polkadot', 'dot',
    ];
    for (const word of cryptoWords) {
        for (const mutated of mutateWord(word)) {
            yield* yieldUnique(mutated);
        }
    }
    // If profile has custom words, add combinations with dict words
    if (profile?.words) {
        for (const userWord of profile.words) {
            for (const dictWord of cryptoWords) {
                yield* yieldUnique(userWord.toLowerCase() + dictWord);
                yield* yieldUnique(dictWord + userWord.toLowerCase());
                yield* yieldUnique(userWord.charAt(0).toUpperCase() +
                    userWord.slice(1).toLowerCase() +
                    dictWord.charAt(0).toUpperCase() +
                    dictWord.slice(1));
            }
        }
    }
}
// ---------- Level 3: Brute-force ----------
const CHARSETS = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    alpha: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    full: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?',
};
function* bruteforceGenerator(charset, minLength, maxLength, resumeFrom = 0n) {
    const base = BigInt(charset.length);
    let globalIndex = 0n;
    for (let length = minLength; length <= maxLength; length++) {
        const totalForLength = base ** BigInt(length);
        for (let i = 0n; i < totalForLength; i++) {
            if (globalIndex >= resumeFrom) {
                // Convert index to string
                let remaining = i;
                const chars = new Array(length);
                for (let pos = length - 1; pos >= 0; pos--) {
                    chars[pos] = charset[Number(remaining % base)];
                    remaining = remaining / base;
                }
                yield chars.join('');
            }
            globalIndex++;
        }
    }
}
// ---------- Public API ----------
export class PasswordGenerator {
    options;
    constructor(options) {
        this.options = {
            strategy: options.strategy,
            profile: options.profile || {},
            bruteforceCharset: options.bruteforceCharset || CHARSETS.full,
            minLength: options.minLength ?? 8,
            maxLength: options.maxLength ?? 16,
            resumeFrom: options.resumeFrom ?? 0n,
        };
    }
    /**
     * Generate password candidates as a lazy iterable.
     * Cascades through strategies: profile → dictionary → brute-force.
     */
    *generate() {
        const { strategy, profile } = this.options;
        if (strategy === 'profile' || strategy === 'all') {
            if (profile && Object.keys(profile).some((k) => {
                const val = profile[k];
                return Array.isArray(val) ? val.length > 0 : !!val;
            })) {
                yield* generateFromProfile(profile);
            }
        }
        if (strategy === 'dictionary' || strategy === 'all') {
            yield* generateFromDictionary(profile);
        }
        if (strategy === 'bruteforce' || strategy === 'all') {
            yield* bruteforceGenerator(this.options.bruteforceCharset, this.options.minLength, this.options.maxLength, this.options.resumeFrom);
        }
    }
    /**
     * Get batches of N candidates at a time.
     */
    *batches(batchSize = 50) {
        let batch = [];
        for (const candidate of this.generate()) {
            batch.push(candidate);
            if (batch.length >= batchSize) {
                yield batch;
                batch = [];
            }
        }
        if (batch.length > 0) {
            yield batch;
        }
    }
    /**
     * Estimate the total number of candidates for the current configuration.
     */
    estimateTotal() {
        const profileCount = this.options.profile
            ? estimateProfileCandidates(this.options.profile)
            : 0;
        const dictCount = COMMON_PASSWORDS.length * 100; // rough estimate with mutations
        const base = BigInt(this.options.bruteforceCharset.length);
        let bruteTotal = 0n;
        for (let len = this.options.minLength; len <= this.options.maxLength; len++) {
            bruteTotal += base ** BigInt(len);
        }
        return {
            profile: profileCount,
            dictionary: dictCount,
            bruteforce: bruteTotal.toString(),
            total: this.options.strategy === 'all'
                ? `~${profileCount + dictCount} smart + ${bruteTotal} brute-force`
                : this.options.strategy === 'bruteforce'
                    ? bruteTotal.toString()
                    : `~${profileCount + dictCount}`,
        };
    }
    /** Available charset presets */
    static CHARSETS = CHARSETS;
}
function estimateProfileCandidates(profile) {
    const tokenCount = (profile.names?.length || 0) +
        (profile.words?.length || 0) +
        (profile.dates?.length || 0);
    const oldPwCount = profile.oldPasswords?.length || 0;
    const partialCount = profile.partials?.length || 0;
    // Rough estimate: each token generates ~50 mutations, combinations are O(n^2)
    return (oldPwCount * 50 +
        partialCount * 50 +
        tokenCount * 50 +
        tokenCount * tokenCount * 15 +
        (profile.dates?.length || 0) * (profile.names?.length || 0) * 20);
}
//# sourceMappingURL=password-generator.js.map