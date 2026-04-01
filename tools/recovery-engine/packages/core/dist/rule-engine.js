/**
 * Hashcat-Compatible Rule Engine
 *
 * Implements hashcat rule functions for password mutation.
 * Each rule transforms an input word into one or more output candidates.
 *
 * Supported rule functions (hashcat-compatible):
 *
 * Case:
 *   l   lowercase           "PassWord" → "password"
 *   u   uppercase           "PassWord" → "PASSWORD"
 *   c   capitalize          "password" → "Password"
 *   C   uncapitalize        "Password" → "pASSWORD" (invert capitalize)
 *   t   toggle case         "password" → "PASSWORD" (toggle all)
 *   TN  toggle pos N        "password" → "pAssword" (toggle char at N)
 *
 * Length:
 *   $X  append char X       "pass" → "pass1"
 *   ^X  prepend char X      "pass" → "1pass"
 *   [   delete first        "password" → "assword"
 *   ]   delete last         "password" → "passwor"
 *   DN  delete at pos N     "password" → "pssword" (D1)
 *
 * Insert/Replace:
 *   iNX insert X at pos N   "password" → "p1assword" (i11)
 *   oNX overwrite pos N     "password" → "p1ssword"  (o11)
 *
 * Duplication:
 *   d   duplicate word      "pass" → "passpass"
 *   p   duplicate word N times
 *   f   reverse word        "pass" → "ssap"
 *   r   reverse word (alias)
 *   {   rotate left         "password" → "asswordp"
 *   }   rotate right        "password" → "dpasswor"
 *
 * Substitution:
 *   sXY replace X with Y    "password" → "p@ssword" (sa@)
 *
 * L33t/Special:
 *   @X  purge char X         "password" → "pssword" (@a)
 *   q   duplicate all chars  "pass" → "ppaassss"
 *
 * Memory:
 *   k   swap first two      "password" → "apssword"
 *   K   swap last two       "password" → "passwrod"
 *
 * Rejection (skip word if condition not met):
 *   >N  reject if len > N
 *   <N  reject if len < N
 *   !X  reject if contains X
 *   /X  reject if not contains X
 */
/**
 * Parse a single rule string into a chain of rule functions.
 * Returns null producers for reject rules (word should be skipped).
 */
export function parseRule(rule) {
    const fns = [];
    let i = 0;
    while (i < rule.length) {
        const ch = rule[i];
        switch (ch) {
            // ── Case rules ──
            case ':': // Noop (pass-through)
                i++;
                break;
            case 'l': // Lowercase
                fns.push((w) => w.toLowerCase());
                i++;
                break;
            case 'u': // Uppercase
                fns.push((w) => w.toUpperCase());
                i++;
                break;
            case 'c': // Capitalize first, lower rest
                fns.push((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
                i++;
                break;
            case 'C': // Uncapitalize: first lower, rest upper
                fns.push((w) => w.charAt(0).toLowerCase() + w.slice(1).toUpperCase());
                i++;
                break;
            case 't': // Toggle all case
                fns.push((w) => {
                    let out = '';
                    for (const c of w) {
                        out += c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase();
                    }
                    return out;
                });
                i++;
                break;
            case 'T': { // Toggle at position N
                const n = parseInt(rule[i + 1], 36); // 0-9 a-z (0-35)
                fns.push((w) => {
                    if (n >= w.length)
                        return w;
                    const c = w[n];
                    const toggled = c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase();
                    return w.substring(0, n) + toggled + w.substring(n + 1);
                });
                i += 2;
                break;
            }
            // ── Length rules ──
            case '$': { // Append char
                const x = rule[i + 1];
                fns.push((w) => w + x);
                i += 2;
                break;
            }
            case '^': { // Prepend char
                const x = rule[i + 1];
                fns.push((w) => x + w);
                i += 2;
                break;
            }
            case '[': // Delete first char
                fns.push((w) => w.length > 0 ? w.slice(1) : w);
                i++;
                break;
            case ']': // Delete last char
                fns.push((w) => w.length > 0 ? w.slice(0, -1) : w);
                i++;
                break;
            case 'D': { // Delete at position N
                const n = parseInt(rule[i + 1], 36);
                fns.push((w) => {
                    if (n >= w.length)
                        return w;
                    return w.substring(0, n) + w.substring(n + 1);
                });
                i += 2;
                break;
            }
            // ── Insert / Replace ──
            case 'i': { // Insert X at position N
                const n = parseInt(rule[i + 1], 36);
                const x = rule[i + 2];
                fns.push((w) => {
                    const pos = Math.min(n, w.length);
                    return w.substring(0, pos) + x + w.substring(pos);
                });
                i += 3;
                break;
            }
            case 'o': { // Overwrite at position N with X
                const n = parseInt(rule[i + 1], 36);
                const x = rule[i + 2];
                fns.push((w) => {
                    if (n >= w.length)
                        return w;
                    return w.substring(0, n) + x + w.substring(n + 1);
                });
                i += 3;
                break;
            }
            // ── Duplication / Transformation ──
            case 'd': // Duplicate
                fns.push((w) => w + w);
                i++;
                break;
            case 'f': // Reverse
            case 'r':
                fns.push((w) => w.split('').reverse().join(''));
                i++;
                break;
            case '{': // Rotate left
                fns.push((w) => w.length > 1 ? w.slice(1) + w[0] : w);
                i++;
                break;
            case '}': // Rotate right
                fns.push((w) => w.length > 1 ? w[w.length - 1] + w.slice(0, -1) : w);
                i++;
                break;
            case 'q': // Duplicate every char
                fns.push((w) => w.split('').map((c) => c + c).join(''));
                i++;
                break;
            // ── Substitution ──
            case 's': { // Replace X with Y
                const x = rule[i + 1];
                const y = rule[i + 2];
                fns.push((w) => w.split(x).join(y));
                i += 3;
                break;
            }
            case '@': { // Purge char X (remove all occurrences)
                const x = rule[i + 1];
                fns.push((w) => w.split(x).join(''));
                i += 2;
                break;
            }
            // ── Swap ──
            case 'k': // Swap first two
                fns.push((w) => w.length >= 2 ? w[1] + w[0] + w.slice(2) : w);
                i++;
                break;
            case 'K': // Swap last two
                fns.push((w) => w.length >= 2 ? w.slice(0, -2) + w[w.length - 1] + w[w.length - 2] : w);
                i++;
                break;
            // ── Reject rules (return null to skip) ──
            case '>': { // Reject if length > N
                const n = parseInt(rule[i + 1], 36);
                fns.push((w) => w.length > n ? null : w);
                i += 2;
                break;
            }
            case '<': { // Reject if length < N
                const n = parseInt(rule[i + 1], 36);
                fns.push((w) => w.length < n ? null : w);
                i += 2;
                break;
            }
            case '!': { // Reject if contains X
                const x = rule[i + 1];
                fns.push((w) => w.includes(x) ? null : w);
                i += 2;
                break;
            }
            case '/': { // Reject if NOT contains X
                const x = rule[i + 1];
                fns.push((w) => w.includes(x) ? w : null);
                i += 2;
                break;
            }
            // ── Unknown: skip ──
            default:
                i++;
                break;
        }
    }
    return fns;
}
/**
 * Apply a chain of rule functions to a word.
 * Returns null if any reject rule triggers.
 */
export function applyRule(word, ruleFns) {
    let result = word;
    for (const fn of ruleFns) {
        result = fn(result);
        if (result === null)
            return null;
    }
    return result;
}
/**
 * Apply a rule string (e.g. "c$1$2$3") to a word.
 */
export function applyRuleStr(word, rule) {
    return applyRule(word, parseRule(rule));
}
// ── Pre-defined rule sets ──
/** Best64 — the most effective 64 rules from hashcat-utils */
export const RULES_BEST64 = [
    ':', 'l', 'u', 'c', 'C', 't',
    'r', 'd', 'f',
    '$1', '$2', '$3', '$!', '$@', '$#',
    '^1', '^!',
    '$1$2$3', '$!$!',
    'c$1', 'c$1$2', 'c$1$2$3',
    'c$!', 'c$@', 'c$123',
    'l$1', 'l$12', 'l$123',
    'u$1',
    'sa@', 'se3', 'si1', 'so0', 'ss$', 'st7',
    'sa@se3', 'sa@si1so0', 'sa@se3si1so0',
    'c$0$1', 'c$6$9', 'c$!$!',
    '[', ']', '[[', ']]',
    '{', '}',
    'k', 'K',
    'T0', 'T1', 'T2', 'T3',
    '$1$!', '$!$1',
    'q',
    'sa@$1', 'se3$1',
    'c$2$0$2$4', 'c$2$0$2$5', 'c$2$0$2$6',
    '^!c', '^1c',
    'D0', 'D1',
    'o0M', 'o0P',
    'i0!', 'i01',
];
/** L33t speak rules */
export const RULES_LEET = [
    'sa@', 'se3', 'si1', 'so0', 'ss$', 'st7', 'sl1', 'sb8', 'sg9',
    'sa@se3', 'sa@si1', 'sa@so0',
    'sa@se3si1', 'sa@se3si1so0',
    'sa@se3si1so0ss$', 'sa@se3si1so0ss$st7',
];
/** Toggle case rules */
export const RULES_TOGGLES = [
    'T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7',
    'T0T1', 'T0T2', 'T1T2', 'T1T3',
];
/** Append common numbers/years */
export const RULES_APPEND_NUMS = [
    '$0', '$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8', '$9',
    '$0$0', '$0$1', '$1$0', '$1$1', '$1$2', '$2$1', '$2$2', '$6$9', '$9$9',
    '$0$0$0', '$0$0$7', '$1$2$3', '$3$2$1', '$6$6$6', '$7$7$7',
    '$1$2$3$4', '$2$0$2$0', '$2$0$2$1', '$2$0$2$2', '$2$0$2$3',
    '$2$0$2$4', '$2$0$2$5', '$2$0$2$6',
    '$1$9$9$0', '$1$9$9$1', '$1$9$9$2', '$1$9$9$3', '$1$9$9$4',
    '$1$9$9$5', '$1$9$9$6', '$1$9$9$7', '$1$9$9$8', '$1$9$9$9',
];
/**
 * Apply a rule set to a wordlist and yield all transformed passwords.
 * Deduplicates and filters by min length.
 */
export function* applyRules(words, rules, minLength = 8) {
    const seen = new Set();
    const parsedRules = rules.map(parseRule);
    for (const word of words) {
        for (const ruleFns of parsedRules) {
            const result = applyRule(word, ruleFns);
            if (result !== null && result.length >= minLength && !seen.has(result)) {
                seen.add(result);
                yield result;
            }
        }
    }
}
/**
 * Apply rules in batches (for worker distribution).
 */
export function* applyRulesBatch(words, rules, batchSize = 64, minLength = 8) {
    let batch = [];
    for (const candidate of applyRules(words, rules, minLength)) {
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
 * Load rules from a hashcat-format rule file (one rule per line, # comments).
 */
export function loadRulesFile(filePath) {
    const fs = require('node:fs');
    const content = fs.readFileSync(filePath, 'utf-8');
    return content
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'));
}
/**
 * Estimate how many candidates a rule set will generate from N words.
 */
export function estimateRuleOutput(wordCount, rules) {
    // Rough: ~70% of rules produce unique output on average
    return Math.floor(wordCount * rules.length * 0.7);
}
//# sourceMappingURL=rule-engine.js.map