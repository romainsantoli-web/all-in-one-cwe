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
export type RuleFunction = (word: string) => string | null;
/**
 * Parse a single rule string into a chain of rule functions.
 * Returns null producers for reject rules (word should be skipped).
 */
export declare function parseRule(rule: string): RuleFunction[];
/**
 * Apply a chain of rule functions to a word.
 * Returns null if any reject rule triggers.
 */
export declare function applyRule(word: string, ruleFns: RuleFunction[]): string | null;
/**
 * Apply a rule string (e.g. "c$1$2$3") to a word.
 */
export declare function applyRuleStr(word: string, rule: string): string | null;
/** Best64 — the most effective 64 rules from hashcat-utils */
export declare const RULES_BEST64: string[];
/** L33t speak rules */
export declare const RULES_LEET: string[];
/** Toggle case rules */
export declare const RULES_TOGGLES: string[];
/** Append common numbers/years */
export declare const RULES_APPEND_NUMS: string[];
/**
 * Apply a rule set to a wordlist and yield all transformed passwords.
 * Deduplicates and filters by min length.
 */
export declare function applyRules(words: Iterable<string>, rules: string[], minLength?: number): Generator<string>;
/**
 * Apply rules in batches (for worker distribution).
 */
export declare function applyRulesBatch(words: Iterable<string>, rules: string[], batchSize?: number, minLength?: number): Generator<string[]>;
/**
 * Load rules from a hashcat-format rule file (one rule per line, # comments).
 */
export declare function loadRulesFile(filePath: string): string[];
/**
 * Estimate how many candidates a rule set will generate from N words.
 */
export declare function estimateRuleOutput(wordCount: number, rules: string[]): number;
//# sourceMappingURL=rule-engine.d.ts.map