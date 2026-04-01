/**
 * Probabilistic Context-Free Grammar (PCFG) Engine
 *
 * Learns password structures from training data and generates candidates
 * in probability-descending order.
 *
 * Grammar example:
 *   S → L4 D4 Y1    p=0.12   (4 lowercase + 4 digits + 1 symbol)
 *   S → U1 L5 D2    p=0.08   (1 upper + 5 lower + 2 digits)
 *
 * Each terminal class:
 *   L4 → "roma" p=0.3, "pass" p=0.2, "love" p=0.1, ...
 *   D4 → "2024" p=0.15, "1990" p=0.1, "1234" p=0.08, ...
 *   Y1 → "!" p=0.4, "@" p=0.15, "#" p=0.1, ...
 *
 * Reference: Weir et al. "Password Cracking Using Probabilistic CFGs" (2009)
 */
// ---------- Helpers ----------
function classifyChar(c) {
    if (/[A-Z]/.test(c))
        return 'U';
    if (/[a-z]/.test(c))
        return 'L';
    if (/[0-9]/.test(c))
        return 'D';
    return 'S';
}
function parseStructure(password) {
    if (password.length === 0)
        return [];
    const segments = [];
    let currentClass = classifyChar(password[0]);
    let currentLen = 1;
    for (let i = 1; i < password.length; i++) {
        const cls = classifyChar(password[i]);
        if (cls === currentClass) {
            currentLen++;
        }
        else {
            segments.push({ class: currentClass, length: currentLen });
            currentClass = cls;
            currentLen = 1;
        }
    }
    segments.push({ class: currentClass, length: currentLen });
    return segments;
}
function structureKey(s) {
    return s.map(seg => `${seg.class}${seg.length}`).join('');
}
function segmentKey(seg) {
    return `${seg.class}${seg.length}`;
}
function extractSegmentValue(password, structure, segIndex) {
    let offset = 0;
    for (let i = 0; i < segIndex; i++) {
        offset += structure[i].length;
    }
    return password.substring(offset, offset + structure[segIndex].length);
}
// ---------- PCFG Model ----------
export class PCFGEngine {
    /** Structure rules: key → { structure, probability, count } */
    structures = new Map();
    /** Terminal fills: "L4" → [{ value: "roma", probability, count }, ...] */
    terminals = new Map();
    /** Total training samples */
    totalSamples = 0;
    /**
     * Train the PCFG model on a set of passwords.
     * Can be called multiple times to add more training data.
     */
    train(passwords) {
        // Count structures
        const structCounts = new Map();
        const termCounts = new Map(); // "L4" → { "roma": 5, ... }
        for (const pw of passwords) {
            if (pw.length < 1)
                continue;
            this.totalSamples++;
            const structure = parseStructure(pw);
            const key = structureKey(structure);
            // Count structure
            const existing = structCounts.get(key);
            if (existing) {
                existing.count++;
            }
            else {
                structCounts.set(key, { structure, count: 1 });
            }
            // Count terminal fills
            for (let i = 0; i < structure.length; i++) {
                const segKey = segmentKey(structure[i]);
                const value = extractSegmentValue(pw, structure, i);
                if (!termCounts.has(segKey)) {
                    termCounts.set(segKey, new Map());
                }
                const fills = termCounts.get(segKey);
                fills.set(value, (fills.get(value) || 0) + 1);
            }
        }
        // Merge into model
        for (const [key, data] of structCounts) {
            const existing = this.structures.get(key);
            if (existing) {
                existing.count += data.count;
            }
            else {
                this.structures.set(key, {
                    structure: data.structure,
                    count: data.count,
                    probability: 0,
                });
            }
        }
        for (const [segKey, fills] of termCounts) {
            if (!this.terminals.has(segKey)) {
                this.terminals.set(segKey, []);
            }
            const existing = this.terminals.get(segKey);
            const existingMap = new Map(existing.map(f => [f.value, f]));
            for (const [value, count] of fills) {
                const ex = existingMap.get(value);
                if (ex) {
                    ex.count += count;
                }
                else {
                    const newFill = { value, count, probability: 0 };
                    existing.push(newFill);
                    existingMap.set(value, newFill);
                }
            }
        }
        // Recompute probabilities
        this.recomputeProbabilities();
    }
    /**
     * Train on user profile data — generates synthetic passwords from profile tokens.
     */
    trainOnProfile(profile) {
        // Old passwords are the most valuable training data
        if (profile.oldPasswords?.length) {
            this.train(profile.oldPasswords);
        }
        // Generate synthetic passwords from profile tokens to boost terminal fills
        const tokens = [
            ...(profile.names || []),
            ...(profile.words || []),
            ...(profile.partials || []),
        ];
        const dates = profile.dates || [];
        const syntheticPasswords = [];
        for (const token of tokens) {
            // Common patterns: Token123, Token!, Token2024, token123!
            syntheticPasswords.push(`${token}123`, `${token}1234`, `${token}!`, `${token}!!`, `${token}@`, `${token}123!`, `${token.toLowerCase()}123`, `${token.toLowerCase()}!`);
            for (const date of dates) {
                syntheticPasswords.push(`${token}${date}`, `${token}${date}!`);
            }
            // Combine tokens
            for (const other of tokens) {
                if (other !== token) {
                    syntheticPasswords.push(`${token}${other}`);
                    syntheticPasswords.push(`${token}${other}!`);
                }
            }
        }
        // Train on synthetic but with lower weight (mark as synthetic)
        if (syntheticPasswords.length > 0) {
            this.train(syntheticPasswords);
        }
    }
    recomputeProbabilities() {
        // Structure probabilities
        for (const rule of this.structures.values()) {
            rule.probability = rule.count / this.totalSamples;
        }
        // Terminal probabilities (per segment key)
        for (const fills of this.terminals.values()) {
            const total = fills.reduce((sum, f) => sum + f.count, 0);
            for (const fill of fills) {
                fill.probability = fill.count / total;
            }
            // Sort by probability descending
            fills.sort((a, b) => b.probability - a.probability);
        }
    }
    /**
     * Generate password candidates in probability-descending order.
     * Uses a priority queue to efficiently enumerate the cross-product
     * of structures × terminal fills.
     */
    *generate(maxCandidates = 100_000) {
        // Get structures sorted by probability
        const sortedStructures = [...this.structures.values()]
            .sort((a, b) => b.probability - a.probability);
        const queue = [];
        const seen = new Set();
        // Seed queue with top fill for each structure
        for (let si = 0; si < sortedStructures.length; si++) {
            const rule = sortedStructures[si];
            const fillIndices = new Array(rule.structure.length).fill(0);
            const prob = this.computeCandidateProbability(rule, fillIndices);
            if (prob > 0) {
                queue.push({ prob, structIdx: si, fillIndices });
            }
        }
        // Sort queue (descending)
        queue.sort((a, b) => b.prob - a.prob);
        let yielded = 0;
        while (queue.length > 0 && yielded < maxCandidates) {
            // Pop highest probability
            const best = queue.shift();
            const rule = sortedStructures[best.structIdx];
            // Build password
            const password = this.buildPassword(rule, best.fillIndices);
            const key = password;
            if (!seen.has(key)) {
                seen.add(key);
                yield {
                    password,
                    probability: best.prob,
                    structure: structureKey(rule.structure),
                };
                yielded++;
            }
            // Expand: increment each fill index by 1 (next-best fill for each segment)
            for (let seg = 0; seg < best.fillIndices.length; seg++) {
                const newIndices = [...best.fillIndices];
                newIndices[seg]++;
                // Check bounds
                const segKey = segmentKey(rule.structure[seg]);
                const fills = this.terminals.get(segKey);
                if (!fills || newIndices[seg] >= fills.length)
                    continue;
                const expandKey = `${best.structIdx}:${newIndices.join(',')}`;
                if (seen.has(expandKey))
                    continue;
                seen.add(expandKey);
                const prob = this.computeCandidateProbability(rule, newIndices);
                if (prob > 0) {
                    // Insert sorted
                    const item = { prob, structIdx: best.structIdx, fillIndices: newIndices };
                    const insertIdx = queue.findIndex(q => q.prob < prob);
                    if (insertIdx === -1) {
                        queue.push(item);
                    }
                    else {
                        queue.splice(insertIdx, 0, item);
                    }
                }
            }
        }
    }
    computeCandidateProbability(rule, fillIndices) {
        let prob = rule.probability;
        for (let i = 0; i < rule.structure.length; i++) {
            const segKey = segmentKey(rule.structure[i]);
            const fills = this.terminals.get(segKey);
            if (!fills || fillIndices[i] >= fills.length)
                return 0;
            prob *= fills[fillIndices[i]].probability;
        }
        return prob;
    }
    buildPassword(rule, fillIndices) {
        let password = '';
        for (let i = 0; i < rule.structure.length; i++) {
            const segKey = segmentKey(rule.structure[i]);
            const fills = this.terminals.get(segKey);
            password += fills[fillIndices[i]].value;
        }
        return password;
    }
    /** Get statistics about the trained model */
    getStats() {
        const topStructures = [...this.structures.entries()]
            .sort((a, b) => b[1].probability - a[1].probability)
            .slice(0, 10)
            .map(([key, rule]) => ({ key, probability: rule.probability }));
        return {
            totalSamples: this.totalSamples,
            structureCount: this.structures.size,
            topStructures,
            terminalGroups: this.terminals.size,
        };
    }
    /** Serialize model to JSON */
    toJSON() {
        return JSON.stringify({
            totalSamples: this.totalSamples,
            structures: [...this.structures.entries()],
            terminals: [...this.terminals.entries()],
        });
    }
    /** Load model from JSON */
    static fromJSON(json) {
        const data = JSON.parse(json);
        const engine = new PCFGEngine();
        engine.totalSamples = data.totalSamples;
        engine.structures = new Map(data.structures);
        engine.terminals = new Map(data.terminals);
        return engine;
    }
}
//# sourceMappingURL=pcfg-engine.js.map