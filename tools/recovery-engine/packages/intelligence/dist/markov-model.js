/**
 * Markov Chain Password Model
 *
 * Learns character-level transition probabilities from training passwords.
 * Used to score how "natural" a password looks and to generate candidates
 * that follow realistic character patterns.
 *
 * Example: After seeing "ro", the probability of "m" is high (romain)
 *          while the probability of "z" is low.
 *
 * Uses N-gram chains (default: 3-gram) for better context.
 */
// Special tokens
const START = '\x02'; // Start of password
const END = '\x03'; // End of password
export class MarkovModel {
    order;
    smoothing;
    /** Transition counts: context → { nextChar → count } */
    transitions = new Map();
    /** All observed characters */
    alphabet = new Set();
    totalSamples = 0;
    constructor(options = {}) {
        this.order = options.order ?? 3;
        this.smoothing = options.smoothing ?? 0.001;
    }
    /**
     * Train on a list of passwords.
     */
    train(passwords) {
        for (const pw of passwords) {
            if (pw.length < 1)
                continue;
            this.totalSamples++;
            // Add chars to alphabet
            for (const c of pw) {
                this.alphabet.add(c);
            }
            // Pad with START/END tokens
            const padded = START.repeat(this.order) + pw + END;
            // Count N-gram transitions
            for (let i = this.order; i < padded.length; i++) {
                const context = padded.substring(i - this.order, i);
                const nextChar = padded[i];
                if (!this.transitions.has(context)) {
                    this.transitions.set(context, new Map());
                }
                const counts = this.transitions.get(context);
                counts.set(nextChar, (counts.get(nextChar) || 0) + 1);
            }
        }
    }
    /**
     * Score a password: log-probability under the Markov model.
     * Higher score = more likely password pattern.
     * Returns a value between 0 and 1 (normalized).
     */
    score(password) {
        if (password.length === 0)
            return 0;
        const padded = START.repeat(this.order) + password + END;
        let logProb = 0;
        for (let i = this.order; i < padded.length; i++) {
            const context = padded.substring(i - this.order, i);
            const nextChar = padded[i];
            const prob = this.getTransitionProbability(context, nextChar);
            logProb += Math.log(prob);
        }
        // Normalize by length to make scores comparable across password lengths
        const normalizedLogProb = logProb / (password.length + 1);
        // Convert to 0-1 range (sigmoid-like normalization)
        // More negative = less likely
        return 1 / (1 + Math.exp(-normalizedLogProb - 2));
    }
    /**
     * Get the transition probability P(nextChar | context).
     * Uses Laplace smoothing for unseen transitions.
     */
    getTransitionProbability(context, nextChar) {
        const counts = this.transitions.get(context);
        const alphabetSize = this.alphabet.size + 1; // +1 for END token
        if (!counts) {
            // Unseen context: uniform distribution
            return 1 / alphabetSize;
        }
        const total = [...counts.values()].reduce((s, c) => s + c, 0);
        const count = counts.get(nextChar) || 0;
        // Laplace smoothing
        return (count + this.smoothing) / (total + this.smoothing * alphabetSize);
    }
    /**
     * Generate a password by sampling from the Markov chain.
     * Optionally use temperature to control randomness.
     */
    generate(maxLength = 20, temperature = 1.0) {
        let context = START.repeat(this.order);
        let password = '';
        for (let i = 0; i < maxLength; i++) {
            const nextChar = this.sampleNext(context, temperature);
            if (nextChar === END)
                break;
            password += nextChar;
            context = context.substring(1) + nextChar;
        }
        return password;
    }
    /**
     * Generate multiple candidate passwords, sorted by probability.
     */
    *generateCandidates(count = 1000, temperature = 0.8) {
        const seen = new Set();
        let attempts = 0;
        const maxAttempts = count * 10;
        while (seen.size < count && attempts < maxAttempts) {
            attempts++;
            const pw = this.generate(20, temperature);
            if (pw.length >= 8 && !seen.has(pw)) {
                seen.add(pw);
                yield { password: pw, score: this.score(pw) };
            }
        }
    }
    sampleNext(context, temperature) {
        const counts = this.transitions.get(context);
        if (!counts || counts.size === 0) {
            // Random from alphabet + END
            const chars = [...this.alphabet, END];
            return chars[Math.floor(Math.random() * chars.length)];
        }
        // Build probability distribution with temperature
        const entries = [...counts.entries()];
        const total = entries.reduce((s, [, c]) => s + c, 0);
        // Apply temperature
        const probs = entries.map(([char, count]) => ({
            char,
            prob: Math.pow(count / total, 1 / temperature),
        }));
        const probSum = probs.reduce((s, p) => s + p.prob, 0);
        // Sample
        let r = Math.random() * probSum;
        for (const { char, prob } of probs) {
            r -= prob;
            if (r <= 0)
                return char;
        }
        return entries[entries.length - 1][0];
    }
    /** Get model statistics */
    getStats() {
        return {
            totalSamples: this.totalSamples,
            alphabetSize: this.alphabet.size,
            contextCount: this.transitions.size,
            order: this.order,
        };
    }
    /** Serialize model */
    toJSON() {
        return JSON.stringify({
            order: this.order,
            smoothing: this.smoothing,
            totalSamples: this.totalSamples,
            alphabet: [...this.alphabet],
            transitions: [...this.transitions.entries()].map(([ctx, counts]) => [
                ctx, [...counts.entries()],
            ]),
        });
    }
    /** Deserialize model */
    static fromJSON(json) {
        const data = JSON.parse(json);
        const model = new MarkovModel({ order: data.order, smoothing: data.smoothing });
        model.totalSamples = data.totalSamples;
        model.alphabet = new Set(data.alphabet);
        for (const [ctx, counts] of data.transitions) {
            model.transitions.set(ctx, new Map(counts));
        }
        return model;
    }
}
//# sourceMappingURL=markov-model.js.map