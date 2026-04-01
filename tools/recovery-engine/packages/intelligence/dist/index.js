/**
 * @metamask-recovery/intelligence
 *
 * V3 Password Intelligence Engine — AI-powered password candidate generation.
 *
 * Modules:
 * - PCFGEngine: Probabilistic Context-Free Grammar for structure learning
 * - MarkovModel: Character-level transition probabilities
 * - OSINTCollector: Automatic profile enrichment from public sources
 * - PasswordScorer: Multi-signal probability scoring and ranking
 * - SmartGenerator: Orchestrates all modules into a priority-ordered candidate stream
 */
export { PCFGEngine } from './pcfg-engine.js';
export { MarkovModel } from './markov-model.js';
export { OSINTCollector } from './osint-collector.js';
export { PasswordScorer } from './password-scorer.js';
export { SmartGenerator, } from './smart-generator.js';
//# sourceMappingURL=index.js.map