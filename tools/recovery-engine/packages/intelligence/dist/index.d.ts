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
export { MarkovModel, type MarkovOptions } from './markov-model.js';
export { OSINTCollector, type OSINTConfig, type OSINTResult, type BreachInfo } from './osint-collector.js';
export { PasswordScorer, type ScoredCandidate, type ScorerOptions } from './password-scorer.js';
export { SmartGenerator, type SmartGeneratorOptions, type SmartGeneratorStats, } from './smart-generator.js';
//# sourceMappingURL=index.d.ts.map