/**
 * @metamask-recovery/core
 * Core library for MetaMask vault password recovery.
 *
 * Provides vault extraction, decryption, password candidate generation,
 * worker pool management, and GPU acceleration utilities.
 */
export { VaultExtractor } from './vault-extractor.js';
export { VaultDecryptor, } from './decryptor.js';
export { PasswordGenerator, } from './password-generator.js';
export { WorkerPool } from './worker-pool.js';
export { GpuAccelerator } from './gpu-accelerator.js';
export { CrackOrchestrator } from './orchestrator.js';
export { VectorizedCrackEngine } from './vectorized-engine.js';
export { UniversalCrackEngine } from './universal-engine.js';
// ── Attack Modes ──
export { maskGenerator, maskBatchGenerator, incrementalMaskGenerator, hybridGenerator, combinatoryGenerator, parseMask, maskKeyspace, getMaskInfo, } from './mask-generator.js';
export { parseRule, applyRule, applyRuleStr, applyRules, applyRulesBatch, loadRulesFile, estimateRuleOutput, RULES_BEST64, RULES_LEET, RULES_TOGGLES, RULES_APPEND_NUMS, } from './rule-engine.js';
// ── Session Management ──
export { CheckpointManager, } from './checkpoint.js';
// ── ETA / Progress ──
export { ETAEstimator, formatDuration, formatSpeed, formatNumber, } from './eta-estimator.js';
// ── Wordlist Management ──
export { WordlistManager, } from './wordlist-manager.js';
//# sourceMappingURL=index.js.map