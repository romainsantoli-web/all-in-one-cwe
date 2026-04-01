/**
 * @metamask-recovery/core
 * Core library for MetaMask vault password recovery.
 *
 * Provides vault extraction, decryption, password candidate generation,
 * worker pool management, and GPU acceleration utilities.
 */
export { VaultExtractor, type VaultData, type RawVault } from './vault-extractor.js';
export { VaultDecryptor, type DecryptionResult, type DecryptedVault, } from './decryptor.js';
export { PasswordGenerator, type UserProfile, type GeneratorOptions, type Strategy, } from './password-generator.js';
export { WorkerPool, type WorkerPoolOptions, type CrackResult } from './worker-pool.js';
export { GpuAccelerator, type GpuOptions } from './gpu-accelerator.js';
export { CrackOrchestrator, type OrchestratorOptions, type ProgressInfo } from './orchestrator.js';
export { VectorizedCrackEngine, type VaultData as V2VaultData, type V2Options, type CrackResult as V2CrackResult, type ProgressInfo as V2ProgressInfo } from './vectorized-engine.js';
export { UniversalCrackEngine, type UniversalOptions, type UniversalProgressInfo, type UniversalCrackResult } from './universal-engine.js';
export { maskGenerator, maskBatchGenerator, incrementalMaskGenerator, hybridGenerator, combinatoryGenerator, parseMask, maskKeyspace, getMaskInfo, type MaskOptions, type MaskInfo, } from './mask-generator.js';
export { parseRule, applyRule, applyRuleStr, applyRules, applyRulesBatch, loadRulesFile, estimateRuleOutput, RULES_BEST64, RULES_LEET, RULES_TOGGLES, RULES_APPEND_NUMS, type RuleFunction, } from './rule-engine.js';
export { CheckpointManager, type CheckpointData, type CheckpointProgress, type CheckpointOptions, } from './checkpoint.js';
export { ETAEstimator, formatDuration, formatSpeed, formatNumber, type ETAInfo, } from './eta-estimator.js';
export { WordlistManager, type WordlistInfo, type WordlistManagerOptions, } from './wordlist-manager.js';
//# sourceMappingURL=index.d.ts.map