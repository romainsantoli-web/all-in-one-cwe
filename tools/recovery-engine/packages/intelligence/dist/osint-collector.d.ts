/**
 * OSINT Collector — Automatic profile enrichment
 *
 * Collects public information (WITH USER'S CONSENT) to build
 * a richer password guessing profile.
 *
 * Sources:
 * 1. Have I Been Pwned (HIBP) — check if email was in a breach
 * 2. Public social media metadata (if API keys provided)
 * 3. Username enumeration across platforms
 * 4. Blockchain address analysis (ENS names, NFT metadata)
 * 5. WHOIS / domain registration data
 *
 * All data collected is used solely for password candidate generation.
 */
import { type UserProfile } from '@metamask-recovery/core';
export interface OSINTConfig {
    /** User's email addresses */
    emails?: string[];
    /** Known usernames / handles */
    usernames?: string[];
    /** Ethereum addresses (for ENS / on-chain analysis) */
    ethAddresses?: string[];
    /** Social media profile URLs */
    socialUrls?: string[];
    /** API keys for enhanced collection */
    apiKeys?: {
        hibp?: string;
        hunter?: string;
        etherscan?: string;
    };
}
export interface OSINTResult {
    /** Discovered names */
    names: string[];
    /** Discovered dates (birthdays, registration dates) */
    dates: string[];
    /** Discovered words (interests, locations, etc.) */
    words: string[];
    /** Discovered partials (common fragments) */
    partials: string[];
    /** Breaches the user appeared in */
    breaches: BreachInfo[];
    /** ENS names linked to addresses */
    ensNames: string[];
    /** Raw collected data for audit trail */
    rawData: Record<string, unknown>;
}
export interface BreachInfo {
    name: string;
    date: string;
    dataTypes: string[];
    /** Whether plaintext passwords were leaked (helps with pattern analysis) */
    hasPasswords: boolean;
}
export declare class OSINTCollector {
    private config;
    private results;
    constructor(config: OSINTConfig);
    /**
     * Run all available OSINT collection in parallel.
     */
    collect(): Promise<OSINTResult>;
    /**
     * Merge OSINT results into an existing user profile.
     */
    enrichProfile(profile: UserProfile): UserProfile;
    private collectFromHIBP;
    private collectFromHIBPFree;
    private extractEmailPatterns;
    private analyzeUsernames;
    private analyzeBlockchain;
    private analyzeSocialUrls;
}
//# sourceMappingURL=osint-collector.d.ts.map