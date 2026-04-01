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
export class OSINTCollector {
    config;
    results = {
        names: [],
        dates: [],
        words: [],
        partials: [],
        breaches: [],
        ensNames: [],
        rawData: {},
    };
    constructor(config) {
        this.config = config;
    }
    /**
     * Run all available OSINT collection in parallel.
     */
    async collect() {
        const tasks = [];
        if (this.config.emails?.length) {
            tasks.push(this.collectFromHIBP());
            tasks.push(this.extractEmailPatterns());
        }
        if (this.config.usernames?.length) {
            tasks.push(this.analyzeUsernames());
        }
        if (this.config.ethAddresses?.length) {
            tasks.push(this.analyzeBlockchain());
        }
        if (this.config.socialUrls?.length) {
            tasks.push(this.analyzeSocialUrls());
        }
        await Promise.allSettled(tasks);
        // Deduplicate
        this.results.names = [...new Set(this.results.names)];
        this.results.dates = [...new Set(this.results.dates)];
        this.results.words = [...new Set(this.results.words)];
        this.results.partials = [...new Set(this.results.partials)];
        return this.results;
    }
    /**
     * Merge OSINT results into an existing user profile.
     */
    enrichProfile(profile) {
        return {
            names: [...new Set([...(profile.names || []), ...this.results.names])],
            dates: [...new Set([...(profile.dates || []), ...this.results.dates])],
            words: [...new Set([...(profile.words || []), ...this.results.words])],
            partials: [...new Set([...(profile.partials || []), ...this.results.partials])],
            oldPasswords: profile.oldPasswords || [],
        };
    }
    // ---------- HIBP (Have I Been Pwned) ----------
    async collectFromHIBP() {
        if (!this.config.apiKeys?.hibp) {
            // Without API key, use the k-anonymity range API (free, no key needed)
            return this.collectFromHIBPFree();
        }
        for (const email of this.config.emails || []) {
            try {
                const resp = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
                    headers: {
                        'hibp-api-key': this.config.apiKeys.hibp,
                        'user-agent': 'MetaMask-Recovery-V3',
                    },
                });
                if (resp.status === 200) {
                    const breaches = await resp.json();
                    for (const b of breaches) {
                        this.results.breaches.push({
                            name: b.Name,
                            date: b.BreachDate,
                            dataTypes: b.DataClasses,
                            hasPasswords: b.DataClasses.includes('Passwords'),
                        });
                        // Extract useful tokens from breach names
                        this.results.words.push(b.Name.toLowerCase());
                        // Extract year from breach date
                        const year = b.BreachDate.split('-')[0];
                        if (year)
                            this.results.dates.push(year);
                    }
                }
            }
            catch {
                // Network error, continue silently
            }
        }
    }
    async collectFromHIBPFree() {
        // Just check if email was breached (no details without API key)
        for (const email of this.config.emails || []) {
            try {
                const resp = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`, {
                    headers: { 'user-agent': 'MetaMask-Recovery-V3' },
                });
                if (resp.status === 200) {
                    const breaches = await resp.json();
                    for (const b of breaches) {
                        this.results.breaches.push({
                            name: b.Name,
                            date: 'unknown',
                            dataTypes: [],
                            hasPasswords: false,
                        });
                    }
                }
            }
            catch {
                // Continue
            }
        }
    }
    // ---------- Email Pattern Analysis ----------
    async extractEmailPatterns() {
        for (const email of this.config.emails || []) {
            const [local] = email.split('@');
            if (!local)
                continue;
            // Extract potential name parts: romain.dupont → ["romain", "dupont"]
            const parts = local.split(/[._\-+]/);
            for (const part of parts) {
                if (part.length >= 3) {
                    this.results.partials.push(part);
                    this.results.partials.push(part.charAt(0).toUpperCase() + part.slice(1));
                    this.results.names.push(part);
                }
            }
            // Check for embedded numbers (years, postcodes)
            const numbers = local.match(/\d+/g);
            if (numbers) {
                for (const n of numbers) {
                    this.results.dates.push(n);
                    this.results.partials.push(n);
                }
            }
            // The whole local part is a potential partial
            this.results.partials.push(local);
            // Domain might be useful too (company name, ISP)
            const domain = email.split('@')[1]?.split('.')[0];
            if (domain && domain.length >= 3 && !['gmail', 'yahoo', 'outlook', 'hotmail', 'proton', 'icloud'].includes(domain)) {
                this.results.words.push(domain);
            }
        }
    }
    // ---------- Username Analysis ----------
    async analyzeUsernames() {
        for (const username of this.config.usernames || []) {
            // Split camelCase: "CryptoRomain42" → ["Crypto", "Romain", "42"]
            const camelParts = username.match(/[A-Z]?[a-z]+|[A-Z]+|[0-9]+/g);
            if (camelParts) {
                for (const part of camelParts) {
                    if (part.length >= 3 && !/^\d+$/.test(part)) {
                        this.results.partials.push(part);
                        this.results.partials.push(part.toLowerCase());
                        this.results.partials.push(part.charAt(0).toUpperCase() + part.slice(1).toLowerCase());
                    }
                    if (/^\d+$/.test(part)) {
                        this.results.dates.push(part);
                        this.results.partials.push(part);
                    }
                }
            }
            // Split by common separators
            const sepParts = username.split(/[._\-]/);
            for (const part of sepParts) {
                if (part.length >= 3) {
                    this.results.partials.push(part);
                }
            }
            // Full username variants
            this.results.partials.push(username);
            this.results.partials.push(username.toLowerCase());
        }
    }
    // ---------- Blockchain Analysis ----------
    async analyzeBlockchain() {
        for (const address of this.config.ethAddresses || []) {
            // ENS reverse lookup
            try {
                const resp = await fetch(`https://api.ensideas.com/ens/resolve/${address}`);
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.name) {
                        this.results.ensNames.push(data.name);
                        // Extract tokens: "romain.eth" → "romain"
                        const name = data.name.replace(/\.eth$/, '');
                        this.results.partials.push(name);
                        this.results.names.push(name);
                    }
                }
            }
            catch {
                // Continue
            }
            // Etherscan labels (if API key provided)
            if (this.config.apiKeys?.etherscan) {
                try {
                    const resp = await fetch(`https://api.etherscan.io/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=1&sort=asc&apikey=${this.config.apiKeys.etherscan}`);
                    if (resp.ok) {
                        const data = await resp.json();
                        if (data.result?.[0]) {
                            // First transaction date → potential registration date
                            const ts = parseInt(data.result[0].timeStamp) * 1000;
                            const date = new Date(ts);
                            this.results.dates.push(String(date.getFullYear()));
                            this.results.dates.push(`${date.getDate().toString().padStart(2, '0')}${(date.getMonth() + 1).toString().padStart(2, '0')}${date.getFullYear()}`);
                        }
                    }
                }
                catch {
                    // Continue
                }
            }
        }
    }
    // ---------- Social URL Analysis ----------
    async analyzeSocialUrls() {
        for (const url of this.config.socialUrls || []) {
            try {
                const parsed = new URL(url);
                const pathParts = parsed.pathname.split('/').filter(p => p.length > 0);
                // The last path segment is usually the username
                const username = pathParts[pathParts.length - 1];
                if (username && username.length >= 3) {
                    this.results.partials.push(username);
                    this.results.partials.push(username.toLowerCase());
                    // Split username variants
                    const parts = username.match(/[A-Z]?[a-z]+|[A-Z]+|[0-9]+/g);
                    if (parts) {
                        for (const part of parts) {
                            if (part.length >= 3 && !/^\d+$/.test(part)) {
                                this.results.partials.push(part);
                            }
                            if (/^\d+$/.test(part)) {
                                this.results.dates.push(part);
                            }
                        }
                    }
                }
                // Platform name as a word
                const platform = parsed.hostname.replace('www.', '').split('.')[0];
                if (platform) {
                    this.results.words.push(platform);
                }
            }
            catch {
                // Invalid URL, skip
            }
        }
    }
}
//# sourceMappingURL=osint-collector.js.map