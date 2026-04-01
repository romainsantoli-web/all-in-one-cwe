// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
// Static data mirrored from orchestrator/config.py for the dashboard.

export interface ToolMeta {
  name: string;
  profile: string | null;
  requires: string | null;
  group: string;
  envRequires?: string[];
  fileRequires?: string;
  sequential?: boolean;
}

export interface ParallelGroup {
  name: string;
  tools: string[];
  dependsOn: string[];
}

export const PARALLEL_GROUPS: ParallelGroup[] = [
  { name: "recon", tools: ["subfinder", "httpx", "naabu", "katana", "amass", "dnsx", "whatweb", "wafw00f", "gowitness"], dependsOn: [] },
  { name: "dast", tools: ["nuclei", "zap", "nikto", "testssl", "corscanner", "nmap", "dalfox", "log4j-scan"], dependsOn: ["recon"] },
  { name: "injection", tools: ["sqlmap", "sstimap", "crlfuzz", "ffuf", "feroxbuster", "arjun", "ssrfmap", "ppmap"], dependsOn: ["dast"] },
  { name: "specialized", tools: ["graphw00f", "clairvoyance", "jsluice", "cloud-enum", "dnsreaper", "subdominator", "cmseek", "theharvester", "cherrybomb", "interactsh"], dependsOn: ["recon"] },
  { name: "python-scanners", tools: ["idor-scanner", "auth-bypass", "user-enum", "notif-inject", "redirect-cors", "oidc-audit", "bypass-403-advanced", "ssrf-scanner", "xss-scanner", "api-discovery", "secret-leak", "websocket-scanner", "cache-deception", "slowloris-check"], dependsOn: ["recon"] },
  { name: "code-analysis", tools: ["semgrep", "gitleaks", "trufflehog", "trivy", "dependency-check", "trivy-image", "cwe-checker", "cve-bin-tool", "dockle", "retirejs"], dependsOn: [] },
  { name: "conditional", tools: ["garak", "jwt-tool"], dependsOn: [] },
  { name: "waf-bypass", tools: ["bypass-403"], dependsOn: ["recon"] },
  { name: "web-advanced", tools: ["smuggler"], dependsOn: ["dast"] },
  { name: "iac", tools: ["checkov"], dependsOn: [] },
  { name: "api-fuzzing", tools: ["restler"], dependsOn: ["recon"] },
  { name: "waf-evasion", tools: ["waf-bypass", "header-classifier", "header-poc-generator"], dependsOn: ["recon"] },
  { name: "business-logic", tools: ["coupon-promo-fuzzer", "hateoas-fuzzer", "timing-oracle"], dependsOn: ["recon"] },
  { name: "discovery", tools: ["source-map-scanner", "hidden-endpoint-scanner", "response-pii-detector"], dependsOn: ["recon"] },
  { name: "oauth-session", tools: ["oauth-flow-scanner"], dependsOn: ["recon"] },
  { name: "cdp-scanners", tools: ["cdp-token-extractor", "cdp-checkout-interceptor", "cdp-credential-scanner"], dependsOn: ["recon"] },
  { name: "crypto-ctf", tools: ["crypto-analyzer"], dependsOn: [] },
  { name: "forensics", tools: ["steg-analyzer", "pcap-analyzer", "forensic-toolkit"], dependsOn: [] },
  { name: "reversing", tools: ["disasm-analyzer", "pwn-toolkit"], dependsOn: [] },
  { name: "privesc", tools: ["privesc-scanner"], dependsOn: ["recon"] },
];

export const TOOL_META: Record<string, Omit<ToolMeta, "name" | "group">> = {
  subfinder:           { profile: null, requires: "domain" },
  httpx:               { profile: "recon", requires: "domain" },
  naabu:               { profile: "recon", requires: "domain" },
  katana:              { profile: "recon", requires: "target" },
  amass:               { profile: null, requires: "domain" },
  dnsx:                { profile: null, requires: "domain" },
  whatweb:             { profile: null, requires: "target" },
  wafw00f:             { profile: null, requires: "target" },
  gowitness:           { profile: "screenshot", requires: "target" },
  nuclei:              { profile: null, requires: "target" },
  zap:                 { profile: null, requires: "target" },
  nikto:               { profile: null, requires: "target" },
  testssl:             { profile: null, requires: "target" },
  corscanner:          { profile: null, requires: "domain" },
  nmap:                { profile: "network", requires: "domain" },
  dalfox:              { profile: "xss", requires: "target" },
  "log4j-scan":        { profile: null, requires: "target" },
  sqlmap:              { profile: null, requires: "target", sequential: true },
  sstimap:             { profile: null, requires: "target" },
  crlfuzz:             { profile: null, requires: "target" },
  ffuf:                { profile: "fuzz", requires: "target" },
  feroxbuster:         { profile: "fuzz", requires: "target" },
  arjun:               { profile: "fuzz", requires: "target" },
  ssrfmap:             { profile: "ssrf", requires: "target" },
  ppmap:               { profile: "prototype", requires: "target" },
  graphw00f:           { profile: null, requires: "target" },
  clairvoyance:        { profile: "graphql", requires: "target" },
  jsluice:             { profile: "js", requires: "target" },
  "cloud-enum":        { profile: null, requires: "domain" },
  dnsreaper:           { profile: null, requires: "domain" },
  subdominator:        { profile: null, requires: "domain" },
  cmseek:              { profile: "cms", requires: "target" },
  theharvester:        { profile: "osint", requires: "domain" },
  cherrybomb:          { profile: "openapi", requires: null, fileRequires: "reports/cherrybomb/openapi.json" },
  interactsh:          { profile: "oob", requires: null },
  semgrep:             { profile: null, requires: "code" },
  gitleaks:            { profile: null, requires: "repo" },
  trufflehog:          { profile: null, requires: "repo" },
  trivy:               { profile: null, requires: "code" },
  "dependency-check":  { profile: null, requires: "code" },
  "trivy-image":       { profile: null, requires: "image" },
  "cwe-checker":       { profile: null, requires: "binary" },
  "cve-bin-tool":      { profile: null, requires: "bin_dir" },
  dockle:              { profile: "container", requires: "image" },
  retirejs:            { profile: "frontend-sca", requires: "code" },
  garak:               { profile: null, requires: null, envRequires: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] },
  "jwt-tool":          { profile: "jwt", requires: null, envRequires: ["JWT_TOKEN"] },
  "bypass-403":        { profile: "waf", requires: "target" },
  "idor-scanner":      { profile: "python-scanners", requires: "target" },
  "auth-bypass":       { profile: "python-scanners", requires: "target" },
  "user-enum":         { profile: "python-scanners", requires: "target" },
  "notif-inject":      { profile: "python-scanners", requires: "target" },
  "redirect-cors":     { profile: "python-scanners", requires: "target" },
  "oidc-audit":        { profile: "python-scanners", requires: "target" },
  "bypass-403-advanced": { profile: "python-scanners", requires: "target" },
  "ssrf-scanner":      { profile: "python-scanners", requires: "target" },
  "xss-scanner":       { profile: "python-scanners", requires: "target" },
  "api-discovery":     { profile: "python-scanners", requires: "target" },
  "secret-leak":       { profile: "python-scanners", requires: "target" },
  "websocket-scanner": { profile: "python-scanners", requires: "target" },
  "cache-deception":   { profile: "python-scanners", requires: "target" },
  "slowloris-check":   { profile: "python-scanners", requires: "target" },
  smuggler:            { profile: "web-advanced", requires: "target" },
  checkov:             { profile: "iac", requires: "code" },
  restler:             { profile: "api-fuzzing", requires: null, fileRequires: "configs/openapi.yaml" },
  // --- 12 new generic tools ---
  "waf-bypass":        { profile: "python-scanners", requires: "target" },
  "source-map-scanner": { profile: "python-scanners", requires: "target" },
  "hidden-endpoint-scanner": { profile: "python-scanners", requires: "target" },
  "hateoas-fuzzer":    { profile: "python-scanners", requires: "target" },
  "coupon-promo-fuzzer": { profile: "python-scanners", requires: "target" },
  "response-pii-detector": { profile: "python-scanners", requires: "target" },
  "header-classifier": { profile: "python-scanners", requires: "target" },
  "header-poc-generator": { profile: "python-scanners", requires: "target" },
  "timing-oracle":     { profile: "python-scanners", requires: "target" },
  "oauth-flow-scanner": { profile: "python-scanners", requires: "target" },
  "cdp-token-extractor": { profile: "python-scanners", requires: "target", envRequires: ["CDP_URL"] },
  "cdp-checkout-interceptor": { profile: "python-scanners", requires: "target", envRequires: ["CDP_URL"] },
  "cdp-credential-scanner": { profile: "python-scanners", requires: "target", envRequires: ["CDP_URL"] },
  // --- CTF / Forensics / Reversing ---
  "crypto-analyzer":   { profile: "python-scanners", requires: null },
  "steg-analyzer":     { profile: "python-scanners", requires: null },
  "pcap-analyzer":     { profile: "python-scanners", requires: null },
  "forensic-toolkit":  { profile: "python-scanners", requires: null },
  "disasm-analyzer":   { profile: "python-scanners", requires: null },
  "pwn-toolkit":       { profile: "python-scanners", requires: null },
  "privesc-scanner":   { profile: "python-scanners", requires: "target" },
};

export const LIGHT_TOOLS = [
  "nuclei", "zap", "testssl", "sqlmap", "semgrep", "gitleaks", "trivy",
  "idor-scanner", "auth-bypass", "secret-leak", "api-discovery",
  "xss-scanner", "httpx", "whatweb", "wafw00f",
  "header-classifier", "source-map-scanner",
];

export const MEDIUM_TOOLS = [
  ...LIGHT_TOOLS,
  "nmap", "nikto", "dalfox", "corscanner", "crlfuzz", "sstimap",
  "arjun", "ffuf", "ssrfmap", "trufflehog", "dependency-check",
  "retirejs", "redirect-cors", "oidc-audit", "bypass-403-advanced",
  "user-enum", "notif-inject", "header-poc-generator", "timing-oracle",
];

export const CWE_TRIGGERS: Record<string, string[]> = {
  "CWE-918": ["ssrf-scanner"],
  "CWE-79":  ["xss-scanner", "header-poc-generator"],
  "CWE-89":  ["sqlmap"],
  "CWE-444": ["smuggler"],
  "CWE-524": ["cache-deception"],
  "CWE-400": ["slowloris-check"],
  "CWE-284": ["websocket-scanner"],
  "CWE-178": ["waf-bypass"],
  "CWE-200": ["response-pii-detector", "header-classifier"],
  "CWE-215": ["source-map-scanner", "hidden-endpoint-scanner"],
  "CWE-639": ["hateoas-fuzzer", "coupon-promo-fuzzer"],
  "CWE-601": ["oauth-flow-scanner"],
  "CWE-798": ["cdp-credential-scanner"],
  "CWE-208": ["timing-oracle"],
  "CWE-347": ["cdp-token-extractor"],
  "CWE-915": ["cdp-checkout-interceptor"],
  "CWE-327": ["crypto-analyzer"],
  "CWE-310": ["crypto-analyzer"],
  "CWE-319": ["pcap-analyzer", "header-poc-generator"],
  "CWE-1021": ["header-poc-generator"],
  "CWE-532": ["forensic-toolkit", "steg-analyzer"],
  "CWE-693": ["disasm-analyzer"],
  "CWE-119": ["pwn-toolkit"],
  "CWE-250": ["privesc-scanner"],
  "CWE-269": ["privesc-scanner"],
};

export const LLM_PROVIDERS = [
  { name: "claude", model: "claude-sonnet-4-20250514", envVar: "ANTHROPIC_API_KEY" },
  { name: "gpt", model: "gpt-4o", envVar: "OPENAI_API_KEY" },
  { name: "copilot-pro", model: "claude-sonnet-4.6", envVar: "COPILOT_OAUTH_TOKEN" },
  { name: "copilot", model: "gpt-4o", envVar: "COPILOT_OAUTH_TOKEN" },
  { name: "mistral", model: "mistral-large-latest", envVar: "MISTRAL_API_KEY" },
  { name: "gemini", model: "models/gemini-3-flash-preview", envVar: "GEMINI_API_KEY" },
];

/** Official models per provider — mirrors VS Code Copilot model picker. */
export const PROVIDER_MODELS: Record<string, string[]> = {
  claude: [
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250514",
    "claude-haiku-4-20250514",
    "claude-3.5-sonnet-20241022",
    "claude-3.5-haiku-20241022",
  ],
  gpt: [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "o3-mini",
  ],
  "copilot-pro": [
    "claude-sonnet-4.6",
    "claude-opus-4.6",
    "claude-opus-4.5",
    "claude-sonnet-4.5",
    "claude-sonnet-4",
    "claude-haiku-4.5",
    "gpt-4.1",
    "gpt-4o",
    "gpt-5-mini",
    "gpt-5.1",
    "gpt-5.2",
    "gpt-5.3",
    "gpt-5.4",
    "o3-mini",
    "o4-mini",
    "gemini-2.5-pro",
    "gemini-3-pro",
    "gemini-3.1-pro",
  ],
  copilot: [
    "gpt-4o",
    "gpt-4o-mini",
  ],
  mistral: [
    "mistral-large-latest",
    "mistral-medium-latest",
    "mistral-small-latest",
    "codestral-latest",
    "open-mistral-nemo",
  ],
  gemini: [
    "models/gemini-3-flash-preview",
    "models/gemini-2.5-pro-preview-05-06",
    "models/gemini-2.5-flash-preview-04-17",
    "models/gemini-2.0-flash",
    "models/gemini-2.0-flash-lite",
  ],
};

/** Get all tools with their group info resolved. */
export function getAllTools(): ToolMeta[] {
  const tools: ToolMeta[] = [];
  const seen = new Set<string>();
  for (const group of PARALLEL_GROUPS) {
    for (const name of group.tools) {
      if (seen.has(name)) continue;
      seen.add(name);
      const meta = TOOL_META[name] || { profile: null, requires: "target" };
      tools.push({ name, group: group.name, ...meta });
    }
  }
  // Add any tools in TOOL_META not captured in groups
  for (const [name, meta] of Object.entries(TOOL_META)) {
    if (!seen.has(name)) {
      seen.add(name);
      tools.push({ name, group: "ungrouped", ...meta });
    }
  }
  return tools;
}

/** Get tools matching a scan profile. */
export function getToolsForProfile(profile: "light" | "medium" | "full"): string[] {
  if (profile === "full") return getAllTools().map((t) => t.name);
  if (profile === "medium") return MEDIUM_TOOLS;
  return LIGHT_TOOLS;
}

/** Build graph data (nodes + links) for visualization. */
export function buildGraphData() {
  const nodes: { id: string; group: string; requires: string | null }[] = [];
  const links: { source: string; target: string; type: string }[] = [];
  const seen = new Set<string>();

  for (const group of PARALLEL_GROUPS) {
    for (const tool of group.tools) {
      if (!seen.has(tool)) {
        seen.add(tool);
        const meta = TOOL_META[tool];
        nodes.push({ id: tool, group: group.name, requires: meta?.requires || null });
      }
    }
    // Group dependency edges
    for (const dep of group.dependsOn) {
      const depGroup = PARALLEL_GROUPS.find((g) => g.name === dep);
      if (depGroup) {
        // Connect first tool of dependent group to last of dependency (simplified)
        links.push({ source: dep, target: group.name, type: "group_dep" });
      }
    }
  }

  // CWE trigger edges
  for (const [cwe, tools] of Object.entries(CWE_TRIGGERS)) {
    for (const tool of tools) {
      links.push({ source: cwe, target: tool, type: "cwe_trigger" });
    }
  }

  return { nodes, links, groups: PARALLEL_GROUPS, cweTriggers: CWE_TRIGGERS };
}
