// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Copilot Pro Bridge — exchanges GitHub OAuth JWT for Copilot API access
 * and proxies requests to Claude or Mistral models via the Copilot API.
 *
 * Flow:
 *   1. User provides a GitHub OAuth token or PAT with `copilot` scope
 *   2. Bridge exchanges it for a short-lived Copilot session token
 *   3. Requests are proxied to api.githubcopilot.com (OpenAI-compatible)
 *   4. User picks target model: Claude (Anthropic) or Mistral
 */

import { getProviderSettings } from "@/lib/settings";

/* ---------- constants ---------- */

const GITHUB_COPILOT_TOKEN_URL =
  "https://api.github.com/copilot_internal/v2/token";
const COPILOT_CHAT_URL =
  "https://api.githubcopilot.com/chat/completions";

/** Models available via Copilot API */
export const COPILOT_MODELS = {
  "claude-code": {
    id: "claude-sonnet-4-20250514",
    label: "Claude Sonnet 4 (via Copilot)",
    provider: "anthropic",
  },
  "mistral-vibe": {
    id: "mistral-large-latest",
    label: "Mistral Large (via Copilot)",
    provider: "mistral",
  },
} as const;

export type BridgeTarget = keyof typeof COPILOT_MODELS;

/* ---------- token cache ---------- */

interface CachedToken {
  token: string;
  expiresAt: number; // epoch ms
}

let tokenCache: CachedToken | null = null;

/* ---------- public API ---------- */

/**
 * Get the raw GitHub token from settings or env.
 * Priority: saved settings > env var.
 */
export async function getGitHubToken(): Promise<string | null> {
  const saved = await getProviderSettings();
  return saved["COPILOT_JWT"] || process.env.COPILOT_JWT || null;
}

/**
 * Exchange GitHub token for a Copilot session token.
 * Returns cached token if still valid (with 60s margin).
 */
export async function getCopilotToken(): Promise<string> {
  const ghToken = await getGitHubToken();
  if (!ghToken) {
    throw new Error("No COPILOT_JWT configured — add it in Settings");
  }

  // Return cached if not expired (60s margin)
  if (tokenCache && tokenCache.expiresAt > Date.now() + 60_000) {
    return tokenCache.token;
  }

  const res = await fetch(GITHUB_COPILOT_TOKEN_URL, {
    headers: {
      Authorization: `token ${ghToken}`,
      Accept: "application/json",
      "User-Agent": "security-dashboard/1.0",
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    if (res.status === 401) {
      throw new Error("Invalid GitHub token — check COPILOT_JWT in Settings");
    }
    if (res.status === 403) {
      throw new Error(
        "GitHub token lacks Copilot access — ensure Copilot Pro is active and token has 'copilot' scope",
      );
    }
    throw new Error(`Copilot token exchange failed (${res.status}): ${text.slice(0, 200)}`);
  }

  const data = (await res.json()) as { token?: string; expires_at?: number };
  if (!data.token) {
    throw new Error("Copilot token response missing 'token' field");
  }

  tokenCache = {
    token: data.token,
    expiresAt: data.expires_at
      ? data.expires_at * 1000 // GitHub returns epoch seconds
      : Date.now() + 25 * 60 * 1000, // default 25 min
  };

  return tokenCache.token;
}

/**
 * Proxy a chat completion request through the Copilot API.
 */
export async function copilotChatCompletion(params: {
  target: BridgeTarget;
  messages: Array<{ role: string; content: string }>;
  temperature?: number;
  maxTokens?: number;
  stream?: boolean;
}): Promise<Response> {
  const copilotToken = await getCopilotToken();
  const model = COPILOT_MODELS[params.target];

  const body = {
    model: model.id,
    messages: params.messages,
    temperature: params.temperature ?? 0.7,
    max_tokens: params.maxTokens ?? 4096,
    stream: params.stream ?? false,
  };

  const res = await fetch(COPILOT_CHAT_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${copilotToken}`,
      "Content-Type": "application/json",
      "Copilot-Integration-Id": "vscode-chat",
      "Editor-Version": "vscode/1.100.0",
      "User-Agent": "security-dashboard/1.0",
    },
    body: JSON.stringify(body),
  });

  return res;
}

/**
 * Test the bridge connection — verifies token exchange works.
 */
export async function testBridgeConnection(): Promise<{
  ok: boolean;
  error?: string;
  tokenExpiresAt?: string;
  availableModels: string[];
}> {
  try {
    const token = await getCopilotToken();
    return {
      ok: true,
      tokenExpiresAt: tokenCache
        ? new Date(tokenCache.expiresAt).toISOString()
        : undefined,
      availableModels: Object.entries(COPILOT_MODELS).map(
        ([key, m]) => `${key} → ${m.id}`,
      ),
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      availableModels: [],
    };
  }
}

/**
 * Get environment variables for spawning Claude Code or Mistral Vibe
 * through the Copilot bridge.
 *
 * Claude Code reads ANTHROPIC_API_KEY + ANTHROPIC_BASE_URL
 * Mistral Vibe reads MISTRAL_API_KEY + MISTRAL_ENDPOINT
 */
export async function getBridgeEnvForProvider(
  target: BridgeTarget,
): Promise<Record<string, string>> {
  const copilotToken = await getCopilotToken();

  if (target === "claude-code") {
    return {
      ANTHROPIC_API_KEY: copilotToken,
      ANTHROPIC_BASE_URL: COPILOT_CHAT_URL.replace("/chat/completions", ""),
    };
  }

  if (target === "mistral-vibe") {
    return {
      MISTRAL_API_KEY: copilotToken,
      MISTRAL_ENDPOINT: COPILOT_CHAT_URL.replace("/chat/completions", ""),
    };
  }

  return {};
}

/**
 * Get bridge status for UI display.
 */
export async function getBridgeStatus(): Promise<{
  configured: boolean;
  tokenCached: boolean;
  tokenExpiresAt: string | null;
  targets: Array<{
    id: string;
    label: string;
    model: string;
    provider: string;
  }>;
}> {
  const ghToken = await getGitHubToken();

  return {
    configured: !!ghToken,
    tokenCached: !!tokenCache && tokenCache.expiresAt > Date.now(),
    tokenExpiresAt: tokenCache
      ? new Date(tokenCache.expiresAt).toISOString()
      : null,
    targets: Object.entries(COPILOT_MODELS).map(([id, m]) => ({
      id,
      label: m.label,
      model: m.id,
      provider: m.provider,
    })),
  };
}

/** Invalidate the cached token (useful after key change). */
export function clearTokenCache(): void {
  tokenCache = null;
}
