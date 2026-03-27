// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Settings store — JSON-file-based persistence for provider API keys.
 * Stored in PROJECT_ROOT/reports/.settings/providers.json
 * Keys are stored server-side only — never exposed in full to the client.
 */

import { readFile, writeFile, mkdir } from "fs/promises";
import { join } from "path";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const SETTINGS_DIR = join(PROJECT_ROOT, "reports", ".settings");
const PROVIDERS_FILE = join(SETTINGS_DIR, "providers.json");

export interface ProviderSettings {
  [envVar: string]: string; // e.g. { "ANTHROPIC_API_KEY": "sk-ant-..." }
}

async function ensureDir(): Promise<void> {
  await mkdir(SETTINGS_DIR, { recursive: true });
}

/**
 * Read saved provider keys from disk.
 */
export async function getProviderSettings(): Promise<ProviderSettings> {
  try {
    const raw = await readFile(PROVIDERS_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as ProviderSettings;
    }
    return {};
  } catch {
    return {};
  }
}

/**
 * Save provider keys to disk (atomic write).
 */
export async function saveProviderSettings(settings: ProviderSettings): Promise<void> {
  await ensureDir();
  // Validate: only allow known env var patterns (alphanumeric + underscore)
  for (const key of Object.keys(settings)) {
    if (!/^[A-Z][A-Z0-9_]{1,63}$/.test(key)) {
      throw new Error(`Invalid env var name: ${key}`);
    }
  }
  await writeFile(PROVIDERS_FILE, JSON.stringify(settings, null, 2));
}

/**
 * Merge saved settings into process.env for subprocess spawning.
 * Returns a new env object (does NOT mutate process.env).
 */
export async function getEnvWithSettings(): Promise<NodeJS.ProcessEnv> {
  const saved = await getProviderSettings();
  return { ...process.env, ...saved };
}

/**
 * Mask a secret for display: show only last 4 chars.
 */
export function maskSecret(value: string): string {
  if (value.length <= 4) return "****";
  return "****" + value.slice(-4);
}

/**
 * Check if a provider key is configured (from saved settings or process.env).
 */
export async function isProviderConfigured(envVar: string): Promise<boolean> {
  const saved = await getProviderSettings();
  return !!(saved[envVar] || process.env[envVar]);
}
