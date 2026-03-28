// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Interactive terminal sessions — spawns CLI processes.
 * Shell sessions use node-pty for real PTY support (echo, line editing, TUI apps).
 * AI provider sessions use child_process.spawn with pipes.
 * In-memory store (single process).
 */

import { spawn, type ChildProcess } from "child_process";
import { randomUUID } from "crypto";
import * as pty from "node-pty";

export type AIProvider = "claude-code" | "mistral-vibe" | "shell";

export interface InteractiveSession {
  id: string;
  provider: AIProvider;
  label: string;
  status: "running" | "stopped" | "error";
  createdAt: string;
  outputBuffer: string[];
  totalBytes: number;
  pid: number | null;
  exitCode: number | null;
  error: string | null;
}

interface SessionInternal extends InteractiveSession {
  process: ChildProcess | null;
  ptyProcess: pty.IPty | null;
  listeners: Set<(chunk: string) => void>;
}

/** Provider command definitions — only these are allowed (no arbitrary commands). */
const PROVIDER_COMMANDS: Record<AIProvider, { cmd: string; args: string[]; label: string }> = {
  "claude-code": {
    cmd: "claude",
    args: [],
    label: "Claude Code",
  },
  "mistral-vibe": {
    cmd: "mistral-vibe",
    args: [],
    label: "Mistral Vibe",
  },
  shell: {
    cmd: process.env.SHELL || "/bin/zsh",
    args: [],
    label: "Shell",
  },
};

/**
 * Persist sessions on globalThis so that Next.js HMR doesn't reset the Map.
 * Without this, every hot-reload creates a fresh Map and existing sessions 404.
 */
const globalSessions = globalThis as unknown as {
  __interactive_sessions?: Map<string, SessionInternal>;
};
if (!globalSessions.__interactive_sessions) {
  globalSessions.__interactive_sessions = new Map();
}
const sessions = globalSessions.__interactive_sessions;

/** Max output buffer lines (prevent memory blow-up) */
const MAX_BUFFER_LINES = 5000;

/**
 * Create and start a new interactive session.
 */
export function createInteractiveSession(
  provider: AIProvider,
  customEnv?: Record<string, string>,
  cols = 80,
  rows = 24,
): InteractiveSession {
  const config = PROVIDER_COMMANDS[provider];
  if (!config) {
    throw new Error(`Unknown provider: ${provider}`);
  }

  const id = randomUUID();
  const isShell = provider === "shell";
  const cwd = process.env.PROJECT_ROOT || process.env.HOME || "/tmp";
  const env = {
    ...process.env,
    ...customEnv,
    TERM: isShell ? "xterm-256color" : "dumb",
    ...(isShell ? {} : { NO_COLOR: "1" }),
  };

  const session: SessionInternal = {
    id,
    provider,
    label: config.label,
    status: "running",
    createdAt: new Date().toISOString(),
    outputBuffer: [],
    totalBytes: 0,
    pid: null,
    exitCode: null,
    error: null,
    process: null,
    ptyProcess: null,
    listeners: new Set(),
  };

  const pushOutput = (text: string) => {
    session.outputBuffer.push(text);
    session.totalBytes += text.length;
    if (session.outputBuffer.length > MAX_BUFFER_LINES) {
      session.outputBuffer.splice(0, session.outputBuffer.length - MAX_BUFFER_LINES);
    }
    for (const listener of session.listeners) {
      listener(text);
    }
  };

  if (isShell) {
    // Use node-pty for real PTY — shell gets proper echo, line editing, TUI support
    try {
      const ptyProc = pty.spawn(config.cmd, config.args, {
        name: "xterm-256color",
        cols,
        rows,
        cwd,
        env: env as Record<string, string>,
      });

      session.ptyProcess = ptyProc;
      session.pid = ptyProc.pid;

      ptyProc.onData((data: string) => {
        pushOutput(data);
      });

      ptyProc.onExit(({ exitCode }: { exitCode: number }) => {
        session.status = "stopped";
        session.exitCode = exitCode;
        pushOutput(`\n[Process exited with code ${exitCode}]\n`);
      });
    } catch (err) {
      session.status = "error";
      session.error = `Failed to spawn PTY: ${err instanceof Error ? err.message : String(err)}`;
    }
  } else {
    // AI providers use child_process.spawn with pipes (no PTY needed)
    try {
      const proc = spawn(config.cmd, config.args, {
        env,
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
      });

      session.process = proc;
      session.pid = proc.pid ?? null;

      proc.stdout?.on("data", (chunk: Buffer) => {
        pushOutput(chunk.toString("utf-8"));
      });

      proc.stderr?.on("data", (chunk: Buffer) => {
        pushOutput(chunk.toString("utf-8"));
      });

      proc.on("close", (code) => {
        session.status = "stopped";
        session.exitCode = code;
        pushOutput(`\n[Process exited with code ${code}]\n`);
      });

      proc.on("error", (err) => {
        session.status = "error";
        session.error = err.message;
        pushOutput(`\n[Error: ${err.message}]\n`);
      });
    } catch (err) {
      session.status = "error";
      session.error = `Failed to spawn ${config.cmd}: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  sessions.set(id, session);
  return toPublic(session);
}

/**
 * Send text to the stdin of a session.
 */
export function sendInput(sessionId: string, text: string): boolean {
  const session = sessions.get(sessionId);
  if (!session || session.status !== "running") return false;
  try {
    if (session.ptyProcess) {
      session.ptyProcess.write(text);
    } else if (session.process) {
      session.process.stdin?.write(text);
    } else {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Resize the PTY (only works for shell sessions with node-pty).
 */
export function resizeSession(sessionId: string, cols: number, rows: number): boolean {
  const session = sessions.get(sessionId);
  if (!session || !session.ptyProcess || session.status !== "running") return false;
  try {
    session.ptyProcess.resize(
      Math.max(1, Math.min(cols, 500)),
      Math.max(1, Math.min(rows, 200)),
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Subscribe to output events (for SSE streaming).
 * Returns an unsubscribe function.
 */
export function subscribeOutput(
  sessionId: string,
  listener: (chunk: string) => void,
): (() => void) | null {
  const session = sessions.get(sessionId);
  if (!session) return null;

  // Send existing buffer first
  for (const line of session.outputBuffer) {
    listener(line);
  }

  session.listeners.add(listener);
  return () => {
    session.listeners.delete(listener);
  };
}

/**
 * Kill an interactive session.
 */
export function killInteractiveSession(sessionId: string): boolean {
  const session = sessions.get(sessionId);
  if (!session) return false;

  if (session.status === "running") {
    try {
      if (session.ptyProcess) {
        session.ptyProcess.kill();
      } else if (session.process) {
        session.process.kill("SIGTERM");
      }
    } catch {
      try {
        session.process?.kill("SIGKILL");
      } catch { /* already gone */ }
    }
    session.status = "stopped";
  }
  return true;
}

/**
 * Remove a session from memory entirely (kill first if still running).
 */
export function removeInteractiveSession(sessionId: string): boolean {
  const session = sessions.get(sessionId);
  if (!session) return false;

  if (session.status === "running") {
    try {
      if (session.ptyProcess) {
        session.ptyProcess.kill();
      } else if (session.process) {
        session.process.kill("SIGTERM");
      }
    } catch { /* */ }
  }
  session.listeners.clear();
  sessions.delete(sessionId);
  return true;
}

/**
 * List all interactive sessions.
 */
export function listInteractiveSessions(): InteractiveSession[] {
  return Array.from(sessions.values())
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map(toPublic);
}

/**
 * Get a single session.
 */
export function getInteractiveSession(sessionId: string): InteractiveSession | null {
  const session = sessions.get(sessionId);
  return session ? toPublic(session) : null;
}

/**
 * Check if a provider is available (command exists in PATH).
 */
export function isProviderAvailable(provider: AIProvider): boolean {
  const config = PROVIDER_COMMANDS[provider];
  if (!config) return false;
  // shell is always available
  if (provider === "shell") return true;
  try {
    const { execSync } = require("child_process");
    execSync(`which ${config.cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get provider info for display.
 */
export function getProviderInfo() {
  return Object.entries(PROVIDER_COMMANDS).map(([key, val]) => ({
    id: key as AIProvider,
    label: val.label,
    command: val.cmd,
    available: isProviderAvailable(key as AIProvider),
  }));
}

function toPublic(s: SessionInternal): InteractiveSession {
  return {
    id: s.id,
    provider: s.provider,
    label: s.label,
    status: s.status,
    createdAt: s.createdAt,
    outputBuffer: [], // Don't send buffer in list responses
    totalBytes: s.totalBytes,
    pid: s.pid,
    exitCode: s.exitCode,
    error: s.error,
  };
}
