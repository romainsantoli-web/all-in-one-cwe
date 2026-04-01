// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useRef, useCallback, useEffect } from "react";

export const dynamic = "force-dynamic";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VaultResult {
  format_id: string;
  format_name: string;
  category: string;
  file_path: string;
  size: number;
  encrypted: boolean;
  note: string;
  kdf: string;
  iterations: number;
  kdf_params: string;
}

interface ScanResult {
  total: number;
  results: VaultResult[];
  categories: Record<string, number>;
}

interface WordlistResult {
  total_candidates: number;
  output_path: string;
  output_filename: string;
  top_10: string[];
  web_words_count: number;
  stats: {
    profile_tokens: number;
    web_words: number;
    pcfg: { structure_count: number; terminal_count: number };
    markov: { context_count: number; alphabet_size: number; total_samples: number };
  };
}

// Recovery pipeline types
interface RecoveryProgress {
  attempts: number;
  speed: number;
  elapsed_s: number;
}

interface RecoveryLog {
  time: number;
  type: string;
  data: Record<string, unknown>;
}

type RecoverStatus = "idle" | "running" | "found" | "not_found" | "error";

// Android Bridge types
interface AndroidDevice {
  serial: string;
  state: string;
  info: string;
}

interface AndroidStatus {
  model: string;
  android_version: string;
  rooted: boolean;
  interfaces: string;
}

interface ShellOutput {
  ok: boolean;
  stdout: string;
  stderr: string;
  code: number;
}

// ---------------------------------------------------------------------------
// Category icons & colors
// ---------------------------------------------------------------------------

const CAT_ICONS: Record<string, string> = {
  crypto_wallet: "🪙",
  password_manager: "🔐",
  encrypted_file: "📦",
  ssh_key: "🔑",
  disk_encryption: "💽",
  wifi: "📡",
};

const CAT_COLORS: Record<string, string> = {
  crypto_wallet: "#F59E0B",
  password_manager: "#8B5CF6",
  encrypted_file: "#3B82F6",
  ssh_key: "#10B981",
  disk_encryption: "#EF4444",
  wifi: "#06B6D4",
};

const SEV_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#10B981",
  info: "#6B7280",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PasswordsPage() {
  // --- Vault Scanner state ---
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [extraDirs, setExtraDirs] = useState("");
  const [catFilter, setCatFilter] = useState("all");

  // --- Wordlist generator state ---
  const [generating, setGenerating] = useState(false);
  const [wordlistResult, setWordlistResult] = useState<WordlistResult | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const [webSearch, setWebSearch] = useState(false);

  // Profile fields
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [birthDate, setBirthDate] = useState("");
  const [email, setEmail] = useState("");
  const [city, setCity] = useState("");
  const [postalCode, setPostalCode] = useState("");
  const [keywords, setKeywords] = useState("");
  const [oldPasswords, setOldPasswords] = useState("");
  const [spouseName, setSpouseName] = useState("");
  const [petNames, setPetNames] = useState("");
  const [company, setCompany] = useState("");
  const [phone, setPhone] = useState("");
  // WiFi fields
  const [ssid, setSsid] = useState("");
  const [bssid, setBssid] = useState("");
  const [isp, setIsp] = useState("");

  // --- Password hints state ---
  const [hintPrefix, setHintPrefix] = useState("");
  const [hintSuffix, setHintSuffix] = useState("");
  const [hintKnownDigits, setHintKnownDigits] = useState("");
  const [hintKnownSpecial, setHintKnownSpecial] = useState("");
  const [hintFragments, setHintFragments] = useState("");
  const [hintMinLen, setHintMinLen] = useState("");
  const [hintMaxLen, setHintMaxLen] = useState("");

  // --- Recovery pipeline state ---
  const [recoverStatus, setRecoverStatus] = useState<RecoverStatus>("idle");
  const [recoverTarget, setRecoverTarget] = useState("");
  const [recoverStrategy, setRecoverStrategy] = useState("all");
  const [recoverCharset, setRecoverCharset] = useState("full");
  const [recoverMinLen, setRecoverMinLen] = useState("8");
  const [recoverMaxLen, setRecoverMaxLen] = useState("16");
  const [recoverThreads, setRecoverThreads] = useState("0");
  const [recoverConcurrent, setRecoverConcurrent] = useState("8");
  const [recoverWordlist, setRecoverWordlist] = useState("");
  const [recoverFormat, setRecoverFormat] = useState("");
  const [recoverSalt, setRecoverSalt] = useState("");
  const [recoverUseFile, setRecoverUseFile] = useState(false);
  const [recoverPassword, setRecoverPassword] = useState<string | null>(null);
  const [recoverMnemonic, setRecoverMnemonic] = useState<string | null>(null);
  const [recoverProgress, setRecoverProgress] = useState<RecoveryProgress | null>(null);
  const [recoverPhase, setRecoverPhase] = useState<string | null>(null);
  const [recoverLogs, setRecoverLogs] = useState<RecoveryLog[]>([]);
  const [recoverError, setRecoverError] = useState<string | null>(null);
  const [recoverIterations, setRecoverIterations] = useState<number | null>(null);
  const [recoverParallel, setRecoverParallel] = useState<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // --- Android Bridge state ---
  const [adbAvailable, setAdbAvailable] = useState<boolean | null>(null);
  const [androidDevices, setAndroidDevices] = useState<AndroidDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState("");
  const [deviceStatus, setDeviceStatus] = useState<AndroidStatus | null>(null);
  const [connectTarget, setConnectTarget] = useState("");
  const [pairingTarget, setPairingTarget] = useState("");
  const [pairingCode, setPairingCode] = useState("");
  const [shellCommand, setShellCommand] = useState("");
  const [shellAsRoot, setShellAsRoot] = useState(false);
  const [shellHistory, setShellHistory] = useState<{ cmd: string; result: ShellOutput }[]>([]);
  const [pullPath, setPullPath] = useState("");
  const [pushLocal, setPushLocal] = useState("");
  const [pushDevice, setPushDevice] = useState("");
  const [androidLoading, setAndroidLoading] = useState<string | null>(null);
  const [androidError, setAndroidError] = useState<string | null>(null);
  const shellEndRef = useRef<HTMLDivElement>(null);

  // --- WiFi Capture Workflow ---
  const [captureIface, setCaptureIface] = useState("wlan0");
  const [capturePackets, setCapturePackets] = useState("10000");
  const [captureFile, setCaptureFile] = useState("/sdcard/capture.pcap");

  // --- Mac Capture ---
  const [macIface, setMacIface] = useState("en0");
  const [macDuration, setMacDuration] = useState("30");
  const [macOutFile, setMacOutFile] = useState("mac-capture.pcap");

  const launchWifiCapture = () => {
    if (!selectedDevice) return;
    window.dispatchEvent(
      new CustomEvent("open-adb-capture", {
        detail: {
          serial: selectedDevice,
          iface: captureIface || "wlan0",
          packets: capturePackets || "10000",
          outFile: captureFile || "/sdcard/capture.pcap",
          title: "WiFi Capture (Root)",
        },
      }),
    );
  };

  const launchTermuxSetup = () => {
    if (!selectedDevice) return;
    window.dispatchEvent(
      new CustomEvent("open-adb-capture", {
        detail: {
          serial: selectedDevice,
          iface: "wlan0",
          packets: "0",
          outFile: "",
          endpoint: "/api/android/termux-setup",
          title: "Termux Setup",
        },
      }),
    );
  };

  const launchMacCapture = () => {
    if (!selectedDevice) return;
    window.dispatchEvent(
      new CustomEvent("open-adb-capture", {
        detail: {
          serial: selectedDevice,
          iface: macIface || "en0",
          packets: "0",
          outFile: macOutFile || "mac-capture.pcap",
          endpoint: "/api/android/mac-capture",
          title: "Mac Capture (No Root)",
          extraBody: {
            macIface: macIface || "en0",
            duration: parseInt(macDuration || "30", 10),
          },
        },
      }),
    );
  };

  // --- ADB auto-polling (every 5s) ---
  const connectedCount = androidDevices.filter(d => d.state === "device").length;
  const adbConnected = connectedCount > 0;

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch("/api/android");
        const data = await res.json();
        if (cancelled) return;
        setAdbAvailable(data.adb_available);
        setAndroidDevices(data.devices || []);
        if (data.devices?.length > 0 && !selectedDevice) {
          setSelectedDevice(data.devices[0].serial);
        }
      } catch { /* silent */ }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [selectedDevice]);

  // --- Select vault from scan results ---
  const selectVaultForRecovery = useCallback((v: VaultResult) => {
    setRecoverTarget(v.file_path);
    setRecoverUseFile(false);
    if (v.iterations > 0) {
      setRecoverIterations(v.iterations);
    }
    if (v.format_id) {
      setRecoverFormat(v.format_id);
    }
    document.getElementById("recovery-section")?.scrollIntoView({ behavior: "smooth" });
  }, []);

  // --- Recovery pipeline ---
  const handleRecover = async () => {
    if (!recoverTarget.trim()) return;

    setRecoverStatus("running");
    setRecoverPassword(null);
    setRecoverMnemonic(null);
    setRecoverProgress(null);
    setRecoverPhase(null);
    setRecoverLogs([]);
    setRecoverError(null);
    setRecoverIterations(null);
    setRecoverParallel(null);

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const payload: Record<string, unknown> = {
      strategy: recoverStrategy,
      charset: recoverCharset,
      min_length: parseInt(hintMinLen || recoverMinLen) || 8,
      max_length: parseInt(hintMaxLen || recoverMaxLen) || 16,
      threads: parseInt(recoverThreads) || 0,
      concurrent: parseInt(recoverConcurrent) || 8,
    };

    if (recoverUseFile) {
      payload.file_path = recoverTarget.trim();
      if (recoverFormat) payload.format = recoverFormat;
      if (recoverSalt) payload.salt = recoverSalt;
    } else {
      payload.vault_path = recoverTarget.trim();
    }

    if (recoverWordlist.trim()) {
      payload.wordlist_path = recoverWordlist.trim();
    }

    // Build profile from the wordlist generator fields
    const profileTokens: Record<string, string[]> = {};
    const names = [firstName, lastName, spouseName].filter(Boolean);
    if (names.length > 0) profileTokens.names = names;
    const words = keywords.split(",").map(k => k.trim()).filter(Boolean);
    if (words.length > 0) profileTokens.words = words;
    const dates = [birthDate].filter(Boolean);
    if (dates.length > 0) profileTokens.dates = dates;
    const partials = [
      city, postalCode, company, phone,
      ...petNames.split(",").map(k => k.trim()).filter(Boolean),
    ].filter(Boolean);
    if (partials.length > 0) profileTokens.partials = partials;
    const oldPws = oldPasswords.split(",").map(k => k.trim()).filter(Boolean);
    if (oldPws.length > 0) profileTokens.oldPasswords = oldPws;
    // hints / fragments
    const hints: Record<string, string | string[]> = {};
    if (hintPrefix.trim()) hints.prefix = hintPrefix.trim();
    if (hintSuffix.trim()) hints.suffix = hintSuffix.trim();
    if (hintKnownDigits.trim()) hints.known_digits = hintKnownDigits.trim();
    if (hintKnownSpecial.trim()) hints.known_special = hintKnownSpecial.trim();
    const frags = hintFragments.split(",").map(f => f.trim()).filter(Boolean);
    if (frags.length > 0) hints.fragments = frags;
    if (hintMinLen.trim()) hints.min_length = hintMinLen.trim();
    if (hintMaxLen.trim()) hints.max_length = hintMaxLen.trim();
    if (Object.keys(hints).length > 0) {
      profileTokens.hints = Object.entries(hints).map(([k, v]) => `${k}:${Array.isArray(v) ? v.join("|") : v}`);
      if (!partials.length) profileTokens.partials = [];
      // merge hint prefix/suffix/fragments into partials for the cracker
      if (hintPrefix.trim()) profileTokens.partials = [...(profileTokens.partials || []), hintPrefix.trim()];
      if (hintSuffix.trim()) profileTokens.partials = [...(profileTokens.partials || []), hintSuffix.trim()];
      frags.forEach(f => { profileTokens.partials = [...(profileTokens.partials || []), f]; });
    }
    if (Object.keys(profileTokens).length > 0) payload.profile = profileTokens;

    try {
      const res = await fetch("/api/passwords/recover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        setRecoverError(err.error || `HTTP ${res.status}`);
        setRecoverStatus("error");
        return;
      }

      const reader = res.body?.getReader();
      if (!reader) {
        setRecoverError("No response stream");
        setRecoverStatus("error");
        return;
      }

      const decoder = new TextDecoder();
      let buffer = "";

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          const eventMatch = part.match(/event:\s*(\S+)/);
          const dataMatch = part.match(/data:\s*(.*)/);
          if (!eventMatch || !dataMatch) continue;

          const event = eventMatch[1];
          let data: Record<string, unknown>;
          try {
            data = JSON.parse(dataMatch[1]);
          } catch {
            continue;
          }

          const logEntry: RecoveryLog = { time: Date.now(), type: event, data };

          switch (event) {
            case "progress":
              setRecoverProgress(data as unknown as RecoveryProgress);
              break;
            case "phase":
              setRecoverPhase(
                typeof data.strategy === "string"
                  ? (data.strategy as string).toUpperCase()
                  : typeof data.name === "string"
                  ? `Phase ${data.phase}: ${data.name}`
                  : "..."
              );
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
            case "phase_done":
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
            case "found":
              setRecoverPassword(data.password as string);
              setRecoverStatus("found");
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
            case "mnemonic":
              setRecoverMnemonic(data.mnemonic as string);
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
            case "not_found":
              setRecoverStatus("not_found");
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
            case "info":
              if (data.iterations) setRecoverIterations(data.iterations as number);
              if (data.total_parallel) setRecoverParallel(data.total_parallel as number);
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
            case "error":
              setRecoverError(data.message as string);
              setRecoverStatus("error");
              break;
            case "done":
              setRecoverStatus(prev => prev === "running" ? "not_found" : prev);
              break;
            case "log":
              setRecoverLogs(prev => [...prev, logEntry]);
              break;
          }

          setTimeout(() => logsEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
        }
      }
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        setRecoverStatus("idle");
      } else {
        setRecoverError(String(err));
        setRecoverStatus("error");
      }
    }
  };

  const handleAbortRecover = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setRecoverStatus("idle");
  };

  // --- Android Bridge helpers ---
  const androidPost = async (action: string, extra: Record<string, unknown> = {}) => {
    const payload: Record<string, unknown> = { action, ...extra };
    if (selectedDevice) payload.serial = selectedDevice;
    const res = await fetch("/api/android", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  };

  const refreshDevices = async () => {
    setAndroidLoading("devices");
    setAndroidError(null);
    try {
      const res = await fetch("/api/android");
      const data = await res.json();
      setAdbAvailable(data.adb_available);
      setAndroidDevices(data.devices || []);
      if (data.devices?.length > 0 && !selectedDevice) {
        setSelectedDevice(data.devices[0].serial);
      }
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  const handleConnect = async () => {
    if (!connectTarget.trim()) return;
    setAndroidLoading("connect");
    setAndroidError(null);
    try {
      await androidPost("connect", { target: connectTarget.trim() });
      await refreshDevices();
      setConnectTarget("");
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  const handlePair = async () => {
    if (!pairingTarget.trim() || !pairingCode.trim()) return;
    setAndroidLoading("pair");
    setAndroidError(null);
    try {
      await androidPost("pair", { target: pairingTarget.trim(), pairing_code: pairingCode.trim() });
      setPairingCode("");
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  const fetchDeviceStatus = async () => {
    setAndroidLoading("status");
    setAndroidError(null);
    try {
      const data = await androidPost("status");
      setDeviceStatus(data);
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  const handleShell = async () => {
    if (!shellCommand.trim()) return;
    setAndroidLoading("shell");
    setAndroidError(null);
    try {
      const data = await androidPost("shell", { command: shellCommand, as_root: shellAsRoot });
      setShellHistory(prev => [...prev, { cmd: `${shellAsRoot ? "# " : "$ "}${shellCommand}`, result: data }]);
      setShellCommand("");
      setTimeout(() => shellEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  const handlePull = async () => {
    if (!pullPath.trim()) return;
    setAndroidLoading("pull");
    setAndroidError(null);
    try {
      const data = await androidPost("pull", { device_path: pullPath.trim() });
      setShellHistory(prev => [...prev, { cmd: `pull ${pullPath}`, result: data }]);
      setPullPath("");
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  const handlePush = async () => {
    if (!pushLocal.trim() || !pushDevice.trim()) return;
    setAndroidLoading("push");
    setAndroidError(null);
    try {
      const data = await androidPost("push", { local_path: pushLocal.trim(), device_path: pushDevice.trim() });
      setShellHistory(prev => [...prev, { cmd: `push ${pushLocal} \u2192 ${pushDevice}`, result: data }]);
      setPushLocal("");
      setPushDevice("");
    } catch (err) {
      setAndroidError(String(err));
    } finally {
      setAndroidLoading(null);
    }
  };

  // --- Vault scan ---
  const handleScan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const params = new URLSearchParams();
      if (extraDirs.trim()) params.set("extra_dirs", extraDirs.trim());
      if (catFilter !== "all") params.set("category", catFilter);
      const res = await fetch(`/api/passwords/scan?${params.toString()}`);
      if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
      const data: ScanResult = await res.json();
      setScanResult(data);
    } catch (err) {
      setScanError(String(err));
    } finally {
      setScanning(false);
    }
  };

  // --- Wordlist generation ---
  const handleGenerate = async () => {
    setGenerating(true);
    setGenError(null);
    try {
      const profile = {
        first_name: firstName,
        last_name: lastName,
        birth_date: birthDate,
        email,
        city,
        postal_code: postalCode,
        keywords: keywords.split(",").map((k) => k.trim()).filter(Boolean),
        old_passwords: oldPasswords.split(",").map((k) => k.trim()).filter(Boolean),
        spouse_name: spouseName,
        pet_names: petNames.split(",").map((k) => k.trim()).filter(Boolean),
        company,
        phone,
        ssid,
        bssid,
        isp,
      };
      const res = await fetch("/api/passwords/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile, web_search: webSearch }),
      });
      if (!res.ok) throw new Error(`Generate failed: ${res.status}`);
      const data: WordlistResult = await res.json();
      setWordlistResult(data);
    } catch (err) {
      setGenError(String(err));
    } finally {
      setGenerating(false);
    }
  };

  const filteredResults = scanResult?.results.filter(
    (r) => catFilter === "all" || r.category === catFilter
  ) ?? [];

  return (
    <main className="px-6 py-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          Passwords
        </h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Vault extraction, smart wordlist generation, and OSINT-powered intelligence.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* ============= LEFT: Vault Scanner ============= */}
        <div className="space-y-4">
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
            <h2 className="text-lg font-bold mb-3 flex items-center gap-2">
              🔍 Vault & Encrypted File Scanner
            </h2>
            <p className="text-xs text-[var(--text-dim)] mb-4">
              Auto-detect encrypted wallets, password managers, SSH keys, and encrypted archives on this system.
            </p>

            {/* Extra dirs */}
            <div className="mb-3">
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Extra directories (comma separated)
              </label>
              <input
                type="text"
                value={extraDirs}
                onChange={(e) => setExtraDirs(e.target.value)}
                placeholder="/mnt/backup, /media/usb"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)]"
              />
            </div>

            {/* Category filter */}
            <div className="mb-4">
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Category filter
              </label>
              <select
                value={catFilter}
                onChange={(e) => setCatFilter(e.target.value)}
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
              >
                <option value="all">All categories</option>
                <option value="crypto_wallet">🪙 Crypto Wallets</option>
                <option value="password_manager">🔐 Password Managers</option>
                <option value="encrypted_file">📦 Encrypted Files</option>
                <option value="ssh_key">🔑 SSH Keys</option>
                <option value="disk_encryption">💽 Disk Encryption</option>
              </select>
            </div>

            <button
              onClick={handleScan}
              disabled={scanning}
              className="w-full py-2.5 text-sm font-medium rounded bg-[var(--accent)] text-white hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              {scanning ? "⏳ Scanning..." : "🔍 Scan System"}
            </button>

            {scanError && (
              <div className="mt-3 p-3 rounded bg-red-900/20 border border-red-800 text-xs text-red-400">
                {scanError}
              </div>
            )}
          </div>

          {/* Scan Results */}
          {scanResult && (
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
              <h3 className="font-bold text-sm mb-3 flex items-center justify-between">
                <span>Found {scanResult.total} items</span>
                <span className="text-xs text-[var(--text-dim)]">
                  {Object.entries(scanResult.categories).map(([cat, count]) => (
                    <span key={cat} className="ml-2">
                      {CAT_ICONS[cat] || "📄"} {count}
                    </span>
                  ))}
                </span>
              </h3>

              {/* Category breakdown */}
              <div className="flex gap-2 mb-4 flex-wrap">
                {Object.entries(scanResult.categories).map(([cat, count]) => (
                  <button
                    key={cat}
                    onClick={() => setCatFilter(cat === catFilter ? "all" : cat)}
                    className={`text-[10px] px-2 py-1 rounded-full font-medium transition-colors ${
                      catFilter === cat
                        ? "ring-1 ring-[var(--accent)]"
                        : ""
                    }`}
                    style={{
                      background: `${CAT_COLORS[cat] || "#666"}20`,
                      color: CAT_COLORS[cat] || "#666",
                    }}
                  >
                    {CAT_ICONS[cat]} {cat.replace("_", " ")} ({count})
                  </button>
                ))}
              </div>

              {/* Results table */}
              <div className="max-h-[400px] overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-[var(--card-bg)]">
                    <tr className="text-left text-[var(--text-dim)] border-b border-[var(--border)]">
                      <th className="py-2">Format</th>
                      <th className="py-2">Path</th>
                      <th className="py-2">KDF / Iterations</th>
                      <th className="py-2 text-right">Size</th>
                      <th className="py-2 text-center">Enc.</th>
                      <th className="py-2 text-center">Crack</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResults.map((r, i) => (
                      <tr key={i} className="border-b border-[var(--border)]/30 hover:bg-[var(--bg)]/50">
                        <td className="py-2">
                          <div className="flex items-center gap-1.5">
                            <span>{CAT_ICONS[r.category] || "📄"}</span>
                            <span className="font-medium">{r.format_name}</span>
                          </div>
                        </td>
                        <td className="py-2 text-[var(--text-dim)] font-mono truncate max-w-[200px]" title={r.file_path}>
                          {r.file_path}
                        </td>
                        <td className="py-2 text-[var(--text-dim)]" title={r.kdf_params || ""}>
                          {r.kdf ? (
                            <div>
                              <span className="text-cyan-400 font-medium">{r.kdf}</span>
                              {r.iterations > 0 && (
                                <span className="text-yellow-400 ml-1">× {r.iterations.toLocaleString()}</span>
                              )}
                            </div>
                          ) : (
                            <span className="text-[var(--text-dim)]">—</span>
                          )}
                        </td>
                        <td className="py-2 text-right text-[var(--text-dim)]">
                          {r.size > 1024 * 1024
                            ? `${(r.size / (1024 * 1024)).toFixed(1)}M`
                            : r.size > 1024
                            ? `${(r.size / 1024).toFixed(0)}K`
                            : `${r.size}B`}
                        </td>
                        <td className="py-2 text-center">
                          {r.encrypted ? (
                            <span className="text-red-400">🔒</span>
                          ) : (
                            <span className="text-green-400">🔓</span>
                          )}
                        </td>
                        <td className="py-2 text-center">
                          {r.encrypted && (
                            <button
                              onClick={() => selectVaultForRecovery(r)}
                              className="text-[10px] px-2 py-0.5 rounded bg-orange-600/20 text-orange-400 hover:bg-orange-600/40 transition-colors"
                              title={r.kdf && r.iterations ? `${r.kdf} × ${r.iterations.toLocaleString()} iterations` : "Send to recovery pipeline"}
                            >
                              ⚡ Crack
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {filteredResults.length === 0 && (
                <p className="text-xs text-[var(--text-dim)] text-center py-4">
                  No items in this category.
                </p>
              )}
            </div>
          )}
        </div>

        {/* ============= RIGHT: Wordlist Generator ============= */}
        <div className="space-y-4">
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
            <h2 className="text-lg font-bold mb-3 flex items-center gap-2">
              🧠 Smart Wordlist Generator
            </h2>
            <p className="text-xs text-[var(--text-dim)] mb-4">
              Build a probability-ranked personalized wordlist using OSINT, PCFG, and Markov chains.
            </p>

            {/* Profile form */}
            <div className="grid grid-cols-2 gap-3 mb-4">
              <Input label="First Name" value={firstName} onChange={setFirstName} placeholder="Jean" />
              <Input label="Last Name" value={lastName} onChange={setLastName} placeholder="Dupont" />
              <Input label="Birth Date" value={birthDate} onChange={setBirthDate} placeholder="15/03/1990" />
              <Input label="Email" value={email} onChange={setEmail} placeholder="jean@example.com" />
              <Input label="City" value={city} onChange={setCity} placeholder="Paris" />
              <Input label="Postal Code" value={postalCode} onChange={setPostalCode} placeholder="75001" />
              <Input label="Spouse Name" value={spouseName} onChange={setSpouseName} placeholder="Marie" />
              <Input label="Company" value={company} onChange={setCompany} placeholder="Acme Inc" />
              <Input label="Phone" value={phone} onChange={setPhone} placeholder="+33612345678" />
              <Input label="Pet Names" value={petNames} onChange={setPetNames} placeholder="Rex, Luna" />
            </div>

            <div className="mb-3">
              <Input label="Keywords (comma separated)" value={keywords} onChange={setKeywords} placeholder="bitcoin, crypto, metamask, soleil" full />
            </div>
            <div className="mb-3">
              <Input label="Old Passwords (comma separated)" value={oldPasswords} onChange={setOldPasswords} placeholder="OldPass123!, Summer2024" full />
            </div>

            {/* WiFi section */}
            <details className="mb-4">
              <summary className="text-xs font-medium text-[var(--text-muted)] cursor-pointer hover:text-[var(--text)]">
                📡 WiFi / ISP Options
              </summary>
              <div className="grid grid-cols-2 gap-3 mt-3">
                <Input label="SSID" value={ssid} onChange={setSsid} placeholder="Livebox-A1B2" />
                <Input label="BSSID" value={bssid} onChange={setBssid} placeholder="AA:BB:CC:DD:EE:FF" />
                <div className="col-span-2">
                  <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">ISP</label>
                  <select
                    value={isp}
                    onChange={(e) => setIsp(e.target.value)}
                    className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                  >
                    <option value="">None</option>
                    <option value="orange">Orange / Livebox</option>
                    <option value="sfr">SFR</option>
                    <option value="bouygues">Bouygues / Bbox</option>
                    <option value="free">Free / Freebox</option>
                  </select>
                </div>
              </div>
            </details>

            {/* Web search toggle */}
            <label className="flex items-center gap-2 mb-4 cursor-pointer">
              <input
                type="checkbox"
                checked={webSearch}
                onChange={(e) => setWebSearch(e.target.checked)}
                className="accent-[var(--accent)]"
              />
              <span className="text-xs">
                🌐 Enable web OSINT search (DuckDuckGo + HIBP)
              </span>
            </label>

            <button
              onClick={handleGenerate}
              disabled={generating || (!firstName && !lastName && !email && !keywords)}
              className="w-full py-2.5 text-sm font-medium rounded bg-purple-600 text-white hover:bg-purple-700 transition-colors disabled:opacity-50"
            >
              {generating ? "⏳ Generating..." : "🧠 Generate Wordlist"}
            </button>

            {genError && (
              <div className="mt-3 p-3 rounded bg-red-900/20 border border-red-800 text-xs text-red-400">
                {genError}
              </div>
            )}
          </div>

          {/* Wordlist Results */}
          {wordlistResult && (
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
              <h3 className="font-bold text-sm mb-3">
                ✅ Generated {wordlistResult.total_candidates.toLocaleString()} candidates
              </h3>

              {/* Stats grid */}
              <div className="grid grid-cols-3 gap-2 mb-4">
                <StatBox label="Profile tokens" value={wordlistResult.stats.profile_tokens} color="#F59E0B" />
                <StatBox label="PCFG structures" value={wordlistResult.stats.pcfg.structure_count} color="#8B5CF6" />
                <StatBox label="Markov contexts" value={wordlistResult.stats.markov.context_count} color="#3B82F6" />
                <StatBox label="Web keywords" value={wordlistResult.web_words_count} color="#06B6D4" />
                <StatBox label="Alphabet size" value={wordlistResult.stats.markov.alphabet_size} color="#10B981" />
                <StatBox label="Total" value={wordlistResult.total_candidates} color="#EF4444" />
              </div>

              {/* Output path */}
              <div className="mb-4 p-2 rounded bg-[var(--bg)] text-xs font-mono text-[var(--text-dim)] truncate" title={wordlistResult.output_path}>
                📁 {wordlistResult.output_filename}
              </div>

              {/* Top 10 preview */}
              <div>
                <h4 className="text-xs font-medium text-[var(--text-muted)] mb-2">Top 10 candidates (highest probability)</h4>
                <div className="space-y-1">
                  {wordlistResult.top_10.map((pw, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs font-mono px-2 py-1 rounded bg-[var(--bg)]/50">
                      <span className="text-[var(--text-dim)] w-4">{i + 1}.</span>
                      <span className="text-[var(--text)]">{pw}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ============= PASSWORD HINTS & FRAGMENTS ============= */}
      <div className="mt-6">
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
          <h2 className="text-lg font-bold mb-1 flex items-center gap-2">
            🧩 Password Hints &amp; Fragments
          </h2>
          <p className="text-xs text-[var(--text-dim)] mb-4">
            Enter any fragments you remember — the recovery engine will prioritize combinations starting
            with these prefixes, containing these digits/characters, and matching this length range.
          </p>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <div>
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Known beginning
              </label>
              <input
                type="text"
                value={hintPrefix}
                onChange={(e) => setHintPrefix(e.target.value)}
                placeholder="Pass, MyP@, 2024"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Known ending
              </label>
              <input
                type="text"
                value={hintSuffix}
                onChange={(e) => setHintSuffix(e.target.value)}
                placeholder="!23, 2024, xyz"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Known digits
              </label>
              <input
                type="text"
                value={hintKnownDigits}
                onChange={(e) => setHintKnownDigits(e.target.value)}
                placeholder="19, 42, 007"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Known special chars
              </label>
              <input
                type="text"
                value={hintKnownSpecial}
                onChange={(e) => setHintKnownSpecial(e.target.value)}
                placeholder="@, !, #, $"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mt-3">
            <div className="lg:col-span-1">
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Other fragments (comma separated)
              </label>
              <input
                type="text"
                value={hintFragments}
                onChange={(e) => setHintFragments(e.target.value)}
                placeholder="crypto, lune, btc, sol"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Estimated min length
              </label>
              <input
                type="number"
                value={hintMinLen}
                onChange={(e) => setHintMinLen(e.target.value)}
                min={1}
                max={64}
                placeholder="8"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)]"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                Estimated max length
              </label>
              <input
                type="number"
                value={hintMaxLen}
                onChange={(e) => setHintMaxLen(e.target.value)}
                min={1}
                max={64}
                placeholder="16"
                className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)]"
              />
            </div>
          </div>

          {/* Summary of active hints */}
          {(hintPrefix || hintSuffix || hintKnownDigits || hintKnownSpecial || hintFragments) && (
            <div className="mt-3 p-3 rounded bg-yellow-900/10 border border-yellow-800/30 text-xs">
              <span className="text-yellow-400 font-medium">Active hints: </span>
              <span className="text-[var(--text-dim)]">
                {[
                  hintPrefix && `starts with "${hintPrefix}"`,
                  hintSuffix && `ends with "${hintSuffix}"`,
                  hintKnownDigits && `contains digits "${hintKnownDigits}"`,
                  hintKnownSpecial && `contains "${hintKnownSpecial}"`,
                  hintFragments && `fragments: ${hintFragments}`,
                  hintMinLen && `min ${hintMinLen} chars`,
                  hintMaxLen && `max ${hintMaxLen} chars`,
                ].filter(Boolean).join(" · ")}
              </span>
              <span className="text-yellow-500 ml-2">
                → auto-included in recovery profile
              </span>
            </div>
          )}
        </div>
      </div>

      {/* ============= BOTTOM: Recovery Pipeline ============= */}
      <div id="recovery-section" className="mt-6">
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
          <h2 className="text-lg font-bold mb-1 flex items-center gap-2">
            ⚡ Password Recovery Pipeline
          </h2>
          <p className="text-xs text-[var(--text-dim)] mb-4">
            Vectorized PBKDF2 cracking engine — 23+ formats, multi-threaded, profile + dictionary + brute-force cascade.
            {recoverTarget && (
              <span className="ml-2 text-orange-400 font-medium">
                Target: {recoverTarget.split("/").pop()}
              </span>
            )}
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* --- Config panel --- */}
            <div className="space-y-3">
              {/* Mode toggle */}
              <div className="flex gap-2 mb-2">
                <button
                  onClick={() => setRecoverUseFile(false)}
                  className={`flex-1 text-xs py-1.5 rounded font-medium transition-colors ${
                    !recoverUseFile
                      ? "bg-orange-600 text-white"
                      : "bg-[var(--bg)] text-[var(--text-dim)] hover:text-[var(--text)]"
                  }`}
                >
                  🪙 Vault JSON
                </button>
                <button
                  onClick={() => setRecoverUseFile(true)}
                  className={`flex-1 text-xs py-1.5 rounded font-medium transition-colors ${
                    recoverUseFile
                      ? "bg-orange-600 text-white"
                      : "bg-[var(--bg)] text-[var(--text-dim)] hover:text-[var(--text)]"
                  }`}
                >
                  📦 Any File (23+)
                </button>
              </div>

              {/* Target path */}
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                  {recoverUseFile ? "Encrypted file path" : "Vault JSON path"}
                </label>
                <input
                  type="text"
                  value={recoverTarget}
                  onChange={(e) => setRecoverTarget(e.target.value)}
                  placeholder={recoverUseFile ? "/path/to/encrypted.kdbx" : "/path/to/vault.json"}
                  className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
                />
              </div>

              {/* Universal mode extras */}
              {recoverUseFile && (
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Format (auto-detect)</label>
                    <input
                      type="text"
                      value={recoverFormat}
                      onChange={(e) => setRecoverFormat(e.target.value)}
                      placeholder="auto"
                      className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)]"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Salt (e.g. email)</label>
                    <input
                      type="text"
                      value={recoverSalt}
                      onChange={(e) => setRecoverSalt(e.target.value)}
                      placeholder="user@email.com"
                      className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)]"
                    />
                  </div>
                </div>
              )}

              {/* Strategy */}
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Strategy</label>
                <select
                  value={recoverStrategy}
                  onChange={(e) => setRecoverStrategy(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                >
                  <option value="all">🔄 All (cascade: profile → dict → brute)</option>
                  <option value="profile">🎯 Profile only (fast)</option>
                  <option value="dictionary">📖 Dictionary only</option>
                  <option value="bruteforce">🔨 Brute-force only</option>
                </select>
              </div>

              {/* Lengths */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Min length</label>
                  <input
                    type="number"
                    value={recoverMinLen}
                    onChange={(e) => setRecoverMinLen(e.target.value)}
                    min={1}
                    max={64}
                    className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Max length</label>
                  <input
                    type="number"
                    value={recoverMaxLen}
                    onChange={(e) => setRecoverMaxLen(e.target.value)}
                    min={1}
                    max={64}
                    className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                  />
                </div>
              </div>

              {/* Charset */}
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Brute-force charset</label>
                <select
                  value={recoverCharset}
                  onChange={(e) => setRecoverCharset(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                >
                  <option value="full">Full (a-z A-Z 0-9 + special)</option>
                  <option value="alphanumeric">Alphanumeric (a-z A-Z 0-9)</option>
                  <option value="alpha">Alpha only (a-z A-Z)</option>
                  <option value="lowercase">Lowercase only (a-z)</option>
                </select>
              </div>

              {/* Performance */}
              <details>
                <summary className="text-xs font-medium text-[var(--text-muted)] cursor-pointer hover:text-[var(--text)]">
                  ⚙️ Performance tuning
                </summary>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <div>
                    <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Threads (0 = auto)</label>
                    <input
                      type="number"
                      value={recoverThreads}
                      onChange={(e) => setRecoverThreads(e.target.value)}
                      min={0}
                      max={64}
                      className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Concurrent/worker</label>
                    <input
                      type="number"
                      value={recoverConcurrent}
                      onChange={(e) => setRecoverConcurrent(e.target.value)}
                      min={1}
                      max={32}
                      className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)]"
                    />
                  </div>
                </div>
              </details>

              {/* Wordlist path */}
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">
                  Custom wordlist (optional)
                </label>
                <input
                  type="text"
                  value={recoverWordlist}
                  onChange={(e) => setRecoverWordlist(e.target.value)}
                  placeholder="/path/to/wordlist.txt"
                  className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
                />
                {wordlistResult?.output_path && (
                  <button
                    onClick={() => setRecoverWordlist(wordlistResult.output_path)}
                    className="mt-1 text-[10px] text-purple-400 hover:text-purple-300 underline"
                  >
                    Use generated wordlist ({wordlistResult.total_candidates.toLocaleString()} candidates)
                  </button>
                )}
              </div>

              {/* Action buttons */}
              <div className="pt-2">
                {recoverStatus !== "running" ? (
                  <button
                    onClick={handleRecover}
                    disabled={!recoverTarget.trim()}
                    className="w-full py-3 text-sm font-bold rounded bg-gradient-to-r from-orange-600 to-red-600 text-white hover:from-orange-500 hover:to-red-500 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    ⚡ Start Recovery
                  </button>
                ) : (
                  <button
                    onClick={handleAbortRecover}
                    className="w-full py-3 text-sm font-bold rounded bg-red-700 text-white hover:bg-red-600 transition-colors"
                  >
                    ⏹ Abort
                  </button>
                )}
              </div>

              <p className="text-[10px] text-[var(--text-dim)]">
                Profile data from the Wordlist Generator + Password Hints sections is automatically included.
              </p>
            </div>

            {/* --- Live status panel --- */}
            <div className="lg:col-span-2 space-y-3">
              {/* Password found banner */}
              {recoverStatus === "found" && recoverPassword && (
                <div className="p-4 rounded-lg bg-green-900/30 border-2 border-green-500 animate-pulse">
                  <div className="text-center mb-2">
                    <span className="text-2xl">🎉</span>
                    <h3 className="text-lg font-bold text-green-400">PASSWORD FOUND!</h3>
                  </div>
                  <div className="bg-black/40 rounded p-3 font-mono text-center">
                    <span className="text-green-300 text-lg select-all">{recoverPassword}</span>
                  </div>
                  {recoverMnemonic && (
                    <div className="mt-3 bg-black/40 rounded p-3">
                      <p className="text-xs text-green-500 mb-1">🌱 Seed Phrase:</p>
                      <p className="font-mono text-sm text-green-300 select-all break-all">{recoverMnemonic}</p>
                    </div>
                  )}
                  <p className="text-xs text-yellow-400 font-bold mt-3 text-center">
                    ⚠️ Write down your seed phrase NOW — do not leave it on screen.
                  </p>
                </div>
              )}

              {/* Not found banner */}
              {recoverStatus === "not_found" && (
                <div className="p-4 rounded-lg bg-red-900/20 border border-red-800 text-center">
                  <span className="text-xl">😞</span>
                  <h3 className="text-sm font-bold text-red-400 mt-1">Password not found</h3>
                  <p className="text-xs text-[var(--text-dim)] mt-1">
                    Try adding more old passwords, keywords, or use a larger wordlist.
                  </p>
                </div>
              )}

              {/* Error */}
              {recoverStatus === "error" && recoverError && (
                <div className="p-3 rounded bg-red-900/20 border border-red-800 text-xs text-red-400">
                  {recoverError}
                </div>
              )}

              {/* Progress stats */}
              {(recoverStatus === "running" || recoverProgress) && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-3 rounded bg-[var(--bg)] text-center">
                    <div className="text-lg font-bold text-orange-400">
                      {recoverProgress?.attempts?.toLocaleString() ?? "—"}
                    </div>
                    <div className="text-[10px] text-[var(--text-dim)]">Attempts</div>
                  </div>
                  <div className="p-3 rounded bg-[var(--bg)] text-center">
                    <div className="text-lg font-bold text-cyan-400">
                      {recoverProgress?.speed?.toFixed(1) ?? "—"}<span className="text-xs">/s</span>
                    </div>
                    <div className="text-[10px] text-[var(--text-dim)]">Speed</div>
                  </div>
                  <div className="p-3 rounded bg-[var(--bg)] text-center">
                    <div className="text-lg font-bold text-purple-400">
                      {recoverProgress?.elapsed_s != null
                        ? recoverProgress.elapsed_s > 3600
                          ? `${(recoverProgress.elapsed_s / 3600).toFixed(1)}h`
                          : recoverProgress.elapsed_s > 60
                          ? `${(recoverProgress.elapsed_s / 60).toFixed(1)}m`
                          : `${recoverProgress.elapsed_s}s`
                        : "—"}
                    </div>
                    <div className="text-[10px] text-[var(--text-dim)]">Elapsed</div>
                  </div>
                  <div className="p-3 rounded bg-[var(--bg)] text-center">
                    <div className="text-lg font-bold text-yellow-400">
                      {recoverPhase ?? "—"}
                    </div>
                    <div className="text-[10px] text-[var(--text-dim)]">Phase</div>
                  </div>
                </div>
              )}

              {/* Vault info — detected KDF + iterations from scan or engine */}
              {(recoverIterations || recoverParallel || recoverFormat) && (
                <div className="flex gap-3 text-xs text-[var(--text-dim)] flex-wrap">
                  {recoverFormat && (
                    <span>📁 Format: <span className="text-cyan-400">{recoverFormat}</span></span>
                  )}
                  {recoverIterations && (
                    <span>🔐 <span className="text-yellow-400">{recoverIterations.toLocaleString()}</span> iterations</span>
                  )}
                  {recoverParallel && (
                    <span>⚡ {recoverParallel} parallel operations</span>
                  )}
                </div>
              )}

              {/* Running spinner */}
              {recoverStatus === "running" && (
                <div className="flex items-center gap-2 text-xs text-orange-400">
                  <span className="animate-spin">⚡</span>
                  <span>Recovery engine running — {recoverPhase || "initializing"}...</span>
                </div>
              )}

              {/* Log output */}
              {recoverLogs.length > 0 && (
                <div className="bg-black/40 rounded-lg border border-[var(--border)]">
                  <div className="px-3 py-2 border-b border-[var(--border)] flex items-center justify-between">
                    <span className="text-xs font-medium text-[var(--text-dim)]">Engine Output</span>
                    <span className="text-[10px] text-[var(--text-dim)]">{recoverLogs.length} events</span>
                  </div>
                  <div className="max-h-[250px] overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
                    {recoverLogs.map((log, i) => (
                      <div key={i} className="flex gap-2">
                        <span className="text-[var(--text-dim)] shrink-0 w-[52px]">
                          {new Date(log.time).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                        </span>
                        <span className={
                          log.type === "found" ? "text-green-400 font-bold" :
                          log.type === "error" ? "text-red-400" :
                          log.type === "phase" ? "text-purple-400" :
                          log.type === "phase_done" ? "text-cyan-400" :
                          log.type === "not_found" ? "text-red-400" :
                          "text-[var(--text-dim)]"
                        }>
                          {log.type === "found" && `🔑 PASSWORD: ${log.data.password}`}
                          {log.type === "mnemonic" && `🌱 SEED: ${log.data.mnemonic}`}
                          {log.type === "phase" && `▶ ${log.data.strategy || log.data.name}${log.data.estimate ? ` — est. ${(log.data.estimate as number).toLocaleString()} candidates` : ""}`}
                          {log.type === "phase_done" && `✓ ${log.data.strategy} — ${(log.data.candidates as number).toLocaleString()} tried in ${log.data.elapsed_s}s (${(log.data.speed as number).toFixed(1)}/s)`}
                          {log.type === "info" && (log.data.iterations ? `🔐 ${(log.data.iterations as number).toLocaleString()} iterations` : `⚡ ${log.data.total_parallel} parallel`)}
                          {log.type === "not_found" && "❌ Password not found"}
                          {log.type === "log" && String(log.data.message)}
                        </span>
                      </div>
                    ))}
                    <div ref={logsEndRef} />
                  </div>
                </div>
              )}

              {/* Idle state */}
              {recoverStatus === "idle" && recoverLogs.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12 text-[var(--text-dim)]">
                  <span className="text-4xl mb-3">🔓</span>
                  <p className="text-sm font-medium">No recovery in progress</p>
                  <p className="text-xs mt-1">
                    Select a vault from scan results or enter a file path, then click <strong>Start Recovery</strong>.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ============= ANDROID ADB BRIDGE ============= */}
      <div id="android-section" className="mt-6">
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
          <h2 className="text-lg font-bold mb-1 flex items-center gap-2">
            📱 Android ADB Bridge
            {adbAvailable !== null && (
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                adbConnected
                  ? "bg-green-500/15 text-green-400 border border-green-500/30"
                  : "bg-red-500/15 text-red-400 border border-red-500/30"
              }`}>
                <span className={`w-2 h-2 rounded-full ${
                  adbConnected
                    ? "bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.6)] animate-pulse"
                    : "bg-red-400"
                }`} />
                {adbConnected
                  ? `${connectedCount} device${connectedCount > 1 ? "s" : ""} connected`
                  : "Disconnected"}
              </span>
            )}
          </h2>
          <p className="text-xs text-[var(--text-dim)] mb-4">
            Remote device management — WiFi handshake capture, file transfer, shell access via wireless ADB.
          </p>

          {adbAvailable === false && (
            <div className="mb-4 p-3 rounded bg-yellow-900/20 border border-yellow-700 text-xs text-yellow-400">
              ⚠️ ADB not found. Install: <code className="bg-black/30 px-1 rounded">brew install android-platform-tools</code>
            </div>
          )}

          {androidError && (
            <div className="mb-4 p-3 rounded bg-red-900/20 border border-red-800 text-xs text-red-400">
              {androidError}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* --- Left: Device Management --- */}
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-[var(--text-muted)]">📡 Devices</h3>

              <button
                onClick={refreshDevices}
                disabled={androidLoading === "devices"}
                className="w-full py-2 text-xs font-medium rounded bg-cyan-600 text-white hover:bg-cyan-700 transition-colors disabled:opacity-50"
              >
                {androidLoading === "devices" ? "⏳ Scanning..." : "🔄 Scan Devices"}
              </button>

              {androidDevices.length > 0 && (
                <div className="space-y-1">
                  {androidDevices.map((d) => (
                    <button
                      key={d.serial}
                      onClick={() => setSelectedDevice(d.serial)}
                      className={`w-full text-left text-xs p-2 rounded transition-colors ${
                        selectedDevice === d.serial
                          ? "bg-cyan-600/20 border border-cyan-500 text-cyan-300"
                          : "bg-[var(--bg)] border border-[var(--border)] hover:border-cyan-600/50"
                      }`}
                    >
                      <div className="font-mono font-medium">{d.serial}</div>
                      <div className="text-[10px] text-[var(--text-dim)]">
                        {d.state === "device" ? "🟢 Online" : d.state === "offline" ? "🔴 Offline" : `⚪ ${d.state}`}
                        {d.info && ` • ${d.info}`}
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {androidDevices.length === 0 && adbAvailable !== null && (
                <p className="text-xs text-[var(--text-dim)] text-center py-2">No devices found.</p>
              )}

              {/* Connect via IP */}
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">Connect (IP:port)</label>
                <div className="flex gap-1">
                  <input
                    type="text"
                    value={connectTarget}
                    onChange={(e) => setConnectTarget(e.target.value)}
                    placeholder="192.168.1.100:5555"
                    className="flex-1 px-2 py-1.5 text-xs rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
                  />
                  <button
                    onClick={handleConnect}
                    disabled={androidLoading === "connect" || !connectTarget.trim()}
                    className="px-3 py-1.5 text-xs rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-50"
                  >
                    {androidLoading === "connect" ? "..." : "➜"}
                  </button>
                </div>
              </div>

              {/* Wireless Pairing */}
              <details>
                <summary className="text-xs font-medium text-[var(--text-muted)] cursor-pointer hover:text-[var(--text)]">
                  🔗 Wireless Pairing
                </summary>
                <div className="mt-2 space-y-2">
                  <input
                    type="text"
                    value={pairingTarget}
                    onChange={(e) => setPairingTarget(e.target.value)}
                    placeholder="IP:port from pairing dialog"
                    className="w-full px-2 py-1.5 text-xs rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
                  />
                  <input
                    type="text"
                    value={pairingCode}
                    onChange={(e) => setPairingCode(e.target.value)}
                    placeholder="6-digit code"
                    maxLength={6}
                    className="w-full px-2 py-1.5 text-xs rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
                  />
                  <button
                    onClick={handlePair}
                    disabled={androidLoading === "pair" || !pairingTarget.trim() || !pairingCode.trim()}
                    className="w-full py-1.5 text-xs rounded bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-50"
                  >
                    {androidLoading === "pair" ? "⏳ Pairing..." : "🔗 Pair Device"}
                  </button>
                </div>
              </details>

              {/* Device Status */}
              {selectedDevice && (
                <div>
                  <button
                    onClick={fetchDeviceStatus}
                    disabled={androidLoading === "status"}
                    className="w-full py-1.5 text-xs font-medium rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text)] hover:border-cyan-600/50 transition-colors disabled:opacity-50"
                  >
                    {androidLoading === "status" ? "⏳ Loading..." : "ℹ️ Get Device Info"}
                  </button>
                  {deviceStatus && (
                    <div className="mt-2 grid grid-cols-2 gap-1 text-[10px]">
                      <div className="p-1.5 rounded bg-[var(--bg)]">
                        <span className="text-[var(--text-dim)]">Model:</span>{" "}
                        <span className="font-medium">{deviceStatus.model || "—"}</span>
                      </div>
                      <div className="p-1.5 rounded bg-[var(--bg)]">
                        <span className="text-[var(--text-dim)]">Android:</span>{" "}
                        <span className="font-medium">{deviceStatus.android_version || "—"}</span>
                      </div>
                      <div className="p-1.5 rounded bg-[var(--bg)]">
                        <span className="text-[var(--text-dim)]">Root:</span>{" "}
                        <span className={deviceStatus.rooted ? "text-red-400 font-bold" : "text-green-400"}>
                          {deviceStatus.rooted ? "Yes ⚡" : "No"}
                        </span>
                      </div>
                      <div className="p-1.5 rounded bg-[var(--bg)]">
                        <span className="text-[var(--text-dim)]">Ifaces:</span>{" "}
                        <span className="font-medium">{(deviceStatus.interfaces.match(/^\d+:\s+(\w+)/gm) || []).length}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* --- Right: Shell & File Transfer --- */}
            <div className="lg:col-span-2 space-y-3">
              <h3 className="text-sm font-bold text-[var(--text-muted)]">💻 Shell</h3>
              <div className="flex gap-1">
                <input
                  type="text"
                  value={shellCommand}
                  onChange={(e) => setShellCommand(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleShell()}
                  placeholder={selectedDevice ? "ls /sdcard/DCIM" : "Select a device first"}
                  disabled={!selectedDevice}
                  className="flex-1 px-3 py-2 text-sm rounded bg-black/40 border border-[var(--border)] text-green-400 placeholder-[var(--text-dim)] font-mono disabled:opacity-40"
                />
                <label className="flex items-center gap-1 px-2 text-[10px] text-[var(--text-dim)] cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={shellAsRoot}
                    onChange={(e) => setShellAsRoot(e.target.checked)}
                    className="accent-red-500"
                  />
                  root
                </label>
                <button
                  onClick={handleShell}
                  disabled={androidLoading === "shell" || !selectedDevice || !shellCommand.trim()}
                  className="px-4 py-2 text-sm rounded bg-green-700 text-white hover:bg-green-600 disabled:opacity-40 font-mono"
                >
                  {androidLoading === "shell" ? "..." : "▶"}
                </button>
              </div>

              {shellHistory.length > 0 && (
                <div className="bg-black/40 rounded-lg border border-[var(--border)] max-h-[300px] overflow-y-auto p-3 space-y-2 font-mono text-xs">
                  {shellHistory.map((entry, i) => (
                    <div key={i}>
                      <div className="text-green-500">{entry.cmd}</div>
                      {entry.result.stdout && (
                        <pre className="text-[var(--text-dim)] whitespace-pre-wrap break-all">{entry.result.stdout}</pre>
                      )}
                      {entry.result.stderr && (
                        <pre className="text-red-400 whitespace-pre-wrap break-all">{entry.result.stderr}</pre>
                      )}
                      {!entry.result.ok && (
                        <div className="text-red-500 text-[10px]">exit code: {entry.result.code}</div>
                      )}
                    </div>
                  ))}
                  <div ref={shellEndRef} />
                </div>
              )}

              {/* File Transfer */}
              <h3 className="text-sm font-bold text-[var(--text-muted)] pt-2">📁 File Transfer</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded bg-[var(--bg)] border border-[var(--border)]">
                  <label className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider mb-2 block">
                    ⬇ Pull from device
                  </label>
                  <input
                    type="text"
                    value={pullPath}
                    onChange={(e) => setPullPath(e.target.value)}
                    placeholder="/sdcard/captures/wpa.cap"
                    disabled={!selectedDevice}
                    className="w-full px-2 py-1.5 text-xs rounded bg-[var(--card-bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono mb-2 disabled:opacity-40"
                  />
                  <button
                    onClick={handlePull}
                    disabled={androidLoading === "pull" || !selectedDevice || !pullPath.trim()}
                    className="w-full py-1.5 text-xs rounded bg-cyan-700 text-white hover:bg-cyan-600 disabled:opacity-50"
                  >
                    {androidLoading === "pull" ? "⏳ Pulling..." : "⬇ Pull File"}
                  </button>
                </div>

                <div className="p-3 rounded bg-[var(--bg)] border border-[var(--border)]">
                  <label className="text-[10px] font-bold text-orange-400 uppercase tracking-wider mb-2 block">
                    ⬆ Push to device
                  </label>
                  <input
                    type="text"
                    value={pushLocal}
                    onChange={(e) => setPushLocal(e.target.value)}
                    placeholder="reports/wordlist.txt"
                    disabled={!selectedDevice}
                    className="w-full px-2 py-1.5 text-xs rounded bg-[var(--card-bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono mb-1 disabled:opacity-40"
                  />
                  <input
                    type="text"
                    value={pushDevice}
                    onChange={(e) => setPushDevice(e.target.value)}
                    placeholder="/sdcard/Download/"
                    disabled={!selectedDevice}
                    className="w-full px-2 py-1.5 text-xs rounded bg-[var(--card-bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)] font-mono mb-2 disabled:opacity-40"
                  />
                  <button
                    onClick={handlePush}
                    disabled={androidLoading === "push" || !selectedDevice || !pushLocal.trim() || !pushDevice.trim()}
                    className="w-full py-1.5 text-xs rounded bg-orange-700 text-white hover:bg-orange-600 disabled:opacity-50"
                  >
                    {androidLoading === "push" ? "⏳ Pushing..." : "⬆ Push File"}
                  </button>
                </div>
              </div>

              {/* ═══ WiFi Capture Workflows ═══ */}
              <div className="space-y-2 pt-1">
                <h3 className="text-xs font-bold text-[var(--text-muted)] flex items-center gap-2">
                  📡 WiFi Capture Workflows
                  <span className="text-[9px] font-normal text-[var(--text-dim)]">— choisis ta méthode</span>
                </h3>

                {/* ── Tutorial 1: Termux Setup (Root) ── */}
                <details>
                  <summary className="text-xs font-medium text-orange-400 cursor-pointer hover:text-orange-300 flex items-center gap-2">
                    <span className="text-sm">📲</span> Tutorial 1 — Préparer Termux sur le téléphone
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-300">root requis</span>
                  </summary>
                  <div className="mt-2 p-3 rounded bg-gradient-to-br from-orange-950/20 to-[var(--bg)] border border-orange-800/30 text-xs space-y-3">
                    {/* Where it runs */}
                    <div className="flex gap-2 items-start">
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-orange-900/30 border border-orange-700/40 text-[10px] text-orange-300 shrink-0">
                        📱 S&apos;exécute sur le téléphone
                      </div>
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-blue-900/20 border border-blue-700/30 text-[10px] text-blue-300 shrink-0">
                        💻 Piloté depuis ce Mac via ADB
                      </div>
                    </div>
                    <p className="text-[var(--text-dim)]">
                      <strong>Pré-requis :</strong> Le téléphone doit être <span className="text-red-300">rooté</span> (Magisk) et avoir <span className="text-orange-300">Termux</span> installé (F-Droid).
                    </p>
                    <p className="text-[var(--text-dim)]">
                      Ce workflow installe automatiquement <code className="text-orange-300">tcpdump</code>, <code className="text-orange-300">tsu</code> et <code className="text-orange-300">wireless-tools</code>
                      directement sur le téléphone via Termux. Tu n&apos;as rien à taper — le Mac envoie les commandes via ADB.
                    </p>
                    <div className="bg-black/30 rounded p-2 font-mono text-[10px] space-y-0.5">
                      <div className="text-orange-300/50 mb-1"># Commandes exécutées sur le 📱 téléphone via ADB :</div>
                      <div className="text-[var(--text-dim)]">$ pkg update -y</div>
                      <div className="text-[var(--text-dim)]">$ pkg install root-repo tsu tcpdump wireless-tools -y</div>
                      <div className="text-[var(--text-dim)]">$ tsu    <span className="text-red-300"># → active root via Magisk</span></div>
                      <div className="text-[var(--text-dim)]">$ tcpdump --version  <span className="text-green-300"># → vérifie l&apos;installation</span></div>
                    </div>
                    <button
                      onClick={launchTermuxSetup}
                      disabled={!selectedDevice}
                      className="w-full py-2 text-xs font-bold rounded transition-colors bg-orange-600 text-white hover:bg-orange-700 disabled:opacity-40 flex items-center justify-center gap-2"
                    >
                      <span>🐕</span> Lancer le Setup Termux dans le Terminal
                    </button>
                    <p className="text-yellow-400 text-[10px]">
                      ⚠️ Si ton téléphone n&apos;est PAS rooté → passe directement au Tutorial 2 (sans root).
                    </p>
                  </div>
                </details>

                {/* ── Tutorial 2: Mac-side Capture (No Root) ── */}
                <details>
                  <summary className="text-xs font-medium text-cyan-400 cursor-pointer hover:text-cyan-300 flex items-center gap-2">
                    <span className="text-sm">💻</span> Tutorial 2 — Capturer le trafic depuis le Mac (sans root)
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-300">sans root ✅</span>
                  </summary>
                  <div className="mt-2 p-3 rounded bg-gradient-to-br from-cyan-950/20 to-[var(--bg)] border border-cyan-800/30 text-xs space-y-3">
                    {/* Where it runs */}
                    <div className="flex gap-2 items-start">
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-cyan-900/30 border border-cyan-700/40 text-[10px] text-cyan-300 shrink-0">
                        💻 S&apos;exécute sur ce Mac
                      </div>
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-green-900/20 border border-green-700/30 text-[10px] text-green-300 shrink-0">
                        📱 Téléphone non modifié
                      </div>
                    </div>

                    <div className="bg-cyan-900/10 border border-cyan-800/30 rounded p-2.5 text-[var(--text)]">
                      <strong className="text-cyan-300">Comment ça marche :</strong>
                      <ol className="list-decimal list-inside mt-1 space-y-0.5 text-[var(--text-dim)]">
                        <li>Le Mac demande l&apos;IP du téléphone via ADB <span className="text-[var(--text-dim)]">(commande envoyée au tel)</span></li>
                        <li>Le Mac lance <code className="text-cyan-300">tcpdump</code> <strong className="text-cyan-200">sur lui-même</strong> en filtrant l&apos;IP du téléphone</li>
                        <li>Tout le trafic réseau qui passe entre le téléphone et le réseau WiFi est capturé</li>
                        <li>Le fichier <code className="text-cyan-300">.pcap</code> est sauvegardé <strong className="text-cyan-200">sur le Mac</strong> dans <code className="text-[var(--text-dim)]">reports/android/</code></li>
                      </ol>
                    </div>

                    <div className="grid grid-cols-3 gap-2">
                      <div>
                        <label className="text-[10px] text-[var(--text-dim)] block mb-0.5">Interface Mac (WiFi)</label>
                        <input
                          type="text" value={macIface} onChange={e => setMacIface(e.target.value)}
                          className="w-full px-2 py-1 text-xs rounded bg-black/30 border border-[var(--border)] text-[var(--text)] font-mono"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-[var(--text-dim)] block mb-0.5">Durée capture (sec)</label>
                        <input
                          type="text" value={macDuration} onChange={e => setMacDuration(e.target.value)}
                          className="w-full px-2 py-1 text-xs rounded bg-black/30 border border-[var(--border)] text-[var(--text)] font-mono"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-[var(--text-dim)] block mb-0.5">Fichier .pcap (sur le Mac)</label>
                        <input
                          type="text" value={macOutFile} onChange={e => setMacOutFile(e.target.value)}
                          className="w-full px-2 py-1 text-xs rounded bg-black/30 border border-[var(--border)] text-[var(--text)] font-mono"
                        />
                      </div>
                    </div>
                    <div className="bg-black/30 rounded p-2 font-mono text-[10px] space-y-0.5">
                      <div className="text-cyan-300/50 mb-1"># Ce qui va se passer quand tu cliques :</div>
                      <div className="text-[var(--text-dim)]"><span className="text-cyan-300">1.</span> 💻 Mac vérifie que tcpdump est installé</div>
                      <div className="text-[var(--text-dim)]"><span className="text-cyan-300">2.</span> 📱→💻 Récupère l&apos;IP du téléphone via ADB</div>
                      <div className="text-[var(--text-dim)]"><span className="text-cyan-300">3.</span> 💻 Vérifie l&apos;interface réseau {macIface || "en0"}</div>
                      <div className="text-[var(--text-dim)]"><span className="text-cyan-300">4.</span> 💻 Ping le téléphone pour vérifier la connectivité</div>
                      <div className="text-[var(--text-dim)]"><span className="text-cyan-300">5.</span> 💻 Lance tcpdump pendant {macDuration || "30"}s → <span className="text-green-300">{macOutFile || "mac-capture.pcap"}</span></div>
                      <div className="text-[var(--text-dim)]"><span className="text-cyan-300">6.</span> 💻 Résumé + commandes Wireshark pour ouvrir le fichier</div>
                    </div>
                    <button
                      onClick={launchMacCapture}
                      disabled={!selectedDevice}
                      className="w-full py-2 text-xs font-bold rounded transition-colors bg-cyan-600 text-white hover:bg-cyan-700 disabled:opacity-40 flex items-center justify-center gap-2"
                    >
                      <span>🐕</span> Lancer la Capture Mac dans le Terminal
                    </button>
                    <p className="text-green-400 text-[10px]">
                      ✅ Rien à installer ni modifier sur le téléphone. Tout se passe sur ton Mac. Utilise le WiFi pendant la capture pour générer du trafic.
                    </p>
                  </div>
                </details>

                {/* ── Original: Full Root WiFi Capture ── */}
                <details>
                  <summary className="text-xs font-medium text-purple-400 cursor-pointer hover:text-purple-300 flex items-center gap-2">
                    <span className="text-sm">📡</span> Capture WiFi Complète sur le téléphone (Root + Monitor Mode)
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-300">root + tcpdump</span>
                  </summary>
                  <div className="mt-2 p-3 rounded bg-gradient-to-br from-purple-950/20 to-[var(--bg)] border border-purple-800/30 text-xs space-y-3">
                    {/* Where it runs */}
                    <div className="flex gap-2 items-start">
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-purple-900/30 border border-purple-700/40 text-[10px] text-purple-300 shrink-0">
                        📱 S&apos;exécute sur le téléphone
                      </div>
                      <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-red-900/20 border border-red-700/30 text-[10px] text-red-300 shrink-0">
                        ⚠️ Nécessite Tutorial 1 terminé
                      </div>
                    </div>
                    <p className="text-[var(--text-dim)]">
                      Pipeline complète <strong className="text-purple-300">sur le téléphone</strong> : détecte les interfaces WiFi → vérifie tcpdump → active le monitor mode → capture les paquets → pull le .pcap vers le Mac.
                    </p>
                    <div className="grid grid-cols-3 gap-2">
                      <div>
                        <label className="text-[10px] text-[var(--text-dim)] block mb-0.5">Interface</label>
                        <input
                          type="text" value={captureIface} onChange={e => setCaptureIface(e.target.value)}
                          className="w-full px-2 py-1 text-xs rounded bg-black/30 border border-[var(--border)] text-[var(--text)] font-mono"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-[var(--text-dim)] block mb-0.5">Packets</label>
                        <input
                          type="text" value={capturePackets} onChange={e => setCapturePackets(e.target.value)}
                          className="w-full px-2 py-1 text-xs rounded bg-black/30 border border-[var(--border)] text-[var(--text)] font-mono"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-[var(--text-dim)] block mb-0.5">Output file</label>
                        <input
                          type="text" value={captureFile} onChange={e => setCaptureFile(e.target.value)}
                          className="w-full px-2 py-1 text-xs rounded bg-black/30 border border-[var(--border)] text-[var(--text)] font-mono"
                        />
                      </div>
                    </div>
                    <button
                      onClick={launchWifiCapture}
                      disabled={!selectedDevice}
                      className="w-full py-2 text-xs font-bold rounded transition-colors bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-40 flex items-center justify-center gap-2"
                    >
                      <span>🐕</span> Lancer la Capture WiFi dans le Terminal
                    </button>
                    <p className="text-yellow-400 text-[10px]">
                      ⚠️ Requires rooted device with tcpdump. Monitor mode depends on chipset.
                    </p>
                  </div>
                </details>
              </div>

              {/* No device idle state */}
              {!selectedDevice && androidDevices.length === 0 && adbAvailable === null && (
                <div className="flex flex-col items-center justify-center py-8 text-[var(--text-dim)]">
                  <span className="text-3xl mb-2">📱</span>
                  <p className="text-sm font-medium">No device connected</p>
                  <p className="text-xs mt-1">
                    Click <strong>Scan Devices</strong> or connect via IP to get started.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function Input({
  label,
  value,
  onChange,
  placeholder,
  full,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  full?: boolean;
}) {
  return (
    <div className={full ? "col-span-2" : ""}>
      <label className="text-xs font-medium text-[var(--text-muted)] mb-1 block">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-3 py-2 text-sm rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text)] placeholder-[var(--text-dim)]"
      />
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="p-2 rounded bg-[var(--bg)] text-center">
      <div className="text-lg font-bold" style={{ color }}>
        {value.toLocaleString()}
      </div>
      <div className="text-[10px] text-[var(--text-dim)]">{label}</div>
    </div>
  );
}
