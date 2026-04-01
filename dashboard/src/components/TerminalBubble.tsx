// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";
import PixelDog from "@/components/PixelDog";
import TerminalOverlay from "@/components/TerminalOverlay";

export interface AdbCaptureConfig {
  serial: string;
  iface: string;
  packets: string;
  outFile: string;
  /** API endpoint to POST to (default: /api/android/capture) */
  endpoint?: string;
  /** Title shown in the terminal overlay titlebar */
  title?: string;
  /** Extra body fields to include in the POST request */
  extraBody?: Record<string, unknown>;
}

/**
 * Terminal bubble — always visible floating pixel dog + overlay.
 * Mounted in the root layout so it persists across pages.
 */
export default function TerminalBubble() {
  const [isOpen, setIsOpen] = useState(false);
  const [activeCount, setActiveCount] = useState(0);
  const [adbCapture, setAdbCapture] = useState<AdbCaptureConfig | null>(null);

  // Poll running terminal + AI session count for the dog badge
  const fetchCount = useCallback(async () => {
    try {
      const [scanRes, aiRes] = await Promise.all([
        fetch("/api/terminals"),
        fetch("/api/terminals/ai-session"),
      ]);
      const scanData = await scanRes.json();
      const aiData = await aiRes.json();
      const scanRunning = ((scanData.terminals || []) as Array<{ status: string }>)
        .filter((t) => t.status === "running").length;
      const aiRunning = ((aiData.sessions || []) as Array<{ status: string }>)
        .filter((s) => s.status === "running").length;
      setActiveCount(scanRunning + aiRunning);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchCount();
    const interval = setInterval(fetchCount, 3000);
    return () => clearInterval(interval);
  }, [fetchCount]);

  // Listen for ADB capture requests from other pages
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<AdbCaptureConfig>).detail;
      if (detail) {
        setAdbCapture(detail);
        setIsOpen(true);
      }
    };
    window.addEventListener("open-adb-capture", handler);
    return () => window.removeEventListener("open-adb-capture", handler);
  }, []);

  const toggleOverlay = useCallback(() => {
    setIsOpen((prev) => !prev);
  }, []);

  const closeOverlay = useCallback(() => {
    setIsOpen(false);
    setAdbCapture(null);
  }, []);

  return (
    <>
      {/* Floating pixel dog — always visible */}
      {!isOpen && (
        <PixelDog onClick={toggleOverlay} activeCount={activeCount} />
      )}

      {/* Terminal overlay */}
      <TerminalOverlay isOpen={isOpen} onClose={closeOverlay} adbCapture={adbCapture} />
    </>
  );
}
