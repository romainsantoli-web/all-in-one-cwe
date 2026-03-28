// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";
import PixelDog from "@/components/PixelDog";
import TerminalOverlay from "@/components/TerminalOverlay";

/**
 * Terminal bubble — always visible floating pixel dog + overlay.
 * Mounted in the root layout so it persists across pages.
 */
export default function TerminalBubble() {
  const [isOpen, setIsOpen] = useState(false);
  const [activeCount, setActiveCount] = useState(0);

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

  const toggleOverlay = useCallback(() => {
    setIsOpen((prev) => !prev);
  }, []);

  const closeOverlay = useCallback(() => {
    setIsOpen(false);
  }, []);

  return (
    <>
      {/* Floating pixel dog — always visible */}
      {!isOpen && (
        <PixelDog onClick={toggleOverlay} activeCount={activeCount} />
      )}

      {/* Terminal overlay */}
      <TerminalOverlay isOpen={isOpen} onClose={closeOverlay} />
    </>
  );
}
