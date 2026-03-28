// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";

interface PixelDogProps {
  onClick: () => void;
  activeCount: number;
}

/**
 * Pixel-art dog tamagotchi that floats in the bottom-right corner.
 * Animates between idle/happy/alert states. Click to open terminal overlay.
 */
export default function PixelDog({ onClick, activeCount }: PixelDogProps) {
  const [frame, setFrame] = useState(0);
  const [mood, setMood] = useState<"idle" | "happy" | "alert">("idle");
  const [bounce, setBounce] = useState(false);

  // Mood based on active terminals
  useEffect(() => {
    if (activeCount > 2) setMood("alert");
    else if (activeCount > 0) setMood("happy");
    else setMood("idle");
  }, [activeCount]);

  // Animation loop — 3 frames
  useEffect(() => {
    const id = setInterval(() => setFrame((f) => (f + 1) % 4), 600);
    return () => clearInterval(id);
  }, []);

  // Bounce on click
  const handleClick = useCallback(() => {
    setBounce(true);
    setTimeout(() => setBounce(false), 300);
    onClick();
  }, [onClick]);

  // Pixel dog frames rendered as inline SVG for crisp pixels
  const tailWag = frame % 2 === 0;
  const earWiggle = frame % 3 === 0;
  const eyeBlink = frame === 3;

  const moodColor = mood === "alert" ? "#ef4444" : mood === "happy" ? "#22c55e" : "#6366f1";
  const bodyColor = "#c4a882";
  const darkColor = "#8b6f47";
  const noseColor = "#2a2a2a";

  return (
    <button
      onClick={handleClick}
      className="pixel-dog-bubble"
      style={{
        transform: bounce ? "scale(1.2)" : "scale(1)",
        transition: "transform 0.15s cubic-bezier(0.34, 1.56, 0.64, 1)",
      }}
      title={`${activeCount} active terminal${activeCount !== 1 ? "s" : ""} — click to open`}
      aria-label="Open terminal overlay"
    >
      {/* Pixel dog SVG — 16x16 grid scaled up */}
      <svg
        width="56"
        height="56"
        viewBox="0 0 16 16"
        style={{ imageRendering: "pixelated" }}
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Ears */}
        <rect x="3" y={earWiggle ? "1" : "2"} width="2" height="3" fill={darkColor} rx="0" />
        <rect x="11" y={earWiggle ? "1" : "2"} width="2" height="3" fill={darkColor} rx="0" />

        {/* Head */}
        <rect x="4" y="3" width="8" height="6" fill={bodyColor} rx="0" />

        {/* Eyes */}
        {eyeBlink ? (
          <>
            <rect x="5" y="5" width="2" height="1" fill={noseColor} />
            <rect x="9" y="5" width="2" height="1" fill={noseColor} />
          </>
        ) : (
          <>
            <rect x="5" y="4" width="2" height="2" fill="white" />
            <rect x="6" y="5" width="1" height="1" fill={noseColor} />
            <rect x="9" y="4" width="2" height="2" fill="white" />
            <rect x="10" y="5" width="1" height="1" fill={noseColor} />
          </>
        )}

        {/* Nose */}
        <rect x="7" y="6" width="2" height="1" fill={noseColor} />

        {/* Mouth — mood based */}
        {mood === "happy" || mood === "alert" ? (
          <>
            <rect x="6" y="7" width="1" height="1" fill={noseColor} />
            <rect x="7" y="8" width="2" height="1" fill={noseColor} />
            <rect x="9" y="7" width="1" height="1" fill={noseColor} />
          </>
        ) : (
          <rect x="7" y="7" width="2" height="1" fill={noseColor} />
        )}

        {/* Body */}
        <rect x="5" y="9" width="6" height="4" fill={bodyColor} />
        <rect x="6" y="9" width="4" height="1" fill={darkColor} />

        {/* Legs */}
        <rect x="5" y="13" width="2" height="2" fill={darkColor} />
        <rect x="9" y="13" width="2" height="2" fill={darkColor} />

        {/* Tail */}
        <rect
          x={tailWag ? "11" : "12"}
          y={tailWag ? "9" : "10"}
          width="2"
          height="2"
          fill={darkColor}
        />

        {/* Collar */}
        <rect x="5" y="9" width="6" height="1" fill={moodColor} />
      </svg>

      {/* Badge for active count */}
      {activeCount > 0 && (
        <span className="pixel-dog-badge">
          {activeCount}
        </span>
      )}

      {/* Speech bubble on hover */}
      <span className="pixel-dog-speech">
        {mood === "alert" ? "🔥 Busy!" : mood === "happy" ? "▶ Running" : "zzZ"}
      </span>
    </button>
  );
}
