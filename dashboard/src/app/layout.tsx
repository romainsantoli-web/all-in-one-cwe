// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import TerminalBubble from "@/components/TerminalBubble";

export const metadata: Metadata = {
  title: "Security Dashboard — All-in-One CWE",
  description: "Security scan results viewer — severity, CWE, tool breakdown",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen antialiased">
        <Sidebar />
        <div className="main-content">{children}</div>
        <TerminalBubble />
      </body>
    </html>
  );
}
