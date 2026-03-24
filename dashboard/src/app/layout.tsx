import type { Metadata } from "next";
import "./globals.css";

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
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
