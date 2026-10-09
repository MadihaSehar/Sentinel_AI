import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "SentinelAI",
  description: "AI-Powered Web Security Assessment & Vulnerability Intelligence Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="flex bg-slate-950 text-slate-100 antialiased">
        <Sidebar />
        <main className="min-h-screen flex-1 overflow-y-auto">{children}</main>
      </body>
    </html>
  );
}
