import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "codex-security · attested console",
  description:
    "Submit codex-security scans to a confidential cluster, after verifying in your own browser that it is a genuine Intel TDX enclave running the image you pinned.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
