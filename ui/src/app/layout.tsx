import type { Metadata } from "next";
import "./globals.css";
import { Topbar } from "@/components/topbar";
import { VerifyProvider } from "@/lib/verify-context";

// Resolve theme before paint: a saved toggle choice wins, otherwise default to
// light. Mirror the choice onto both `data-theme` (tokens) and the `.dark` class.
const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem('theme');if(t!=='light'&&t!=='dark'){t='light';}var d=document.documentElement;d.dataset.theme=t;d.classList.toggle('dark',t==='dark');}catch(e){document.documentElement.dataset.theme='light';}})();`;

export const metadata: Metadata = {
  title: "codex-security · attested console",
  description:
    "Verify in your browser that the codex-security scan API is a genuine Intel TDX enclave running the image you pinned, then submit scans through the channel that verification established.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="antialiased">
        {/* One provider above both pages: the session established on the trust
            page is the same session the scan page speaks over. */}
        <VerifyProvider>
          <Topbar />
          {children}
        </VerifyProvider>
      </body>
    </html>
  );
}
