"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { Menu, X } from "lucide-react";
import ProtectedLayout from "@/components/ProtectedLayout";
import SettingsSidebar from "./components/Sidebar";

export default function SettingsLayout({ children }) {
  const pathname = usePathname();
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [desktopSidebarOpen, setDesktopSidebarOpen] = useState(false);

  const toggleMobileSidebar = () => setMobileSidebarOpen((prev) => !prev);
  const closeMobileSidebar = () => setMobileSidebarOpen(false);
  const showFloatingMenuButton = pathname !== "/settings";

  useEffect(() => {
    const handleMobileSidebarToggle = () => {
      setMobileSidebarOpen((prev) => !prev);
    };

    window.addEventListener("settings:toggle-mobile-sidebar", handleMobileSidebarToggle);
    return () => {
      window.removeEventListener("settings:toggle-mobile-sidebar", handleMobileSidebarToggle);
    };
  }, []);

  return (
    <ProtectedLayout>
      <div className="relative flex h-screen overflow-hidden bg-[var(--bg)] p-3 gap-3">
        {showFloatingMenuButton && (
          <button
            type="button"
            onClick={toggleMobileSidebar}
            aria-label={mobileSidebarOpen ? "Close settings sidebar" : "Open settings sidebar"}
            className="sm:hidden fixed top-4 left-4 z-[60] inline-flex h-10 w-10 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface)] text-[var(--text)] backdrop-blur-xl transition-colors hover:brightness-110"
          >
            {mobileSidebarOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        )}

        <aside
          aria-label="Settings navigation"
          className={`
            hidden sm:flex shrink-0 h-full bg-transparent
            transition-all duration-300 ease-in-out
            ${desktopSidebarOpen ? "w-[272px]" : "w-[72px]"}
          `}
        >
          <SettingsSidebar
            isOpen={desktopSidebarOpen}
            showToggle={true}
            onToggle={() => setDesktopSidebarOpen((prev) => !prev)}
          />
        </aside>

        <aside
          aria-label="Settings mobile navigation"
          className={`
            fixed sm:hidden top-0 left-0 z-50 h-full w-64 p-2.5
            bg-transparent
            transform transition-transform duration-300 ease-in-out
            ${mobileSidebarOpen ? "translate-x-0" : "-translate-x-full"}
          `}
        >
          <SettingsSidebar isOpen={true} />
        </aside>

        {mobileSidebarOpen && (
          <div
            onClick={closeMobileSidebar}
            className="fixed inset-0 z-40 sm:hidden bg-black/40 backdrop-blur-sm"
          />
        )}

        <div className="flex min-w-0 flex-1 flex-col overflow-y-auto custom-scrollbar rounded-2xl border border-[var(--border)] bg-[var(--card-bg)]">
          <main
            id="main-content"
            aria-label="Settings"
            className="h-full min-h-0"
          >
            <div className="h-full min-h-0">{children}</div>
          </main>
        </div>
      </div>
    </ProtectedLayout>
  );
}
