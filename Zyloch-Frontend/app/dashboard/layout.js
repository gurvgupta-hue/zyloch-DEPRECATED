"use client";

import { useState } from "react";
import Navbar from "./components/DashboardNavbar";
import Sidebar from "./components/DashboardSidebar";
import ProtectedLayout from "@/components/ProtectedLayout";

export default function HomeLayout({ children }) {
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false); // Mobile sidebar
  const [desktopSidebarOpen, setDesktopSidebarOpen] = useState(false);

  const toggleMobileSidebar = () => setMobileSidebarOpen((prev) => !prev);
  const closeMobileSidebar = () => setMobileSidebarOpen(false);

  return (
    <ProtectedLayout>
      <div className="relative flex h-screen overflow-hidden bg-[var(--bg)] p-3 gap-3">

        {/* Desktop sidebar */}
        <aside aria-label="Sidebar navigation" className={`hidden sm:flex shrink-0 h-full bg-transparent transition-all duration-300 ease-in-out ${desktopSidebarOpen ? "w-[272px]" : "w-[72px]"}`}>
          <Sidebar isOpen={desktopSidebarOpen} showToggle={true} onToggle={() => setDesktopSidebarOpen((prev) => !prev)} />
        </aside>

        {/* Mobile sidebar */}
        <aside
          aria-label="Mobile sidebar navigation"
          className={`
            fixed sm:hidden top-0 left-0 z-50 h-full w-[18.5rem] shrink-0 p-2.5 bg-transparent
            transform transition-transform duration-300 ease-in-out
            ${mobileSidebarOpen ? "translate-x-0" : "-translate-x-full"}
          `}
        >
          <Sidebar isOpen={true} />
        </aside>

        {/* Mobile overlay */}
        {mobileSidebarOpen && (
          <div
            onClick={closeMobileSidebar}
            className="fixed inset-0 z-40 sm:hidden bg-black/50 backdrop-blur-sm"
          />
        )}

        {/* Main content */}
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--card-bg)] backdrop-blur-xl">

          {/* Navbar */}
          <header className="shrink-0 border-b border-[var(--border)]">
            <Navbar onToggleSidebar={toggleMobileSidebar} />
          </header>

          {/* Scrollable content */}
          <main id="main-content" aria-label="Dashboard" className="flex-1 overflow-y-auto overflow-x-hidden scrollbar-hide-lg">
            <div className="w-full min-w-0 px-4 py-4">{children}</div>
          </main>
        </div>
      </div>
    </ProtectedLayout>
  );
}