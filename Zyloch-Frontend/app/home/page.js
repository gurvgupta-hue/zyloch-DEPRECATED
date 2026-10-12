import React from "react";
import HomeHeader from "./components/HomeHeader";
import FeatureShowcase from "./components/FeatureShowcase";
import InstallationCard from "./components/InstallationCard";
import HomeFooter from "./components/HomeFooter";

export const metadata = {
  title: "Home — Zyloch Continuous Coverage",
  description:
    "Protect repositories without slowing delivery. Connect via GitHub and activate continuous security intelligence across your codebase.",
  robots: { index: false, follow: false },
};

export default function HomePage() {
  return (
    <div className="min-h-screen w-full bg-[var(--bg)] text-[var(--text)] transition-colors duration-200 flex flex-col justify-between overflow-x-hidden">
      {/* Ambient Lighting matching Theme */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-0 left-1/4 w-[600px] h-[430px] bg-[var(--color-primary)]/5 rounded-full blur-[140px]" />
        <div className="absolute bottom-0 right-1/4 w-[600px] h-[430px] bg-[var(--color-secondary)]/5 rounded-full blur-[140px]" />
      </div>

      {/* Main Container */}
      <div className="relative z-10 max-w-[1278px] w-full mx-auto min-h-screen flex flex-col justify-between px-4 sm:px-6 lg:px-8 py-4 sm:py-5 lg:py-6 gap-4 sm:gap-6">
        {/* Top Header */}
        <HomeHeader />

        {/* 2-Column Split Cards Grid */}
        <main className="w-full flex-1 grid grid-cols-1 lg:grid-cols-[618fr_548fr] gap-6 lg:gap-7 xl:gap-8 items-stretch my-auto">
          {/* Left Column: Feature Tour & Carousel */}
          <FeatureShowcase />

          {/* Right Column: GitHub App Connection & Setup */}
          <InstallationCard />
        </main>

        {/* Bottom Footer */}
        <HomeFooter />
      </div>
    </div>
  );
}
