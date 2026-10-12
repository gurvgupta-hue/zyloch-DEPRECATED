"use client";

import TechStackIcon from "@/components/common/TechStackIcon";

export default function MicrosoftSignInButton({ onClick, disabled = false, isLoading = false }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`relative w-full flex items-center justify-center gap-[12px] rounded-full px-8 py-4 font-dm-sans font-[600] text-[15.5px] leading-tight transition-all duration-700 shadow-[0_4px_15px_rgba(0,0,0,0.3)] overflow-hidden group border transition-colors bg-white/[0.03] border-white/[0.05] text-white ${disabled
        ? "opacity-50 cursor-not-allowed grayscale"
        : "hover:bg-white/[0.08] hover:border-white/20 hover:shadow-2xl hover:scale-[1.01] active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500/30"
        }`}
    >
      {/* Dynamic Glossy Shine Effect */}
      <div className="absolute inset-0 -translate-x-full group-hover:animate-shimmer pointer-events-none transition-transform duration-1000 bg-gradient-to-r from-transparent via-white/5 to-transparent" />

      {/* Microsoft Logo */}
      <div className="relative z-10 p-1.5 rounded-lg transition-colors bg-white/10 group-hover:bg-white/20">
        <TechStackIcon name="microsoft" size={20} />
      </div>
      <span className="relative z-10 transition-colors">
        {isLoading ? "Connecting..." : "Continue with Microsoft"}
      </span>

      <style jsx>{`
        @keyframes shimmer {
          100% { transform: translateX(100%); }
        }
        .group:hover .group-hover\:animate-shimmer {
          animation: shimmer 2s infinite;
        }
      `}</style>
    </button>
  );
}
