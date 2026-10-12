"use client";

import { useTheme } from "@/context/ThemeContext";

export default function ProviderButton({
  label,
  icon: Icon,
  iconNode,
  onClick,
  disabled = false,
  className = "",
  bg,
  textColor,
  style = {},
}) {
  const finalBg = bg || "rgba(255, 255, 255, 0.03)";
  const finalTextColor = textColor || "#ffffff";

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        background: finalBg,
        color: finalTextColor,
        ...style
      }}
      className={`relative w-full flex items-center justify-center gap-[12px] rounded-full px-8 py-4 font-dm-sans font-[600] text-[15.5px] leading-tight transition-all duration-700 shadow-[0_4px_15px_rgba(0,0,0,0.3)] overflow-hidden group border transition-colors border-white/10 ${disabled
        ? "opacity-50 cursor-not-allowed grayscale"
        : "hover:bg-white/[0.08] hover:border-white/20 hover:shadow-2xl hover:scale-[1.01] active:scale-[0.98] active:shadow-inner focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500/30"
        } ${className}`}
    >
      {/* Dynamic Glossy Shine Effect */}
      <div className="absolute inset-0 -translate-x-full group-hover:animate-shimmer pointer-events-none transition-transform duration-1000 bg-gradient-to-r from-transparent via-white/5 to-transparent" />

      {/* Subtle Inner Glow */}
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-b from-white/5 to-transparent pointer-events-none" />

      {iconNode ? (
        <span className="h-5 w-5 relative z-10 transition-transform group-hover:scale-110">
          {iconNode}
        </span>
      ) : (
        Icon && <Icon className="h-5 w-5 relative z-10 transition-transform group-hover:scale-110" />
      )}
      <span className="relative z-10">{label}</span>

      <style jsx>{`
        @keyframes shimmer {
          100% { transform: translateX(100%); }
        }
        .group:hover .group-hover\:animate-shimmer {
          animation: shimmer 1.5s infinite;
        }
      `}</style>
    </button>
  );
}