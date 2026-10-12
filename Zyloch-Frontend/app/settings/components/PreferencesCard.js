"use client";
import React, { useState, useEffect } from "react";
import { Globe, Clock, Save, CheckCircle, ChevronDown, Check } from "lucide-react";
import { useTheme, TIME_ZONE_OPTIONS } from "@/context/ThemeContext";
import { toast } from "react-toastify";

export const PreferencesCard = () => {
  const { timeZone, setTimeZone } = useTheme();
  const [selectedTimeZone, setSelectedTimeZone] = useState(timeZone || "UTC");
  const [isOpen, setIsOpen] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const hasChanges = selectedTimeZone !== timeZone;
  const selectedOption = TIME_ZONE_OPTIONS.find((z) => z.value === selectedTimeZone);

  // Sync if context changes externally
  useEffect(() => {
    setSelectedTimeZone(timeZone || "UTC");
  }, [timeZone]);

  const handleSave = async () => {
    if (!hasChanges) return;
    setIsSaving(true);
    try {
      await new Promise((r) => setTimeout(r, 500));
      setTimeZone(selectedTimeZone);
      setSaved(true);
      toast.success("Timezone saved successfully!");
      setTimeout(() => setSaved(false), 2000);
    } catch {
      toast.error("Failed to save timezone");
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="w-full space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/20">
          <Clock size={16} className="text-cyan-400" />
        </div>
        <div>
          <h3 className="text-sm font-semibold" style={{ color: "var(--text)" }}>
            Time Zone
          </h3>
          <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
            All timestamps across the app will display in your selected timezone
          </p>
        </div>
      </div>

      {/* Custom dropdown — works in all themes */}
      <div className="space-y-2">
        <p className="flex items-center gap-1.5 text-xs font-medium" style={{ color: "var(--muted)" }}>
          <Globe size={13} />
          Select Timezone
        </p>

        {/* Trigger */}
        <button
          type="button"
          onClick={() => setIsOpen((o) => !o)}
          className="w-full flex items-center justify-between rounded-xl px-4 py-3 text-sm transition-all"
          style={{
            background: "rgba(var(--surface-rgb),0.05)",
            border: "1px solid rgba(var(--border-rgb),0.12)",
            color: "var(--text)",
          }}
        >
          <div className="flex items-center gap-2.5">
            <Globe size={15} className="text-cyan-400 shrink-0" />
            <span className="font-medium">{selectedOption?.label ?? selectedTimeZone}</span>
            <span className="text-xs opacity-50">
              UTC{(selectedOption?.offset ?? 0) >= 0 ? "+" : ""}{selectedOption?.offset ?? 0}
            </span>
          </div>
          <ChevronDown
            size={15}
            className={`opacity-50 transition-transform duration-200 ${isOpen ? "rotate-180" : ""}`}
          />
        </button>

        {/* Options — inline, no absolute positioning, safe inside overflow-y-auto */}
        {isOpen && (
          <div
            className="rounded-xl overflow-hidden mt-1"
            style={{
              border: "1px solid rgba(var(--border-rgb),0.10)",
              background: "rgba(var(--bg-rgb),0.98)",
            }}
          >
            {TIME_ZONE_OPTIONS.map((zone) => {
              const isSelected = zone.value === selectedTimeZone;
              return (
                <button
                  key={zone.value}
                  type="button"
                  onClick={() => {
                    setSelectedTimeZone(zone.value);
                    setIsOpen(false);
                  }}
                  className="w-full flex items-center justify-between px-4 py-2.5 text-sm transition-colors"
                  style={{
                    background: isSelected ? "rgba(var(--color-primary-rgb),0.12)" : "transparent",
                    color: isSelected ? "var(--color-primary)" : "var(--text-secondary)",
                  }}
                  onMouseEnter={(e) => {
                    if (!isSelected) e.currentTarget.style.background = "rgba(var(--surface-rgb),0.05)";
                  }}
                  onMouseLeave={(e) => {
                    if (!isSelected) e.currentTarget.style.background = "transparent";
                  }}
                >
                  <span>{zone.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs opacity-50">
                      UTC{zone.offset >= 0 ? "+" : ""}{zone.offset}
                    </span>
                    {isSelected && <Check size={13} className="text-cyan-400" />}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Save button */}
      <button
        type="button"
        onClick={handleSave}
        disabled={isSaving || !hasChanges}
        className="flex w-full items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition-all active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
        style={{
          background: hasChanges ? "var(--color-primary)" : "rgba(var(--surface-rgb),0.05)",
          color: hasChanges ? "var(--text-on-primary)" : "var(--text-disabled)",
          border: hasChanges ? "none" : "1px solid rgba(var(--border-rgb),0.10)",
        }}
      >
        {isSaving ? (
          <>
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
            Saving…
          </>
        ) : saved ? (
          <>
            <CheckCircle size={15} />
            Saved!
          </>
        ) : (
          <>
            <Save size={15} />
            {hasChanges ? "Save Timezone" : "No changes"}
          </>
        )}
      </button>
    </div>
  );
};
