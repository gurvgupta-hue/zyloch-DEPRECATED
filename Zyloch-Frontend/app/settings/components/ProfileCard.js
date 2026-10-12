"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import Image from "next/image";
import { Mail, Calendar, AtSign, User, Palette, ChevronDown, Check } from "lucide-react";
import { FaGithub as Github } from "react-icons/fa";
import { useTheme, TIME_ZONE_OPTIONS } from "@/context/ThemeContext";

export const ProfileCard = () => {
  const { user, theme, timeZone, setTimeZone } = useTheme();
  const isLight = theme === "light";
  const [showEmail, setShowEmail] = useState(false);
  const [isTzOpen, setIsTzOpen] = useState(false);
  const timezoneRef = useRef(null);

  const activeTimeZone = timeZone || "UTC";
  const selectedZone = useMemo(
    () => TIME_ZONE_OPTIONS.find((zone) => zone.value === activeTimeZone),
    [activeTimeZone],
  );

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (timezoneRef.current && !timezoneRef.current.contains(event.target)) {
        setIsTzOpen(false);
      }
    };

    document.addEventListener("mousedown", handleOutsideClick);
    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
    };
  }, []);

  if (!user) {
    return (
      <div
        className="rounded-xl p-4 text-sm"
        style={{ color: "var(--muted)", border: "1px solid var(--border)" }}
      >
        Loading profile...
      </div>
    );
  }

  const formatDate = (date) =>
    new Date(date).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });

  const profileUrl = user.html_url || `https://github.com/${user.login}`;
  const organizationName =
    user?.organizationId && typeof user.organizationId === "object"
      ? user.organizationId.name
      : null;

  const tileStyle = {
    background: "rgba(var(--color-primary-rgb),0.08)",
    border: "1px solid var(--border)",
    borderRadius: "10px",
  };
  const labelStyle = { color: "var(--muted)" };

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center gap-4 p-4 rounded-xl" style={tileStyle}>
        <div
          className="h-14 w-14 rounded-full overflow-hidden shrink-0"
          style={{ background: "var(--gradient-primary)" }}
        >
          {user.avatar_url ? (
            <Image
              src={user.avatar_url}
              alt="User Avatar"
              width={56}
              height={56}
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="h-full w-full flex items-center justify-center text-white font-semibold">
              {(user.name || user.login || "U").charAt(0).toUpperCase()}
            </div>
          )}
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium truncate" style={{ color: "var(--text)" }}>
            {user.name || user.login || "Unknown User"}
          </p>
          <p className="text-xs truncate" style={{ color: "var(--muted)" }}>
            @{user.login || "unknown"}
          </p>
          {organizationName && (
            <p className="text-xs mt-1" style={{ color: "var(--muted)" }}>
              Organization: {organizationName}
            </p>
          )}
        </div>

        <a
          href={profileUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg"
          style={{
            background: "rgba(var(--color-primary-rgb), 0.1)",
            border: "1px solid rgba(var(--color-primary-rgb), 0.3)",
            color: "var(--color-primary)",
          }}
        >
          <Github size={13} />
          Open Profile
        </a>
      </header>

      <section className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>
            Full Name
          </p>
          <div className="h-10 px-3 rounded-lg flex items-center gap-2" style={tileStyle}>
            <User size={14} style={{ color: "var(--muted)" }} />
            <span className="text-sm truncate" style={{ color: "var(--text)" }}>
              {user.name || "Not set"}
            </span>
          </div>
        </div>

        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>
            Email Address
          </p>
          <div className="h-10 px-3 rounded-lg flex items-center justify-between gap-2" style={tileStyle}>
            <span className="inline-flex items-center gap-2 min-w-0">
              <Mail size={14} style={{ color: "var(--muted)" }} />
              <span className="text-sm truncate" style={{ color: "var(--text)" }}>
                {showEmail ? user.email || "Not available" : "••••••••@•••••.com"}
              </span>
            </span>
            <button
              onClick={() => setShowEmail((prev) => !prev)}
              className="text-xs font-medium px-2 py-1 rounded-md"
              style={{
                background: "rgba(var(--color-primary-rgb), 0.12)",
                color: "var(--color-primary)",
              }}
            >
              {showEmail ? "Hide" : "Show"}
            </button>
          </div>
        </div>

        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>
            GitHub Username
          </p>
          <div className="h-10 px-3 rounded-lg flex items-center gap-2" style={tileStyle}>
            <AtSign size={14} style={{ color: "var(--muted)" }} />
            <span className="text-sm truncate" style={{ color: "var(--text)" }}>
              {user.login || "Not available"}
            </span>
          </div>
        </div>

        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>
            Time Zone
          </p>
          <div className="relative" ref={timezoneRef}>
            <button
              onClick={() => setIsTzOpen((prev) => !prev)}
              className="h-10 w-full px-3 rounded-lg flex items-center justify-between gap-2 text-sm"
              style={tileStyle}
            >
              <span className="inline-flex items-center gap-2 min-w-0">
                <Palette size={14} style={{ color: "var(--muted)" }} />
                <span className="truncate" style={{ color: "var(--text)" }}>
                  {selectedZone?.label || activeTimeZone}
                </span>
              </span>
              <ChevronDown
                size={14}
                className={`transition-transform ${isTzOpen ? "rotate-180" : ""}`}
                style={{ color: "var(--muted)" }}
              />
            </button>

            {isTzOpen && (
              <div
                className="absolute z-20 mt-2 w-full max-h-52 overflow-auto rounded-lg p-1"
                style={{
                  background: isLight ? "#fff" : "#1e1e1e",
                  border: "1px solid var(--border)",
                  boxShadow: "var(--shadow-1)",
                }}
              >
                {TIME_ZONE_OPTIONS.map((zone) => (
                  <button
                    key={zone.value}
                    onClick={() => {
                      setTimeZone(zone.value);
                      setIsTzOpen(false);
                    }}
                    className="w-full text-left rounded-md px-2.5 py-2 text-xs flex items-center justify-between"
                    style={{
                      color: zone.value === activeTimeZone ? "var(--color-primary)" : "var(--text)",
                      background:
                        zone.value === activeTimeZone
                          ? "rgba(var(--color-primary-rgb), 0.1)"
                          : "transparent",
                    }}
                  >
                    <span>
                      {zone.label} (UTC{zone.offset >= 0 ? "+" : ""}
                      {zone.offset})
                    </span>
                    {zone.value === activeTimeZone && <Check size={13} />}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      <footer
        className="pt-4 border-t flex flex-wrap items-center justify-between gap-3"
        style={{ borderColor: "var(--border)" }}
      >
        <span
          className="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs"
          style={{
            background: "rgba(var(--success-rgb), 0.1)",
            color: "var(--success)",
          }}
        >
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--success)" }} />
          Profile synced
        </span>
        <span className="inline-flex items-center gap-2 text-xs" style={{ color: "var(--muted)" }}>
          <Calendar size={13} />
          Last updated {formatDate(user.updatedAt || user.createdAt || new Date())}
        </span>
      </footer>

      <div className="px-1">
        <p className="text-[11px]" style={{ color: "var(--muted)" }}>
          Email visibility only affects this screen and does not modify account privacy settings.
        </p>
      </div>
    </div>
  );
};
