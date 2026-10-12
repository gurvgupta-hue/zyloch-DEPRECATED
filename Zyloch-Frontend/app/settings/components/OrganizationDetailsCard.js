"use client";

import React, { useState, useEffect } from "react";
import Image from "next/image";
import {
  Building2,
  Copy,
  Check,
  ExternalLink,
  Calendar,
  Shield,
  Users,
} from "lucide-react";
import { useTheme } from "@/context/ThemeContext";

export const OrganizationDetailsCard = ({ isAdmin }) => {
  const { theme } = useTheme();
  const isLight = theme === "light";
  const [organization, setOrganization] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copiedField, setCopiedField] = useState(null);

  useEffect(() => {
    fetchOrganization();
  }, []);

  const fetchOrganization = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/organization`,
        {
          credentials: "include",
        },
      );

      if (response.ok) {
        const data = await response.json();
        setOrganization(data.organization);
      }
    } catch (error) {
      console.error("Error fetching organization:", error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text, field) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  };

  if (loading) {
    return (
      <div className="rounded-xl p-4 text-sm" style={{ color: "var(--muted)", border: "1px solid var(--border)" }}>
        Loading organization details...
      </div>
    );
  }

  if (!organization) {
    return (
      <div className="rounded-xl p-4 text-sm" style={{ color: "var(--muted)", border: "1px solid var(--border)" }}>
        No organization found.
      </div>
    );
  }

  const tileStyle = {
    background: "rgba(var(--color-primary-rgb),0.08)",
    border: "1px solid var(--border)",
    borderRadius: "10px",
  };
  const labelStyle = { color: "var(--muted)" };

  const admin = organization.adminUserId;
  const membersCount = organization.membersCount || organization.members?.length || 1;

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center gap-4 p-4 rounded-xl" style={tileStyle}>
        <div className="h-14 w-14 rounded-full overflow-hidden shrink-0" style={{ background: "var(--gradient-primary)" }}>
          {organization.logoUrl ? (
            <Image
              src={organization.logoUrl}
              alt="Organization Logo"
              width={56}
              height={56}
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="h-full w-full flex items-center justify-center">
              <Building2 size={24} color="#fff" />
            </div>
          )}
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium truncate" style={{ color: "var(--text)" }}>
            {organization.name || "Organization"}
          </p>
          <p className="text-xs truncate" style={{ color: "var(--muted)" }}>
            Team workspace and access controls
          </p>
          {organization.website && (
            <a
              href={organization.website}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 mt-1 text-xs"
              style={{ color: "var(--color-primary)" }}
            >
              <ExternalLink size={12} />
              {organization.website.replace(/^https?:\/\//, "")}
            </a>
          )}
        </div>

        <span
          className="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs"
          style={{
            background: organization.isActive
              ? "rgba(var(--success-rgb), 0.1)"
              : "rgba(var(--warning-rgb), 0.12)",
            color: organization.isActive ? "var(--success)" : "var(--warning)",
          }}
        >
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: organization.isActive ? "var(--success)" : "var(--warning)" }}
          />
          {organization.isActive ? "Organization Active" : "Organization Inactive"}
        </span>
      </header>

      <section className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>Organization ID</p>
          <div className="h-10 px-3 rounded-lg flex items-center justify-between gap-2" style={tileStyle}>
            <span className="text-xs sm:text-sm truncate" style={{ color: "var(--text)" }}>
              {organization._id}
            </span>
            <button
              onClick={() => copyToClipboard(organization._id, "id")}
              className="p-1 rounded"
              style={{ color: copiedField === "id" ? "var(--success)" : "var(--muted)" }}
              title="Copy organization id"
            >
              {copiedField === "id" ? <Check size={14} /> : <Copy size={14} />}
            </button>
          </div>
        </div>

        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>Created</p>
          <div className="h-10 px-3 rounded-lg flex items-center gap-2" style={tileStyle}>
            <Calendar size={14} style={{ color: "var(--muted)" }} />
            <span className="text-sm truncate" style={{ color: "var(--text)" }}>
              {formatDate(organization.createdAt)}
            </span>
          </div>
        </div>

        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>Members</p>
          <div className="h-10 px-3 rounded-lg flex items-center gap-2" style={tileStyle}>
            <Users size={14} style={{ color: "var(--muted)" }} />
            <span className="text-sm" style={{ color: "var(--text)" }}>
              {membersCount} member{membersCount > 1 ? "s" : ""}
            </span>
          </div>
        </div>

        <div>
          <p className="text-xs mb-1.5" style={labelStyle}>Your Role</p>
          <div className="h-10 px-3 rounded-lg flex items-center gap-2" style={tileStyle}>
            <Shield size={14} style={{ color: "var(--muted)" }} />
            <span className="text-sm" style={{ color: "var(--text)" }}>
              {organization.userRole || (isAdmin ? "admin" : "member")}
            </span>
          </div>
        </div>
      </section>

      <section className="p-3 rounded-lg" style={tileStyle}>
        <p className="text-xs mb-2" style={labelStyle}>Administrator</p>
        {admin ? (
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-full overflow-hidden bg-black/10">
              {admin.avatar_url ? (
                <Image
                  src={admin.avatar_url}
                  alt="Admin Avatar"
                  width={32}
                  height={32}
                  className="h-full w-full object-cover"
                />
              ) : (
                <div className="h-full w-full flex items-center justify-center text-xs" style={{ color: "var(--text)" }}>
                  {(admin.name || "A").charAt(0).toUpperCase()}
                </div>
              )}
            </div>
            <div className="min-w-0">
              <p className="text-sm truncate" style={{ color: "var(--text)" }}>
                {admin.name || "Admin"}
              </p>
              <p className="text-xs truncate" style={{ color: "var(--muted)" }}>
                {admin.email || "No email"}
              </p>
            </div>
          </div>
        ) : (
          <p className="text-sm" style={{ color: "var(--muted)" }}>Not available</p>
        )}
      </section>
    </div>
  );
};
