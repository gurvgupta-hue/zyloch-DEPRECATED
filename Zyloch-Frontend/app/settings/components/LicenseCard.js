"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, CreditCard } from "lucide-react";
import { getLicense } from "@/lib/api/organization";
import { useTenant } from "@/context/TenantContext";

export function LicenseCard() {
  const { isAdmin, license: contextLicense, refresh } = useTenant();
  const [license, setLicense] = useState(contextLicense);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const data = await getLicense(false);
        if (!cancelled) {
          setLicense(data);
          setError("");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.status === 404 ? "No license assigned yet." : err.message || "Failed to load license");
          setLicense(null);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  if (loading) {
    return (
      <div className="rounded-xl p-4 text-sm" style={{ border: "1px solid var(--border)", color: "var(--muted)" }}>
        Loading license…
      </div>
    );
  }

  if (error || !license) {
    return (
      <div className="rounded-xl p-4 text-sm" style={{ border: "1px solid var(--border)", color: "var(--muted)" }}>
        {error || "License unavailable"}
      </div>
    );
  }

  const users = license.usage?.users || { current: 0, max: 0 };
  const overLimit = license.overLimit?.users || (users.max > 0 && users.current >= users.max);

  return (
    <div className="rounded-xl p-5" style={{ border: "1px solid var(--border)", background: "var(--card)" }}>
      <div className="flex items-center gap-2 mb-3">
        <CreditCard size={18} />
        <h3 className="text-base font-semibold m-0">Plan & limits</h3>
        {!isAdmin && (
          <span className="text-xs ml-auto" style={{ color: "var(--muted)" }}>
            Read-only
          </span>
        )}
      </div>
      <p className="text-sm m-0 mb-2">
        <strong>{license.planName || license.planId}</strong>
        <span className="ml-2 text-xs" style={{ color: "var(--muted)" }}>
          {license.status}
          {license.active ? "" : " · inactive"}
        </span>
      </p>
      <div className="text-sm grid gap-1" style={{ color: "var(--muted)" }}>
        <div>
          Users: {users.current} / {users.max || "—"}
        </div>
        <div>
          Repos: {license.usage?.repos?.current ?? 0} / {license.usage?.repos?.max || "—"}
        </div>
        <div>
          Scans this month: {license.usage?.scansThisMonth?.current ?? 0} /{" "}
          {license.usage?.scansThisMonth?.max || "—"}
        </div>
      </div>
      {overLimit && (
        <div
          className="mt-3 flex items-start gap-2 rounded-lg p-3 text-sm"
          style={{ background: "rgba(220,38,38,0.08)", color: "#b91c1c" }}
        >
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span>
            Seat limit reached ({users.current}/{users.max}). Deactivate unused members or ask your
            Zyloch admin to upgrade the plan.
          </span>
        </div>
      )}
    </div>
  );
}
