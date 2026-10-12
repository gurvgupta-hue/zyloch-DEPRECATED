"use client";

import React from "react";
import { Workflow, Shield } from "lucide-react";
import { SettingsPageHeader } from "../components/SettingsPageHeader";

const WorkflowPoliciesPage = () => {
  return (
    <div className="space-y-6">
      <SettingsPageHeader
        icon={Workflow}
        title="Workflow Policies"
        subtitle="Define approval and automation rules for policy-driven security actions."
      />

      <section
        className="rounded-2xl p-5 sm:p-6"
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          boxShadow: "var(--shadow-1)",
        }}
      >
        <div className="flex items-start gap-3">
          <div
            className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-lg"
            style={{
              background:
                "color-mix(in srgb, var(--color-primary) 14%, transparent)",
              border:
                "1px solid color-mix(in srgb, var(--color-primary) 30%, transparent)",
            }}
          >
            <Shield size={18} style={{ color: "var(--color-primary)" }} />
          </div>

          <div>
            <h2 className="text-lg font-semibold" style={{ color: "var(--text)" }}>
              Coming Soon
            </h2>
            <p className="mt-1 text-sm" style={{ color: "var(--muted)" }}>
              Workflow policy controls are being prepared for this section.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};

export default WorkflowPoliciesPage;