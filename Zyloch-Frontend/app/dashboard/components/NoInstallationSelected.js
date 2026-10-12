"use client";

import React from "react";
import {
  ChevronDown,
  Building2,
  User,
  Crown,
  Check,
  ArrowRight,
} from "lucide-react";

import { FaGithub } from "react-icons/fa";

const INSTALLATIONS = [
  { id: "1", name: "my-organization", type: "organization" },
  { id: "2", name: "personal-account", type: "user" },
  { id: "3", name: "enterprise-corp", type: "enterprise" },
];

const ACCOUNT_ICONS = {
  organization: Building2,
  user: User,
  enterprise: Crown,
};

const AccountIcon = ({ type }) => {
  const Icon = ACCOUNT_ICONS[type];
  const colors = {
    organization: "text-cyan-500",
    user: "text-emerald-500",
    enterprise: "text-purple-500",
  };
  return <Icon size={14} className={colors[type]} />;
};

export default function NoInstallationSelected() {
  // const [isOpen, setIsOpen] = useState(false);
  // const [activeStep, setActiveStep] = useState(0);

  // // Auto-demo cycle - no user interaction
  // useEffect(() => {
  //   const timer = setInterval(() => {
  //     setActiveStep(prev => {
  //       if (prev === 0) {
  //         setIsOpen(true);
  //         return 1;
  //       } else if (prev === 1) {
  //         setTimeout(() => setIsOpen(false), 1500);
  //         return 2;
  //       } else {
  //         setIsOpen(false);
  //         return 0;
  //       }
  //     });
  //   }, 5000);

  //   return () => clearInterval(timer);
  // }, []);

  // // Auto-reset after step 2
  // useEffect(() => {
  //   if (activeStep === 2) {
  //     const timer = setTimeout(() => {
  //       setActiveStep(0);
  //       setIsOpen(false);
  //     }, 3000);
  //     return () => clearTimeout(timer);
  //   }
  // }, [activeStep]);

  return (
    <div className="w-full h-full flex items-center justify-center p-6">
      <div className="flex flex-col items-center text-center max-w-md">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-[var(--color-primary)]/10 mb-4">
          <FaGithub size={28} className="text-[var(--color-primary)]" />        </div>
        <h1 className="text-xl font-semibold text-[var(--text)] mb-2">
          Connect Your GitHub Account
        </h1>
        <p className="text-sm text-[var(--muted)]">
          Select a GitHub installation to access repository analytics and insights
        </p>
      </div>

      {/* Demo Card - animation commented out */}
      {false && (
        <div className="bg-[var(--surface)] rounded-xl border border-[var(--border)] overflow-hidden shadow-lg">
          {/* Window header */}
          <div className="px-4 py-2.5 border-b border-[var(--border)] bg-[var(--elevated-surface)]">
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500/80"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-green-500/80"></div>
            </div>
          </div>

          {/* Content with fixed height */}
          <div className="h-[280px] p-6 flex flex-col">
            {/* Navbar Simulation */}
            <div className="bg-[var(--elevated-surface)] rounded-lg p-3 border border-[var(--border)]">
              <div className="flex items-center justify-between">
                <div className="relative">
                  <div
                    className={`flex items-center gap-2 px-3 py-1.5 text-sm bg-[var(--surface)] rounded-lg border border-[var(--border)] min-w-[180px] cursor-default transition-all ${
                      activeStep === 0 ? "ring-2 ring-[var(--color-primary)] ring-offset-2 ring-offset-[var(--elevated-surface)]" : ""
                    }`}
                  >
                    {activeStep === 2 ? (
                      <>
                        <AccountIcon type="organization" />
                        <span className="flex-1 text-left font-medium text-sm text-[var(--text)]">
                          my-organization
                        </span>
                        <Check size={12} className="text-emerald-500" />
                      </>
                    ) : (
                      <>
                        <Building2 size={14} className="text-[var(--muted)]" />
                        <span className="font-medium text-sm text-[var(--text)]">GitHub Account</span>
                        <ChevronDown
                          size={12}
                          className={`text-[var(--muted)] transition-transform duration-200 ${
                            isOpen ? "rotate-180" : ""
                          }`}
                        />
                      </>
                    )}
                  </div>

                  {/* Dropdown */}
                  {isOpen && activeStep !== 2 && (
                    <div className="absolute left-0 top-full mt-1 w-64 bg-[var(--surface)] rounded-lg shadow-xl border border-[var(--border)] z-20 overflow-hidden">
                      <div className="py-1">
                        <div className="px-3 py-1.5 border-b border-[var(--border)]">
                          <span className="text-xs font-medium text-[var(--muted)]">Accounts</span>
                        </div>
                        {INSTALLATIONS.map((item, idx) => (
                          <div
                            key={item.id}
                            className={`flex items-center gap-2 px-3 py-2 text-sm ${
                              activeStep === 1 && idx === 0
                                ? "bg-[var(--color-primary)]/5"
                                : ""
                            }`}
                          >
                            <AccountIcon type={item.type} />
                            <span className="flex-1 text-left text-sm text-[var(--text)]">
                              {item.name}
                            </span>
                            <span className="text-xs text-[var(--muted)] capitalize">
                              {item.type}
                            </span>
                            {activeStep === 1 && idx === 0 && (
                              <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-primary)]" />
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="w-7 h-7 rounded-lg bg-[var(--surface)] border border-[var(--border)]"></div>
              </div>

              {activeStep === 2 && (
                <div className="mt-3 pt-3 border-t border-[var(--border)]">
                  <div className="flex items-center justify-center gap-2">
                    <Check size={12} className="text-emerald-500" />
                    <span className="text-xs text-emerald-500">Connected to my-organization</span>
                  </div>
                </div>
              )}
            </div>

            {/* Progress Steps */}
            <div className="mt-auto pt-6">
              <div className="flex items-center justify-center gap-8">
                {/* Step 1 */}
                <div className="text-center">
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-all ${
                      activeStep >= 1
                        ? "bg-[var(--color-primary)] text-white"
                        : "bg-[var(--border)] text-[var(--muted)]"
                    }`}
                  >
                    {activeStep > 1 ? <Check size={12} /> : "1"}
                  </div>
                  <p className="text-xs text-[var(--muted)] mt-1.5">Select</p>
                </div>

                <ArrowRight size={14} className="text-[var(--border)]" />

                {/* Step 2 */}
                <div className="text-center">
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-all ${
                      activeStep >= 2
                        ? "bg-[var(--color-primary)] text-white"
                        : "bg-[var(--border)] text-[var(--muted)]"
                    }`}
                  >
                    {activeStep >= 2 ? <Check size={12} /> : "2"}
                  </div>
                  <p className="text-xs text-[var(--muted)] mt-1.5">Ready</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}