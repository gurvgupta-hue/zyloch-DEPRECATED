"use client";

import { useState, useEffect } from "react";
import {
  Building2,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import ProviderButton from "./ProviderButton";
import GoogleSignInButton from "./GoogleSignInButton";
import MicrosoftSignInButton from "./MicrosoftSignInButton";
import TechStackIcon from "@/components/common/TechStackIcon";

export default function LoginOptions({ onGitHubLogin, isLoading, orgId, onLeaveOrg }) {
  const [showMore, setShowMore] = useState(false);
  const [loadingProvider, setLoadingProvider] = useState(null);
  const [enabledProviders, setEnabledProviders] = useState({
    google: false,
    microsoft: false
  });
  const [providersLoading, setProvidersLoading] = useState(false);
  const [providersFetchFailed, setProvidersFetchFailed] = useState(false);

  // Fetch enabled providers when orgId is present
  useEffect(() => {
    if (orgId) {
      setProvidersFetchFailed(false);
      fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/organization/${orgId}/providers`)
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            setEnabledProviders(data.providers);
          } else {
            setProvidersFetchFailed(true);
          }
        })
        .catch(err => {
          console.error('Failed to fetch enabled providers:', err);
          setProvidersFetchFailed(true);
        })
        .finally(() => {
          setProvidersLoading(false);
        });
    }
  }, [orgId]);

  // Handle Google Login
  const handleGoogleLogin = () => {
    setLoadingProvider('google');
    const url = orgId
      ? `${process.env.NEXT_PUBLIC_API_URL}/auth/google?orgId=${orgId}`
      : `${process.env.NEXT_PUBLIC_API_URL}/auth/google`;
    window.location.href = url;
  };

  // Handle Microsoft Login
  const handleMicrosoftLogin = () => {
    setLoadingProvider('microsoft');
    const url = orgId
      ? `${process.env.NEXT_PUBLIC_API_URL}/auth/microsoft?orgId=${orgId}`
      : `${process.env.NEXT_PUBLIC_API_URL}/auth/microsoft`;
    window.location.href = url;
  };

  return (
    <div className="w-full flex flex-col gap-4">
      {/* Two distinct entry points:
            no org_id  → admin signup/sign-in with GitHub, which provisions or
                         resolves that admin's own organization;
            org_id     → an invited member signing in to that organization via SSO.
          The organization id only ever arrives on the invite link — it cannot be
          looked up, and the domain box that used to do so was removed because it
          answered "is this company a customer?" to anyone who asked. */}

      {/* Primary Providers - Only show if no orgId */}
      {!orgId && (
        <div className="flex flex-col gap-3">
          <ProviderButton
            label={loadingProvider === 'github' || isLoading ? "Connecting..." : "Continue with GitHub"}
            iconNode={<TechStackIcon name="github" size={20} />}
            onClick={onGitHubLogin}
            bg="rgba(0, 211, 243, 1)"
            textColor="black"
            className="border border-white/10"
          />
          <ProviderButton
            label="Continue with GitLab"
            iconNode={<TechStackIcon name="gitlab" size={20} />}
            bg="linear-gradient(98.02deg, #F4A57A 0%, #E8915C 100%)"
            style={{ boxShadow: '0px 4px 15px rgba(244, 165, 122, 0.25)' }}
            disabled
          />
        </div>
      )}

      {/* Show More / Less Button - Only if no orgId */}
      {!orgId && (
        <button
          onClick={() => setShowMore(!showMore)}
          className="flex items-center justify-center gap-1.5 text-[14px] font-medium text-[#00BCD4] hover:text-[#00BCD4]/80 transition-all"
        >
          {showMore ? (
            <>
              <ChevronUp className="h-4 w-4" /> Show Less
            </>
          ) : (
            <>
              <ChevronDown className="h-4 w-4" /> Show More
            </>
          )}
        </button>
      )}

      {/* Additional Providers - Show based on orgId presence */}
      <div
        className={`w-full flex flex-col gap-3 transition-all duration-500 ease-in-out ${orgId
          ? "max-h-96 opacity-100 scale-100"
          : showMore
            ? "max-h-96 opacity-100 scale-100"
            : "max-h-0 opacity-0 scale-95 overflow-hidden"
          }`}
      >
        <GoogleSignInButton
          onClick={handleGoogleLogin}
          disabled={!orgId || providersLoading || (!providersFetchFailed && !enabledProviders.google)}
          isLoading={loadingProvider === 'google'}
        />

        <MicrosoftSignInButton
          onClick={handleMicrosoftLogin}
          disabled={!orgId || providersLoading || (!providersFetchFailed && !enabledProviders.microsoft)}
          isLoading={loadingProvider === 'microsoft'}
        />

        {!orgId && (
          <ProviderButton
            label="Enterprise SSO"
            icon={Building2}
            bg="#2563EB"
            className="mt-2"
            disabled
          />
        )}
      </div>

      {/* A remembered organization must be escapable: without this, an admin who
          shares a browser with an invited member would only ever be offered that
          member's SSO buttons and could never reach GitHub sign-in. */}
      {orgId && onLeaveOrg && (
        <button
          type="button"
          onClick={onLeaveOrg}
          className="text-[13px] font-medium text-white/60 hover:text-white/90 transition-all"
        >
          Sign in to a different organization
        </button>
      )}
    </div>
  );
}
