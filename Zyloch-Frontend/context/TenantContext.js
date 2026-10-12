"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { usePathname } from "next/navigation";
import { getCurrentUser, logout as apiLogout } from "@/lib/api/user";
import {
  getCapabilities,
  getOrganization,
  listMyOrganizations,
  switchOrganization,
} from "@/lib/api/organization";

const TenantContext = createContext({
  tenantId: null,
  role: null,
  plan: null,
  license: null,
  entitlements: null,
  isLicenseActive: false,
  organization: null,
  user: null,
  isAdmin: false,
  isLoading: true,
  organizations: [],
  capabilities: {},
  can: () => false,
  hasScanner: () => true,
  hasFeature: () => true,
  refresh: async () => { },
  switchOrg: async () => { },
  clearTenant: () => { },
});

export function TenantProvider({ children }) {
  const pathname = usePathname();
  const [user, setUser] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [capabilities, setCapabilities] = useState({});
  const [isLoading, setIsLoading] = useState(true);

  const refresh = useCallback(async () => {
    const isPublicAuthPage =
      pathname?.startsWith("/login") ||
      pathname?.startsWith("/signup") ||
      pathname?.startsWith("/auth/login") ||
      pathname?.startsWith("/auth/signup") ||
      pathname?.startsWith("/cookies") ||
      pathname?.startsWith("/privacy") ||
      pathname?.startsWith("/terms");

    if (isPublicAuthPage) {
      setUser(null);
      setOrganization(null);
      setOrganizations([]);
      setCapabilities({});
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    try {
      const userData = await getCurrentUser(false);
      setUser(userData);
      if (!userData) {
        setOrganization(null);
        setOrganizations([]);
        setCapabilities({});
        return;
      }
      try {
        const org = await getOrganization(false);
        setOrganization(org);
      } catch {
        setOrganization(null);
      }
      try {
        const orgs = await listMyOrganizations(false);
        setOrganizations(orgs);
      } catch {
        setOrganizations([]);
      }
      try {
        const caps = await getCapabilities(false);
        setCapabilities(caps.capabilities);
      } catch {
        setCapabilities({});
      }
    } finally {
      setIsLoading(false);
    }
  }, [pathname]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const clearTenant = useCallback(() => {
    setUser(null);
    setOrganization(null);
    setOrganizations([]);
    setCapabilities({});
  }, []);

  const switchOrg = useCallback(
    async (tenantId) => {
      await switchOrganization(tenantId, true);
      // Full reload avoids cross-org data flash in client stores
      window.location.href = "/home";
    },
    []
  );

  const value = useMemo(() => {
    const tenantId =
      user?.tenantId ||
      user?.organizationId?._id ||
      organization?._id ||
      null;
    const role = user?.role || organization?.userRole || null;
    const license = organization?.license || user?.license || null;
    const plan = license
      ? { planId: license.planId, planName: license.planName, status: license.status }
      : null;
    const isAdmin = role === "admin";

    // Prefer the backend capability map; fall back to the role so a failed
    // capabilities fetch degrades to the same gates rather than locking admins out.
    const can = (capability) =>
      capability in capabilities ? capabilities[capability] : isAdmin;

    // --- License entitlements (MT-05.5) ---
    // Mirrors services/licenseEntitlements.js on the backend. These gate what the
    // UI offers; the backend gates what actually runs. Both read the same
    // entitlement payload, so a control the user can see is a control that works.
    const entitlements = license?.entitlements || null;
    const isLicenseActive = Boolean(license?.active);

    // Unknown until the license has loaded — callers should not gate on `false`
    // while `isLoading` is true, or the UI flashes an upgrade prompt on refresh.
    const hasScanner = (scannerKey) => {
      if (!entitlements) return true;
      const scanners = entitlements.scanners || [];
      return scanners.includes("all") || scanners.includes(scannerKey);
    };

    const hasFeature = (featureKey) => {
      if (!entitlements) return true;
      return entitlements.features?.[featureKey] === true;
    };

    return {
      entitlements,
      isLicenseActive,
      hasScanner,
      hasFeature,
      tenantId: tenantId ? String(tenantId) : null,
      role,
      plan,
      license,
      organization,
      user,
      isAdmin,
      isLoading,
      organizations,
      capabilities,
      can,
      refresh,
      switchOrg,
      clearTenant,
      logoutAndClear: async () => {
        await apiLogout(false);
        clearTenant();
      },
    };
  }, [user, organization, organizations, capabilities, isLoading, refresh, switchOrg, clearTenant]);

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant() {
  return useContext(TenantContext);
}

export default TenantContext;
