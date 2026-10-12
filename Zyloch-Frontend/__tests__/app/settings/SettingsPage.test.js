import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import SettingsPage from "@/app/settings/page";
import { useTheme } from "@/context/ThemeContext";
import { logout } from "@/lib/api/user";
import { toast } from "react-toastify";

jest.mock("@/app/settings/components/ProfileCard", () => ({
    ProfileCard: () => <div data-testid="profile-card">Profile Card</div>,
}));

jest.mock("@/app/settings/components/OAuthConfigCard", () => ({
    OAuthConfigCard: () => <div data-testid="oauth-card">OAuth Card</div>,
}));

jest.mock("@/app/settings/components/OrganizationDetailsCard", () => ({
    OrganizationDetailsCard: ({ isAdmin }) => (
        <div data-testid="organization-card">Org Card {isAdmin ? "admin" : "member"}</div>
    ),
}));

jest.mock("@/components/ThemeToggle", () => ({
    ThemeToggle: () => <button type="button">Theme Toggle</button>,
}));

jest.mock("@/context/ThemeContext", () => ({
    useTheme: jest.fn(),
}));

jest.mock("@/lib/api/user", () => ({
    logout: jest.fn(),
}));

jest.mock("react-toastify", () => ({
    toast: {
        loading: jest.fn(),
        update: jest.fn(),
        error: jest.fn(),
    },
}));

// Named icons keep their stable test ids; anything else resolves to a generic stub
// via the Proxy, so adding a card that uses a new icon does not break this suite.
// MT added TenantContext and the license/members cards. Stub both so this suite
// keeps testing the settings page itself rather than the tenant data layer.
jest.mock("@/context/TenantContext", () => ({
    useTenant: () => ({
        isAdmin: false,
        tenantId: "tenant-1",
        organizations: [],
        license: null,
        capabilities: {},
        can: () => false,
        switchOrg: jest.fn(),
        clearTenant: jest.fn(),
        refresh: jest.fn(),
    }),
}));

jest.mock("@/lib/api/organization", () => ({
    getOrganization: jest.fn().mockResolvedValue({}),
    getCapabilities: jest.fn().mockResolvedValue({ role: "member", isAdmin: false, capabilities: {} }),
    getLicense: jest.fn().mockResolvedValue(null),
    listMembers: jest.fn().mockResolvedValue({ members: [] }),
    inviteMember: jest.fn(),
    deactivateMember: jest.fn(),
    reactivateMember: jest.fn(),
    getPolicyConfigurations: jest.fn().mockResolvedValue({}),
    updatePolicyConfigurations: jest.fn().mockResolvedValue({}),
}));

jest.mock("lucide-react", () => {
    const named = {
        User: (props) => <svg data-testid="icon-user" {...props} />,
        ChevronDown: (props) => <svg data-testid="icon-chevron-down" {...props} />,
        Building2: (props) => <svg data-testid="icon-building2" {...props} />,
        ShieldCheck: (props) => <svg data-testid="icon-shield-check" {...props} />,
        ExternalLink: (props) => <svg data-testid="icon-external-link" {...props} />,
        LogOut: (props) => <svg data-testid="icon-logout" {...props} />,
    };
    return new Proxy(named, {
        get(target, prop) {
            if (prop in target) return target[prop];
            if (prop === "__esModule") return false;
            if (typeof prop !== "string") return undefined;
            const Stub = (props) => <svg data-testid={`icon-${String(prop)}`} {...props} />;
            Stub.displayName = String(prop);
            target[prop] = Stub;
            return Stub;
        },
    });
});

const mockUseTheme = useTheme;
const mockLogout = logout;

describe("SettingsPage", () => {
    beforeEach(() => {
        jest.clearAllMocks();

        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ organization: { userRole: "member" } }),
        });

        mockUseTheme.mockReturnValue({
            user: {
                login: "octocat",
            },
            refreshUser: jest.fn(),
            theme: "light",
        });

        mockLogout.mockResolvedValue(undefined);
        toast.loading.mockReturnValue("toast-id-1");
    });

    test("renders settings header and key sections", async () => {
        render(<SettingsPage />);

        expect(
            screen.getByRole("heading", { name: "Account Settings" }),
        ).toBeInTheDocument();
        expect(screen.getByText("Profile Settings")).toBeInTheDocument();
        expect(screen.getByText("Organization Management")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Sign Out" })).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /GitHub Profile/i })).toHaveAttribute(
            "href",
            "https://github.com/octocat",
        );

        await waitFor(() => {
            expect(global.fetch).toHaveBeenCalledTimes(1);
        });
    });

    test("shows OAuth section for admin users", async () => {
        global.fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ organization: { userRole: "admin" } }),
        });

        render(<SettingsPage />);

        await waitFor(() => {
            expect(screen.getByText("OAuth Configuration")).toBeInTheDocument();
        });

        expect(screen.getByTestId("oauth-card")).toBeInTheDocument();
        expect(screen.getByText(/Organization Admin/i)).toBeInTheDocument();
    });

    test("hides OAuth section for member users", async () => {
        render(<SettingsPage />);

        await waitFor(() => {
            expect(global.fetch).toHaveBeenCalled();
        });

        expect(screen.queryByText("OAuth Configuration")).not.toBeInTheDocument();
        expect(screen.getByText(/Organization Member/i)).toBeInTheDocument();
    });

    test("toggles profile and organization sections", async () => {
        render(<SettingsPage />);

        await waitFor(() => {
            expect(global.fetch).toHaveBeenCalled();
        });

        expect(screen.getByTestId("profile-card")).toBeInTheDocument();
        const collapseButtons = screen.getAllByRole("button", { name: "Collapse" });
        fireEvent.click(collapseButtons[0]);
        expect(screen.queryByTestId("profile-card")).not.toBeInTheDocument();

        expect(screen.getByTestId("organization-card")).toBeInTheDocument();
        fireEvent.click(collapseButtons[1]);
        expect(screen.queryByTestId("organization-card")).not.toBeInTheDocument();
    });

    test("handles sign out flow", async () => {
        render(<SettingsPage />);
        fireEvent.click(screen.getByRole("button", { name: "Sign Out" }));

        await waitFor(() => {
            expect(toast.loading).toHaveBeenCalledWith("Signing out...");
            expect(mockLogout).toHaveBeenCalledWith(false);
            expect(toast.update).toHaveBeenCalledWith(
                "toast-id-1",
                expect.objectContaining({ render: "Signed out successfully", type: "success" }),
            );
        });
    });
});
