import { render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import SettingsPage from "../page";

jest.mock("../components/ProfileCard", () => ({
    ProfileCard: () => <div data-testid="profile-card">ProfileCard</div>,
}));

jest.mock("../components/OrganizationDetailsCard", () => ({
    OrganizationDetailsCard: () => <div data-testid="org-details-card">OrgDetailsCard</div>,
}));

jest.mock("../components/OAuthConfigCard", () => ({
    OAuthConfigCard: () => <div data-testid="oauth-config-card">OAuthConfigCard</div>,
}));

jest.mock("@/components/ThemeToggle", () => ({
    ThemeToggle: () => <button type="button">Theme Toggle</button>,
}));

jest.mock("@/context/ThemeContext", () => ({
    useTheme: jest.fn(() => ({
        user: { login: "octocat" },
        theme: "light",
        refreshUser: jest.fn(),
    })),
}));

describe("Settings Page", () => {
    beforeEach(() => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ organization: { userRole: "member" } }),
        });
    });

    it("renders profile and organization cards", async () => {
        render(<SettingsPage />);

        await waitFor(() => {
            expect(global.fetch).toHaveBeenCalled();
        });

        expect(screen.getByRole("heading", { name: /account settings/i })).toBeInTheDocument();
        expect(screen.getByTestId("profile-card")).toBeInTheDocument();
        expect(screen.getByTestId("org-details-card")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
    });

    it("shows OAuthConfigCard for admin users", async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ organization: { userRole: "admin" } }),
        });

        render(<SettingsPage />);

        await waitFor(() => {
            expect(screen.getByTestId("oauth-config-card")).toBeInTheDocument();
        });
    });
});
