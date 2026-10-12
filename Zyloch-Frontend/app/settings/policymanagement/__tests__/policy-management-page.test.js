import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import PolicyManagementPage from "../page";

jest.mock("@/app/settings/components/ScanOptionsCard", () => ({
    ScanOptionsCard: () => <div data-testid="scan-options-card">ScanOptionsCard</div>,
}));

jest.mock("@/app/settings/components/ScanPoliciesCard", () =>
    function MockScanPoliciesCard() {
        return <div data-testid="scan-policies-card">ScanPoliciesCard</div>;
    },
);

describe("Policy Management Page", () => {
    beforeEach(() => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ organization: { userRole: "admin", githubLogin: "octocat" } }),
        });
    });

    it("renders scan options by default", async () => {
        render(<PolicyManagementPage />);

        await waitFor(() => {
            expect(screen.getByTestId("scan-options-card")).toBeInTheDocument();
        });
    });

    it("switches to policies tab on click", async () => {
        render(<PolicyManagementPage />);

        await waitFor(() => {
            expect(screen.getByRole("button", { name: /policies/i })).toBeInTheDocument();
        });

        fireEvent.click(screen.getByRole("button", { name: /policies/i }));

        expect(screen.getByTestId("scan-policies-card")).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: /policy management/i })).toBeInTheDocument();
    });
});
