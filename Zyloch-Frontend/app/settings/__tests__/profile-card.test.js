import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import { ProfileCard } from "../components/ProfileCard";

jest.mock("next/image", () => ({
    __esModule: true,
    default: (props) => <img alt={props.alt} src={props.src} />,
}));

jest.mock("@/context/ThemeContext", () => ({
    useTheme: jest.fn(() => ({
        theme: "light",
        timeZone: "Asia/Kolkata",
        setTimeZone: jest.fn(),
        user: {
            login: "testuser",
            name: "Test User",
            email: "test@example.com",
            created_at: "2024-01-01T00:00:00.000Z",
            avatar_url: "https://example.com/avatar.png",
            organizationId: { name: "Test Org" },
        },
        TIME_ZONE_OPTIONS: [{ value: "Asia/Kolkata", label: "Asia/Kolkata" }],
    })),
    TIME_ZONE_OPTIONS: [{ value: "Asia/Kolkata", label: "Asia/Kolkata" }],
}));

describe("ProfileCard", () => {
    it("renders profile details from theme context", () => {
        render(<ProfileCard />);

        expect(screen.getAllByText(/test user/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/testuser/i).length).toBeGreaterThan(0);
        expect(screen.getByText(/asia\/kolkata/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole("button", { name: /show/i }));
        expect(screen.getByText(/test@example.com/i)).toBeInTheDocument();
    });
});
