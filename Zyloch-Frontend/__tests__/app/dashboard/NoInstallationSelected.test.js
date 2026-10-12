import React from "react";
import { render, screen } from "@testing-library/react";
import NoInstallationSelected from "@/app/dashboard/components/NoInstallationSelected";

// ── Mocks ─────────────────────────────────────────────────────────────────────

jest.mock("lucide-react", () => ({
  ChevronDown: (props) => <svg data-testid="icon-chevron-down" {...props} />,
  Building2: (props) => <svg data-testid="icon-building2" {...props} />,
  User: (props) => <svg data-testid="icon-user" {...props} />,
  Crown: (props) => <svg data-testid="icon-crown" {...props} />,
  Check: (props) => <svg data-testid="icon-check" {...props} />,
  ArrowRight: (props) => <svg data-testid="icon-arrow-right" {...props} />,
}));

jest.mock("react-icons/fa", () => ({
  FaGithub: (props) => <svg data-testid="icon-github" {...props} />,
}));

// ── Helper ────────────────────────────────────────────────────────────────────

function renderComponent() {
  return render(<NoInstallationSelected />);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("NoInstallationSelected", () => {
  // ── Smoke ──────────────────────────────────────────────────────────────────

  describe("smoke", () => {
    test("renders without crashing", () => {
      expect(() => renderComponent()).not.toThrow();
    });
  });

  // ── Header / Main Content ─────────────────────────────────────────────────

  describe("main content", () => {
    test("renders the GitHub icon", () => {
      renderComponent();
      expect(screen.getByTestId("icon-github")).toBeInTheDocument();
    });

    test("renders the headline", () => {
      renderComponent();
      expect(
        screen.getByText("Connect Your GitHub Account")
      ).toBeInTheDocument();
    });

    test("renders the description", () => {
      renderComponent();
      expect(
        screen.getByText(
          "Select a GitHub installation to access repository analytics and insights"
        )
      ).toBeInTheDocument();
    });

    test("headline is an h1 element for accessibility", () => {
      renderComponent();

      const heading = screen.getByRole("heading", { level: 1 });

      expect(heading).toHaveTextContent("Connect Your GitHub Account");
    });
  });

  // ── Layout ────────────────────────────────────────────────────────────────

  describe("layout", () => {
    test("has flex centering classes on container", () => {
      renderComponent();

      const container = document.querySelector(".w-full.h-full");

      expect(container).toHaveClass(
        "flex",
        "items-center",
        "justify-center"
      );
    });

    test("has text-center class on content wrapper", () => {
      renderComponent();

      const contentWrapper = document.querySelector(
        ".flex.flex-col.items-center.text-center"
      );

      expect(contentWrapper).toBeInTheDocument();
    });

    test("has max-w-md constraint on content", () => {
      renderComponent();

      const contentWrapper = document.querySelector(".max-w-md");

      expect(contentWrapper).toBeInTheDocument();
    });
  });

  // ── Styling ───────────────────────────────────────────────────────────────

  describe("styling", () => {
    test("GitHub icon has primary color class", () => {
      renderComponent();

      const icon = screen.getByTestId("icon-github");

      expect(icon).toHaveClass("text-[var(--color-primary)]");
    });

    test("icon container has rounded-full and background", () => {
      renderComponent();

      const iconContainer =
        screen.getByTestId("icon-github").closest(".rounded-full");

      expect(iconContainer).toBeInTheDocument();
      expect(iconContainer).toHaveClass("rounded-full");
      expect(iconContainer).toHaveClass("bg-[var(--color-primary)]/10");
      expect(iconContainer).toHaveClass("w-14", "h-14");
    });
  });

  // ── Demo Panel (Disabled) ─────────────────────────────────────────────────

  describe("demo panel (disabled)", () => {
    test("does not render demo card", () => {
      renderComponent();

      expect(screen.queryByText("GitHub Account")).not.toBeInTheDocument();
      expect(screen.queryByText("Accounts")).not.toBeInTheDocument();
      expect(screen.queryByText("Select")).not.toBeInTheDocument();
      expect(screen.queryByText("Ready")).not.toBeInTheDocument();

      expect(
        screen.queryByTestId("icon-building2")
      ).not.toBeInTheDocument();

      expect(
        screen.queryByTestId("icon-chevron-down")
      ).not.toBeInTheDocument();
    });

    test("does not render progress steps", () => {
      renderComponent();

      expect(screen.queryByText("1")).not.toBeInTheDocument();
      expect(screen.queryByText("2")).not.toBeInTheDocument();
    });

    test("does not render installation names", () => {
      renderComponent();

      expect(
        screen.queryByText("my-organization")
      ).not.toBeInTheDocument();

      expect(
        screen.queryByText("personal-account")
      ).not.toBeInTheDocument();

      expect(
        screen.queryByText("enterprise-corp")
      ).not.toBeInTheDocument();
    });
  });

  // ── Padding & Spacing ─────────────────────────────────────────────────────

  describe("padding and spacing", () => {
    test("has padding on main container", () => {
      renderComponent();

      const container = document.querySelector(".p-6");

      expect(container).toBeInTheDocument();
    });

    test("has margin bottom on icon container", () => {
      renderComponent();

      const iconContainer =
        screen.getByTestId("icon-github").closest(".mb-4");

      expect(iconContainer).toBeInTheDocument();
    });

    test("has margin bottom on heading", () => {
      renderComponent();

      const heading = document.querySelector(".mb-2");

      expect(heading).toHaveTextContent("Connect Your GitHub Account");
    });
  });
});