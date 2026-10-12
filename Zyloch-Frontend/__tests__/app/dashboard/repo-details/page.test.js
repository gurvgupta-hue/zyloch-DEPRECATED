import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import RepoDetailsPage from "@/app/dashboard/repo-details/page";

const mockPush = jest.fn();
const mockUseInteractiveTable = jest.fn();
let mockType = "public";
let mockRepositories = [];

jest.mock("next/navigation", () => ({
    useRouter: () => ({ push: mockPush }),
    useSearchParams: () => ({ get: () => mockType }),
}));

jest.mock("next/link", () => {
    const MockLink = ({ href, children, ...props }) => (
        <a href={href} {...props}>
            {children}
        </a>
    );
    MockLink.displayName = "MockLink";
    return MockLink;
});

jest.mock("@/hooks/useRepoData", () => ({
    useRepoData: () => ({ repositoriesArray: mockRepositories }),
}));

jest.mock("@/app/scanops/components/scan/shared/useInteractiveTable", () => ({
    useInteractiveTable: (...args) => mockUseInteractiveTable(...args),
}));

jest.mock("lucide-react", () => {
    const icon = (name) => {
        const Icon = (props) => <svg data-testid={`icon-${name}`} {...props} />;
        Icon.displayName = name;
        return Icon;
    };

    return {
        Globe: icon("globe"),
        Lock: icon("lock"),
        GitFork: icon("git-fork"),
        Star: icon("star"),
        GitCommit: icon("git-commit"),
        Code2: icon("code-2"),
        GitBranch: icon("git-branch"),
        ChevronRight: icon("chevron-right"),
        Archive: icon("archive"),
        Timer: icon("timer"),
        ExternalLink: icon("external-link"),
    };
});

const repositories = [
    {
        name: "public-repo",
        url: "https://github.com/example/public-repo",
        isPrivate: false,
        forks: 2,
        stars: 5,
        commits: 10,
        branches: 3,
        lastActive: "2026-06-14T00:00:00.000Z",
        description: "Public repository",
    },
    {
        name: "private-repo",
        url: "https://github.com/example/private-repo",
        isPrivate: true,
        forks: 0,
        stars: 1,
        commits: 4,
        branches: 1,
        isArchived: true,
        hasStaleBranches: true,
    },
];

const renderPage = (type = "public", data = repositories) => {
    mockType = type;
    mockRepositories = data;
    return render(<RepoDetailsPage />);
};

beforeEach(() => {
    mockPush.mockReset();
    mockUseInteractiveTable.mockReset();
    mockType = "public";
    mockRepositories = [];
});

describe("RepoDetailsPage", () => {
    test("renders the full-width themed layout shell", () => {
        const { container } = renderPage();
        const page = container.firstElementChild;
        const shell = page.firstElementChild;

        expect(page).toHaveClass("min-h-screen", "p-3", "sm:p-6");
        expect(shell).toHaveClass("w-full", "border", "border-[var(--border)]", "bg-[var(--surface)]");
    });

    test("renders header and repository filter navigation", () => {
        renderPage();

        expect(screen.getByRole("heading", { name: "Repository Insights" })).toBeInTheDocument();
        expect(screen.getByText("Deep dive into stars, forks, commits, and repository activity.")).toBeInTheDocument();
        expect(screen.getByRole("link", { name: "Dashboard" })).toHaveAttribute("href", "/dashboard");
        expect(screen.getByRole("navigation", { name: "Repository filters" })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /Public 1/i })).toHaveAttribute("aria-current", "page");
    });

    test("shows filter counts and routes to the selected filter", () => {
        renderPage();

        expect(screen.getByRole("button", { name: /Private 1/i })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /Forks 1/i })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /Archived 1/i })).toBeInTheDocument();

        fireEvent.click(screen.getByRole("button", { name: /Private 1/i }));
        expect(mockPush).toHaveBeenCalledWith("/dashboard/repo-details?type=private");
    });

    test("renders aggregate stats for the active filter", async () => {
        renderPage();

        await waitFor(() => {
            const starsCard = screen.getByText("Total Stars").closest("div.flex");
            const forksCard = screen.getByText("Total Forks").closest("div.flex");
            const commitsCard = screen.getByText("Total Commits").closest("div.flex");
            const branchesCard = screen.getByText("Total Branches").closest("div.flex");

            expect(within(starsCard.parentElement).getByText("5")).toBeInTheDocument();
            expect(within(forksCard.parentElement).getByText("2")).toBeInTheDocument();
            expect(within(commitsCard.parentElement).getByText("10")).toBeInTheDocument();
            expect(within(branchesCard.parentElement).getByText("3")).toBeInTheDocument();
        });
    });

    test("renders table structure, repository data, formatted date, and action label", () => {
        renderPage();

        expect(screen.getByRole("table")).toHaveClass("w-full", "min-w-[820px]");
        expect(screen.getByText("public-repo")).toBeInTheDocument();
        expect(screen.getByText("Public repository")).toBeInTheDocument();
        expect(screen.getByText("Jun 14, 2026")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Open public-repo" })).toBeInTheDocument();
        expect(mockUseInteractiveTable).toHaveBeenCalledWith(
            expect.objectContaining({
                storageKey: "dashboard-repo-details-table",
                minWidth: 92,
                deps: [1],
            })
        );
    });

    test("shows empty state and routes back to public repositories", () => {
        renderPage("private", repositories.filter((repository) => !repository.isPrivate));

        expect(screen.getByRole("heading", { name: "Nothing here yet" })).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "View All Repositories" }));
        expect(mockPush).toHaveBeenCalledWith("/dashboard/repo-details?type=public");
    });
});
