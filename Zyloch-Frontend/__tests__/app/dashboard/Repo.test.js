import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Repo from '@/app/dashboard/components/Repo';

// ── Mocks ──────────────────────────────────────────────────────────────────────

const mockReplace = jest.fn();
let mockSearch = '';

jest.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(mockSearch),
  useRouter: () => ({ replace: mockReplace }),
  usePathname: () => '/dashboard',
}));

// Default hook state — overridden per-test via mockRepoData
const defaultRepoData = {
  summaryAnalysis: { data: null, status: null, error: null },
  selectedInstallation: null,
  loading: { summary: false },
  startSummaryAnalysis: jest.fn(),
  refreshSummary: jest.fn(),
  retryFailedSummary: jest.fn(),
  fetchRepoSelection: jest.fn(),
  repoSelection: { status: 'ok', state: null, error: null },
  totalRepositories: 0,
  totalBranches: 0,
  totalTeams: 0,
  totalTeamMembers: 0,
  teamsArray: [],
  repositoriesArray: [],
  processedLanguages: [],
  allLanguages: [],
  summary: null,
  connectingInstallation: null,
  waitForInstallation: jest.fn(() => Promise.resolve(false)),
  cancelWaitForInstallation: jest.fn(),
};

let mockRepoData = { ...defaultRepoData };

jest.mock('@/hooks/useRepoData', () => ({
  useRepoData: () => mockRepoData,
}));

// Sub-component mocks — simple stubs so Repo's branching logic is isolated
jest.mock('@/app/dashboard/components/NoInstallationSelected', () => {
  const Mock = () => <div data-testid="no-installation-selected" />;
  Mock.displayName = 'NoInstallationSelected';
  return Mock;
});

jest.mock('@/app/dashboard/components/InstallationConnecting', () => {
  const Mock = ({ timedOut, onRetry }) => (
    <div data-testid="installation-connecting" data-timed-out={String(timedOut)}>
      <button onClick={onRetry}>Check again</button>
    </div>
  );
  Mock.displayName = 'InstallationConnecting';
  return Mock;
});

jest.mock('@/app/dashboard/components/RepoLoading', () => {
  const Mock = ({ message, variant = 'full' }) => (
    <div data-testid={variant === 'spinner' ? 'repo-spinner' : 'repo-loading'}>{message}</div>
  );
  Mock.displayName = 'RepoLoading';
  return Mock;
});

jest.mock('@/app/dashboard/components/RepoHeaderSection', () => {
  const Mock = (props) => (
    <div data-testid="repo-header-section">
      <span data-testid="repos-count">{props.totalRepositories}</span>
    </div>
  );
  Mock.displayName = 'RepoHeaderSection';
  return Mock;
});

jest.mock('@/app/dashboard/components/RepoChartsSection', () => {
  const Mock = () => <div data-testid="repo-charts-section" />;
  Mock.displayName = 'RepoChartsSection';
  return Mock;
});

jest.mock('@/app/dashboard/components/RepoPerformanceSection', () => {
  const Mock = () => <div data-testid="repo-performance-section" />;
  Mock.displayName = 'RepoPerformanceSection';
  return Mock;
});

jest.mock('lucide-react', () => ({
  AlertCircle: (props) => <svg data-testid="icon-alert-circle" {...props} />,
  Play:        (props) => <svg data-testid="icon-play"         {...props} />,
  Box:         (props) => <svg data-testid="icon-box"          {...props} />,
}));

// ── Helpers ────────────────────────────────────────────────────────────────────

function renderRepo() {
  return render(<Repo />);
}

// ── Setup / Teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  mockRepoData = {
    ...defaultRepoData,
    startSummaryAnalysis: jest.fn(),
    refreshSummary: jest.fn(),
    retryFailedSummary: jest.fn(),
    fetchRepoSelection: jest.fn(),
    waitForInstallation: jest.fn(() => Promise.resolve(false)),
    cancelWaitForInstallation: jest.fn(),
  };
  mockSearch = '';
  mockReplace.mockClear();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Repo', () => {
  // ── No installation selected ──────────────────────────────────────────────

  describe('no installation selected', () => {
    test('renders NoInstallationSelected when selectedInstallation is null', () => {
      mockRepoData.selectedInstallation = null;
      renderRepo();
      expect(screen.getByTestId('no-installation-selected')).toBeInTheDocument();
    });

    test('does not render main content sections', () => {
      mockRepoData.selectedInstallation = null;
      renderRepo();
      expect(screen.queryByTestId('repo-header-section')).not.toBeInTheDocument();
      expect(screen.queryByTestId('repo-charts-section')).not.toBeInTheDocument();
      expect(screen.queryByTestId('repo-performance-section')).not.toBeInTheDocument();
    });
  });

  // ── Back from the GitHub App install redirect ─────────────────────────────

  describe('post-install redirect', () => {
    test('shows the connecting screen, not the empty state, while the install arrives', () => {
      mockRepoData.connectingInstallation = { installationId: '162542487', timedOut: false };
      renderRepo();
      expect(screen.getByTestId('installation-connecting')).toHaveAttribute('data-timed-out', 'false');
      expect(screen.queryByTestId('no-installation-selected')).not.toBeInTheDocument();
    });

    test('passes the timed-out state through and "Check again" restarts the wait', () => {
      mockRepoData.connectingInstallation = { installationId: '162542487', timedOut: true };
      renderRepo();
      expect(screen.getByTestId('installation-connecting')).toHaveAttribute('data-timed-out', 'true');
      fireEvent.click(screen.getByText('Check again'));
      expect(mockRepoData.waitForInstallation).toHaveBeenCalledWith('162542487');
    });

    test('starts waiting for the installation named in the redirect URL', () => {
      mockSearch = 'installation_id=162542487&setup_action=install';
      renderRepo();
      expect(mockRepoData.waitForInstallation).toHaveBeenCalledWith('162542487');
    });

    test('does not wait when there is no redirect', () => {
      renderRepo();
      expect(mockRepoData.waitForInstallation).not.toHaveBeenCalled();
    });

    test('drops only the redirect params from the URL once connected', async () => {
      mockSearch = 'installation_id=162542487&setup_action=install&dev=true';
      mockRepoData.waitForInstallation = jest.fn(() => Promise.resolve(true));
      renderRepo();
      await waitFor(() =>
        expect(mockReplace).toHaveBeenCalledWith('/dashboard?dev=true', { scroll: false })
      );
    });

    test('keeps the redirect params when the wait did not connect', async () => {
      mockSearch = 'installation_id=162542487&setup_action=install';
      renderRepo();
      await Promise.resolve();
      expect(mockReplace).not.toHaveBeenCalled();
    });

    test('stops waiting when the dashboard unmounts', () => {
      mockSearch = 'installation_id=162542487&setup_action=install';
      const { unmount } = renderRepo();
      unmount();
      expect(mockRepoData.cancelWaitForInstallation).toHaveBeenCalled();
    });
  });

  // ── Checking whether a sync is running ────────────────────────────────────

  describe('summary check (before the server answers)', () => {
    test.each([null, 'idle', 'checking'])(
      'shows only the round spinner, never the sync screen, when status is %s',
      (status) => {
        mockRepoData.selectedInstallation = { installationId: 'inst-1' };
        mockRepoData.summaryAnalysis = { data: null, status, error: null };
        renderRepo();
        expect(screen.getByTestId('repo-spinner')).toBeInTheDocument();
        expect(screen.queryByTestId('repo-loading')).not.toBeInTheDocument();
        expect(screen.queryByTestId('repo-header-section')).not.toBeInTheDocument();
      }
    );

    test('shows the spinner, not stale data, when the summary belongs to another installation', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-2' };
      mockRepoData.summaryAnalysis = {
        installationId: 'inst-1',
        data: { repos: [] },
        status: 'completed',
        error: null,
      };
      renderRepo();
      expect(screen.getByTestId('repo-spinner')).toBeInTheDocument();
      expect(screen.queryByTestId('repo-header-section')).not.toBeInTheDocument();
    });

    test('shows the spinner when completed without data', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.summaryAnalysis = { data: null, status: 'completed', error: null };
      renderRepo();
      expect(screen.getByTestId('repo-spinner')).toBeInTheDocument();
    });

    test('a manual refresh (loading.summary) does not hide a completed dashboard', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.loading = { summary: true };
      mockRepoData.summaryAnalysis = { data: { repos: [] }, status: 'completed', error: null };
      renderRepo();
      expect(screen.getByTestId('repo-header-section')).toBeInTheDocument();
      expect(screen.queryByTestId('repo-spinner')).not.toBeInTheDocument();
    });
  });

  // ── Sync job running ──────────────────────────────────────────────────────

  describe('analysis in-progress / pending', () => {
    test.each(['in_progress', 'pending'])(
      'shows only the sync screen when status is "%s"',
      (status) => {
        mockRepoData.selectedInstallation = { installationId: 'inst-1' };
        mockRepoData.loading = { summary: false };
        mockRepoData.summaryAnalysis = {
          data: { repos: [] },
          status,
          error: null,
        };
        renderRepo();
        expect(screen.getByTestId('repo-loading')).toHaveTextContent(
          'We are reading every repository you selected'
        );
        expect(screen.queryByTestId('repo-header-section')).not.toBeInTheDocument();
      }
    );
  });

  // ── Failed / error state ──────────────────────────────────────────────────

  describe('failed / error state', () => {
    test.each(['failed', 'error'])(
      'renders "Analysis Failed" heading when status is "%s"',
      (status) => {
        mockRepoData.selectedInstallation = { installationId: 'inst-1' };
        mockRepoData.loading = { summary: false };
        mockRepoData.summaryAnalysis = {
          data: null,
          status,
          error: null,
        };
        renderRepo();
        expect(screen.getByText('Analysis Failed')).toBeInTheDocument();
      }
    );

    test('shows custom error message from summaryAnalysis.error', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.loading = { summary: false };
      mockRepoData.summaryAnalysis = {
        data: null,
        status: 'failed',
        error: 'GitHub API rate limit exceeded',
      };
      renderRepo();
      expect(
        screen.getByText('GitHub API rate limit exceeded')
      ).toBeInTheDocument();
    });

    test('shows fallback error message when error field is absent', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.loading = { summary: false };
      mockRepoData.summaryAnalysis = {
        data: null,
        status: 'failed',
        error: null,
      };
      renderRepo();
      expect(
        screen.getByText(
          'Unable to analyze repositories. Please try again.'
        )
      ).toBeInTheDocument();
    });

    test('renders "Retry Analysis" button', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.loading = { summary: false };
      mockRepoData.summaryAnalysis = { data: null, status: 'error', error: null };
      renderRepo();
      expect(
        screen.getByRole('button', { name: /Retry Analysis/i })
      ).toBeInTheDocument();
    });

    test('calls retryFailedSummary when retry button is clicked', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.loading = { summary: false };
      mockRepoData.summaryAnalysis = { data: null, status: 'error', error: null };
      renderRepo();
      fireEvent.click(screen.getByRole('button', { name: /Retry Analysis/i }));
      expect(mockRepoData.retryFailedSummary).toHaveBeenCalledTimes(1);
    });

    test('disables retry button and shows "Retrying..." while loading.summary is true', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-1' };
      mockRepoData.loading = { summary: true };
      mockRepoData.summaryAnalysis = { data: { repos: [] }, status: 'error', error: null };
      renderRepo();
      const btn = screen.getByRole('button', { name: /Retrying.../i });
      expect(btn).toBeDisabled();
    });
  });

  // ── Main content (happy path) ─────────────────────────────────────────────

  describe('main content (completed state)', () => {
    function setupHappyPath(overrides = {}) {
      mockRepoData = {
        ...mockRepoData,
        selectedInstallation: { installationId: 'inst-1' },
        loading: { summary: false },
        summaryAnalysis: {
          data: { repos: [] },
          status: 'completed',
          error: null,
        },
        totalRepositories: 12,
        totalBranches: 34,
        totalTeams: 3,
        totalTeamMembers: 18,
        teamsArray: [],
        repositoriesArray: [],
        processedLanguages: [],
        allLanguages: [],
        summary: { public: 8, private: 4 },
        ...overrides,
      };
    }

    test('renders RepoHeaderSection', () => {
      setupHappyPath();
      renderRepo();
      expect(screen.getByTestId('repo-header-section')).toBeInTheDocument();
    });

    test('renders RepoChartsSection', () => {
      setupHappyPath();
      renderRepo();
      expect(screen.getByTestId('repo-charts-section')).toBeInTheDocument();
    });

    test('renders RepoPerformanceSection', () => {
      setupHappyPath();
      renderRepo();
      expect(screen.getByTestId('repo-performance-section')).toBeInTheDocument();
    });

    test('passes totalRepositories to RepoHeaderSection', () => {
      setupHappyPath({ totalRepositories: 42 });
      renderRepo();
      expect(screen.getByTestId('repos-count')).toHaveTextContent('42');
    });

    test('does not render NoInstallationSelected', () => {
      setupHappyPath();
      renderRepo();
      expect(
        screen.queryByTestId('no-installation-selected')
      ).not.toBeInTheDocument();
    });

    test('does not render RepoLoading', () => {
      setupHappyPath();
      renderRepo();
      expect(screen.queryByTestId('repo-loading')).not.toBeInTheDocument();
    });
  });

  // ── Side-effects ──────────────────────────────────────────────────────────

  describe('side-effects', () => {
    test('calls startSummaryAnalysis with installationId on mount', () => {
      mockRepoData.selectedInstallation = { installationId: 'inst-42' };
      mockRepoData.loading = { summary: false };
      mockRepoData.summaryAnalysis = {
        data: { repos: [] },
        status: 'completed',
        error: null,
      };
      renderRepo();
      expect(mockRepoData.startSummaryAnalysis).toHaveBeenCalledWith('inst-42');
    });

    test('does not call startSummaryAnalysis when no installation is selected', () => {
      mockRepoData.selectedInstallation = null;
      renderRepo();
      expect(mockRepoData.startSummaryAnalysis).not.toHaveBeenCalled();
    });
  });
});
