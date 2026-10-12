import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import DashboardNavbar from '@/app/dashboard/components/DashboardNavbar';

// ── Driver.js mocks ───────────────────────────────────────────────────────────

const mockDrive = jest.fn();
const mockDestroy = jest.fn();
const mockDriverInstance = { drive: mockDrive, destroy: mockDestroy };
const mockDriverFn = jest.fn(() => mockDriverInstance);

jest.mock('driver.js', () => ({
  driver: (...args) => mockDriverFn(...args),
}));
jest.mock('driver.js/dist/driver.css', () => {});

// ── Next.js mocks ─────────────────────────────────────────────────────────────

jest.mock('next/link', () => {
  const MockLink = ({ href, children, prefetch, ...props }) => (
    <a href={href} {...props}>{children}</a>
  );
  MockLink.displayName = 'MockLink';
  return MockLink;
});

// ── Lucide mocks ──────────────────────────────────────────────────────────────

jest.mock('lucide-react', () => ({
  ChevronDown: (props) => <svg data-testid="icon-chevron-down" {...props} />,
  Building2:   (props) => <svg data-testid="icon-building2"    {...props} />,
  User:        (props) => <svg data-testid="icon-user"         {...props} />,
  Crown:       (props) => <svg data-testid="icon-crown"        {...props} />,
  RefreshCw:   (props) => <svg data-testid="icon-refresh"      {...props} />,
  Loader2:     (props) => <svg data-testid="icon-loader"       {...props} />,
  X:           (props) => <svg data-testid="icon-x"            {...props} />,
  Menu:        (props) => <svg data-testid="icon-menu"         {...props} />,
  Plug:        (props) => <svg data-testid="icon-plug"         {...props} />,
}));

// ── ThemeToggle mock ──────────────────────────────────────────────────────────

jest.mock('@/components/ThemeToggle', () => ({
  ThemeToggle: () => <div data-testid="theme-toggle" />,
}));

// ── useNavbar mock ────────────────────────────────────────────────────────────

const mockFetchInstallations = jest.fn();
const mockSetSelectedInstallation = jest.fn();
const mockResetSelection = jest.fn();
const mockSetActiveDropdown = jest.fn();
const mockGetAccountIcon = jest.fn((type) => type || 'user');

const defaultNavbarState = {
  installations: [],
  selectedInstallation: null,
  loading: { installations: false },
  error: null,
  activeDropdown: null,
  dropdownRefs: { installation: { current: null } },
  setActiveDropdown: mockSetActiveDropdown,
  getAccountIcon: mockGetAccountIcon,
  resetSelection: mockResetSelection,
  fetchInstallations: mockFetchInstallations,
  setSelectedInstallation: mockSetSelectedInstallation,
  userRole: 'user',
};

let mockNavbarState;

jest.mock('@/hooks/useNavbar', () => ({
  useNavbar: () => mockNavbarState,
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

const sampleInstallations = [
  { installationId: 1, account: { login: 'my-org',   type: 'organization' } },
  { installationId: 2, account: { login: 'personal', type: 'user' } },
];

function renderNavbar(props = {}) {
  return render(<DashboardNavbar onToggleSidebar={jest.fn()} {...props} />);
}

// ── Setup / Teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  mockNavbarState = { ...defaultNavbarState };
  mockFetchInstallations.mockReset();
  mockSetSelectedInstallation.mockReset();
  mockResetSelection.mockReset();
  mockSetActiveDropdown.mockReset();
  mockGetAccountIcon.mockImplementation((type) => type || 'user');
  mockDriverFn.mockClear();
  mockDrive.mockClear();
  mockDestroy.mockClear();
  localStorage.clear();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('DashboardNavbar', () => {
  // ── Smoke ────────────────────────────────────────────────────────────────────
  describe('smoke', () => {
    test('renders without crashing', () => {
      renderNavbar();
    });

    test('renders a nav element', () => {
      const { container } = renderNavbar();
      expect(container.querySelector('nav')).toBeInTheDocument();
    });

    test('renders ThemeToggle', () => {
      renderNavbar();
      expect(screen.getByTestId('theme-toggle')).toBeInTheDocument();
    });
  });

  // ── On mount ─────────────────────────────────────────────────────────────────
  describe('on mount', () => {
    test('calls fetchInstallations once on mount', () => {
      renderNavbar();
      expect(mockFetchInstallations).toHaveBeenCalledTimes(1);
    });
  });

  // ── Mobile menu ───────────────────────────────────────────────────────────────
  describe('mobile menu button', () => {
    test('renders hamburger button', () => {
      renderNavbar();
      expect(screen.getByRole('button', { name: /toggle sidebar/i })).toBeInTheDocument();
    });

    test('calls onToggleSidebar when hamburger clicked', () => {
      const onToggleSidebar = jest.fn();
      render(<DashboardNavbar onToggleSidebar={onToggleSidebar} />);
      fireEvent.click(screen.getByRole('button', { name: /toggle sidebar/i }));
      expect(onToggleSidebar).toHaveBeenCalledTimes(1);
    });
  });

  // ── GitHub Account dropdown button ────────────────────────────────────────────
  describe('GitHub Account dropdown button', () => {
    test('renders when no installation is selected', () => {
      renderNavbar();
      expect(screen.getByText('GitHub Account')).toBeInTheDocument();
    });

    test('has id="github-account-btn"', () => {
      renderNavbar();
      expect(document.getElementById('github-account-btn')).toBeInTheDocument();
    });

    test('is aria-expanded=false when dropdown is closed', () => {
      renderNavbar();
      expect(document.getElementById('github-account-btn')).toHaveAttribute('aria-expanded', 'false');
    });

    test('is aria-expanded=true when dropdown is open', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation' };
      renderNavbar();
      expect(document.getElementById('github-account-btn')).toHaveAttribute('aria-expanded', 'true');
    });

    test('clicking button calls setActiveDropdown with "installation"', () => {
      renderNavbar();
      fireEvent.click(document.getElementById('github-account-btn'));
      expect(mockSetActiveDropdown).toHaveBeenCalledWith('installation');
    });

    test('shows Loader2 spinner inside button while installations load', () => {
      mockNavbarState = { ...defaultNavbarState, loading: { installations: true } };
      renderNavbar();
      expect(screen.getByTestId('icon-loader')).toBeInTheDocument();
    });
  });

  // ── SelectionPill (installation selected) ─────────────────────────────────────
  describe('SelectionPill when installation is selected', () => {
    const selected = { installationId: 1, account: { login: 'my-org', type: 'organization' } };

    test('hides GitHub Account dropdown button', () => {
      mockNavbarState = { ...defaultNavbarState, selectedInstallation: selected };
      renderNavbar();
      expect(document.getElementById('github-account-btn')).toBeNull();
    });

    test('shows selected installation login name', () => {
      mockNavbarState = { ...defaultNavbarState, selectedInstallation: selected };
      renderNavbar();
      expect(screen.getByText('my-org')).toBeInTheDocument();
    });

    test('shows "GitHub Account" label in the pill', () => {
      mockNavbarState = { ...defaultNavbarState, selectedInstallation: selected };
      renderNavbar();
      expect(screen.getByText('GitHub Account:')).toBeInTheDocument();
    });

    test('clicking clear calls resetSelection with "installation"', () => {
      mockNavbarState = { ...defaultNavbarState, selectedInstallation: selected };
      renderNavbar();
      fireEvent.click(screen.getByTitle('Change GitHub Account'));
      expect(mockResetSelection).toHaveBeenCalledWith('installation');
    });
  });

  // ── Dropdown panel ────────────────────────────────────────────────────────────
  describe('installation dropdown panel', () => {
    test('not shown when activeDropdown is null', () => {
      renderNavbar();
      expect(screen.queryByText(/select installation/i)).not.toBeInTheDocument();
    });

    test('shown when activeDropdown is "installation"', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation' };
      renderNavbar();
      expect(screen.getByText(/select installation/i)).toBeInTheDocument();
    });

    test('renders installation login names', () => {
      mockNavbarState = {
        ...defaultNavbarState,
        activeDropdown: 'installation',
        installations: sampleInstallations,
      };
      renderNavbar();
      expect(screen.getByText('my-org')).toBeInTheDocument();
      expect(screen.getByText('personal')).toBeInTheDocument();
    });

    test('renders account type badges', () => {
      mockNavbarState = {
        ...defaultNavbarState,
        activeDropdown: 'installation',
        installations: sampleInstallations,
      };
      renderNavbar();
      expect(screen.getByText('organization')).toBeInTheDocument();
      expect(screen.getByText('user')).toBeInTheDocument();
    });

    test('clicking an installation calls setSelectedInstallation', () => {
      mockNavbarState = {
        ...defaultNavbarState,
        activeDropdown: 'installation',
        installations: sampleInstallations,
      };
      renderNavbar();
      fireEvent.click(screen.getByText('my-org'));
      expect(mockSetSelectedInstallation).toHaveBeenCalledWith(sampleInstallations[0]);
    });

    test('shows "No GitHub installations found" when list is empty', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation' };
      renderNavbar();
      expect(screen.getByText(/no github installations found/i)).toBeInTheDocument();
    });

    test('shows loading spinner and text while loading', () => {
      mockNavbarState = {
        ...defaultNavbarState,
        activeDropdown: 'installation',
        loading: { installations: true },
      };
      renderNavbar();
      expect(screen.getByText(/loading installations/i)).toBeInTheDocument();
    });

    test('refresh button calls fetchInstallations', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation' };
      renderNavbar();
      // fetchInstallations is called once on mount; clicking refresh adds one more
      fireEvent.click(screen.getByRole('button', { name: /refresh installations/i }));
      expect(mockFetchInstallations).toHaveBeenCalledTimes(2);
    });
  });

  // ── Admin — Install GitHub link ───────────────────────────────────────────────
  describe('Install GitHub link', () => {
    test('not shown for non-admin role', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation', userRole: 'user' };
      renderNavbar();
      expect(screen.queryByText(/install github/i)).not.toBeInTheDocument();
    });

    test('shown for admin role', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation', userRole: 'admin' };
      renderNavbar();
      expect(screen.getByText(/install github/i)).toBeInTheDocument();
    });

    test('Install GitHub link points to /home', () => {
      mockNavbarState = { ...defaultNavbarState, activeDropdown: 'installation', userRole: 'admin' };
      renderNavbar();
      expect(screen.getByRole('link', { name: /install github/i })).toHaveAttribute('href', '/home');
    });
  });

  // ── Error state ───────────────────────────────────────────────────────────────
  describe('error state', () => {
    test('no error element when error is null', () => {
      renderNavbar();
      expect(screen.queryByText('Failed to load')).not.toBeInTheDocument();
    });

    test('renders error message when error is set', () => {
      mockNavbarState = { ...defaultNavbarState, error: 'Failed to load' };
      renderNavbar();
      expect(screen.getByText('Failed to load')).toBeInTheDocument();
    });
  });

  // ── Driver.js onboarding tour ─────────────────────────────────────────────────
  describe('Driver.js onboarding tour', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      act(() => { jest.runOnlyPendingTimers(); });
      jest.useRealTimers();
    });

    test('starts the tour after 600 ms on first visit', () => {
      renderNavbar();
      act(() => { jest.advanceTimersByTime(700); });
      expect(mockDriverFn).toHaveBeenCalledTimes(1);
      expect(mockDrive).toHaveBeenCalledTimes(1);
    });

    test('does not start tour when already seen (localStorage flag set)', () => {
      localStorage.setItem('zyloch-account-tour-done', '1');
      renderNavbar();
      act(() => { jest.advanceTimersByTime(700); });
      expect(mockDriverFn).not.toHaveBeenCalled();
    });

    test('does not start tour when #github-account-btn is absent (installation selected)', () => {
      const selected = { installationId: 1, account: { login: 'my-org', type: 'organization' } };
      mockNavbarState = { ...defaultNavbarState, selectedInstallation: selected };
      renderNavbar();
      act(() => { jest.advanceTimersByTime(700); });
      expect(mockDriverFn).not.toHaveBeenCalled();
    });

    test('tour targets #github-account-btn', () => {
      renderNavbar();
      act(() => { jest.advanceTimersByTime(700); });
      const config = mockDriverFn.mock.calls[0][0];
      expect(config.steps[0].element).toBe('#github-account-btn');
    });

    test('tour popover has a title and description', () => {
      renderNavbar();
      act(() => { jest.advanceTimersByTime(700); });
      const { title, description } = mockDriverFn.mock.calls[0][0].steps[0].popover;
      expect(title).toBeTruthy();
      expect(description).toBeTruthy();
    });

    test('onDestroyStarted sets localStorage flag and calls destroy', () => {
      renderNavbar();
      act(() => { jest.advanceTimersByTime(700); });
      const config = mockDriverFn.mock.calls[0][0];
      config.onDestroyStarted();
      expect(localStorage.getItem('zyloch-account-tour-done')).toBe('1');
      expect(mockDestroy).toHaveBeenCalledTimes(1);
    });
  });
});
