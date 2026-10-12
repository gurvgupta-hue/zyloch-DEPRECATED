import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import DashboardSidebar from '@/app/dashboard/components/DashboardSidebar';

// ── Mocks ──────────────────────────────────────────────────────────────────────

const mockPathname = jest.fn(() => '/dashboard');
jest.mock('next/navigation', () => ({
  usePathname: () => mockPathname(),
}));

const mockUseTheme = jest.fn(() => ({ theme: 'dark' }));
jest.mock('@/context/ThemeContext', () => ({
  useTheme: (...args) => mockUseTheme(...args),
}));

let mockSelectedInstallation = null;
jest.mock('@/store/useGithubStore', () => ({
  useGithubStore: (selector) =>
    selector({ selectedInstallation: mockSelectedInstallation }),
}));

jest.mock('next/image', () => {
  const MockImage = ({ src, alt, priority, fill, quality, placeholder, blurDataURL, loader, unoptimized, onLoad, onError, ...props }) => (
    <img src={typeof src === 'string' ? src : 'mock-img'} alt={alt} {...props} />
  );
  MockImage.displayName = 'MockImage';
  return MockImage;
});

jest.mock('next/link', () => {
  const MockLink = ({ href, children, ...props }) => (
    <a href={href} {...props}>
      {children}
    </a>
  );
  MockLink.displayName = 'MockLink';
  return MockLink;
});

jest.mock('lucide-react', () => ({
  PanelLeftClose: (props) => <svg data-testid="icon-panel-close" {...props} />,
  PanelLeftOpen: (props) => <svg data-testid="icon-panel-open" {...props} />,
}));

jest.mock('@/public/assets/icons/dashboard.svg', () => {
  const Icon = (props) => <svg data-testid="icon-dashboard" {...props} />;
  Icon.displayName = 'DashboardIcon';
  return Icon;
});

jest.mock('@/public/assets/icons/survey.svg', () => {
  const Icon = (props) => <svg data-testid="icon-scan" {...props} />;
  Icon.displayName = 'ScanIcon';
  return Icon;
});

jest.mock('@/public/assets/icons/setting.svg', () => {
  const Icon = (props) => <svg data-testid="icon-setting" {...props} />;
  Icon.displayName = 'SettingIcon';
  return Icon;
});

jest.mock('@/public/zyloch_logo.webp', () => 'logo-dark.webp');
jest.mock('@/public/zyloch-black-logo.png', () => 'logo-light.png');

// ── Helpers ────────────────────────────────────────────────────────────────────

function renderSidebar(props = {}) {
  return render(<DashboardSidebar {...props} />);
}

// ── Setup / Teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  mockPathname.mockReturnValue('/dashboard');
  mockUseTheme.mockReturnValue({ theme: 'dark' });
  mockSelectedInstallation = null;
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('DashboardSidebar', () => {
  // ── Collapsed rail (isOpen = false, default) ─────────────────────────────

  describe('collapsed rail (isOpen=false)', () => {
    test('renders Dashboard and Settings as nav links', () => {
      renderSidebar();

      expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute(
        'href',
        '/dashboard'
      );
      expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute(
        'href',
        '/settings'
      );
    });

    test('renders ScanOps as disabled when no installation is selected', () => {
      mockSelectedInstallation = null;
      renderSidebar();

      const disabled = screen.getByRole('generic', {
        name: 'Select an installation first',
      });
      expect(disabled).toHaveAttribute('aria-disabled', 'true');
      expect(screen.queryByRole('link', { name: 'ScanOps' })).toBeNull();
    });

    test('renders ScanOps as a link when an installation is selected', () => {
      mockSelectedInstallation = { installationId: 'abc123' };
      renderSidebar();

      expect(screen.getByRole('link', { name: 'ScanOps' })).toHaveAttribute(
        'href',
        '/scanops/overview'
      );
    });

    test('does not show toggle button by default', () => {
      renderSidebar();

      expect(
        screen.queryByRole('button', { name: 'Expand dashboard sidebar' })
      ).toBeNull();
    });

    test('shows expand toggle button when showToggle=true', () => {
      renderSidebar({ showToggle: true });

      expect(
        screen.getByRole('button', { name: 'Expand dashboard sidebar' })
      ).toBeInTheDocument();
      expect(screen.getByTestId('icon-panel-open')).toBeInTheDocument();
    });

    test('calls onToggle when expand toggle button is clicked', () => {
      const onToggle = jest.fn();
      renderSidebar({ showToggle: true, onToggle });

      fireEvent.click(screen.getByRole('button', { name: 'Expand dashboard sidebar' }));

      expect(onToggle).toHaveBeenCalledTimes(1);
    });

    test('shows tooltip on mouse enter for a nav link', () => {
      mockSelectedInstallation = { installationId: 'abc123' };
      renderSidebar();

      fireEvent.mouseEnter(screen.getByRole('link', { name: 'Dashboard' }));

      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });

    test('hides tooltip on mouse leave', () => {
      mockSelectedInstallation = { installationId: 'abc123' };
      renderSidebar();

      const link = screen.getByRole('link', { name: 'Dashboard' });
      fireEvent.mouseEnter(link);
      fireEvent.mouseLeave(link);

      // After leave, tooltip div is gone (only the nav link label text remains via aria-label)
      const tooltips = screen.queryAllByText('Dashboard');
      // The aria-label is on the element itself; no standalone tooltip element remains
      tooltips.forEach((el) => {
        expect(el.closest('[class*="fixed"]')).toBeNull();
      });
    });

    test('shows "Select an installation first" tooltip when hovering disabled ScanOps', () => {
      mockSelectedInstallation = null;
      renderSidebar();

      const disabled = screen.getByRole('generic', {
        name: 'Select an installation first',
      });
      fireEvent.mouseEnter(disabled);

      expect(
        screen.getByText('Select an installation first')
      ).toBeInTheDocument();
    });

    test('active pill is present for the current route', () => {
      mockPathname.mockReturnValue('/dashboard');
      const { container } = renderSidebar();

      // Active pill is the span with rounded-r-full class
      const pill = container.querySelector('.rounded-r-full');
      expect(pill).toBeInTheDocument();
    });

    test('active pill is absent when route does not match any nav item', () => {
      mockPathname.mockReturnValue('/some-other-page');
      const { container } = renderSidebar();

      expect(container.querySelector('.rounded-r-full')).toBeNull();
    });
  });

  // ── Expanded drawer (isOpen = true) ──────────────────────────────────────

  describe('expanded drawer (isOpen=true)', () => {
    test('renders Dashboard and Settings as nav links', () => {
      mockSelectedInstallation = { installationId: 'abc123' };
      renderSidebar({ isOpen: true });

      expect(screen.getByRole('link', { name: /dashboard/i })).toHaveAttribute(
        'href',
        '/dashboard'
      );
      expect(screen.getByRole('link', { name: /settings/i })).toHaveAttribute(
        'href',
        '/settings'
      );
    });

    test('renders ScanOps as a link when installation is selected', () => {
      mockSelectedInstallation = { installationId: 'abc123' };
      renderSidebar({ isOpen: true });

      expect(screen.getByRole('link', { name: /scanops/i })).toHaveAttribute(
        'href',
        '/scanops/overview'
      );
    });

    test('renders ScanOps as disabled when no installation is selected', () => {
      mockSelectedInstallation = null;
      renderSidebar({ isOpen: true });

      // Should not be a link
      expect(screen.queryByRole('link', { name: /scanops/i })).toBeNull();

      // Should be a non-interactive div with title
      const disabled = screen.getByTitle('Select an installation first');
      expect(disabled).toBeInTheDocument();
    });

    test('disabled ScanOps div contains label text', () => {
      mockSelectedInstallation = null;
      renderSidebar({ isOpen: true });

      const disabled = screen.getByTitle('Select an installation first');
      expect(disabled).toHaveTextContent('ScanOps');
    });

    test('does not show collapse toggle by default', () => {
      renderSidebar({ isOpen: true });

      expect(
        screen.queryByRole('button', { name: 'Collapse dashboard sidebar' })
      ).toBeNull();
    });

    test('shows collapse toggle button when showToggle=true', () => {
      renderSidebar({ isOpen: true, showToggle: true });

      expect(
        screen.getByRole('button', { name: 'Collapse dashboard sidebar' })
      ).toBeInTheDocument();
      expect(screen.getByTestId('icon-panel-close')).toBeInTheDocument();
    });

    test('calls onToggle when collapse toggle button is clicked', () => {
      const onToggle = jest.fn();
      renderSidebar({ isOpen: true, showToggle: true, onToggle });

      fireEvent.click(
        screen.getByRole('button', { name: 'Collapse dashboard sidebar' })
      );

      expect(onToggle).toHaveBeenCalledTimes(1);
    });

    test('renders the logo image in expanded mode', () => {
      renderSidebar({ isOpen: true });

      expect(screen.getByAltText('Zyloch')).toBeInTheDocument();
    });

    test('applies active styles to the current route link', () => {
      mockSelectedInstallation = { installationId: 'abc123' };
      mockPathname.mockReturnValue('/scanops/overview');
      renderSidebar({ isOpen: true });

      const link = screen.getByRole('link', { name: /scanops/i });
      expect(link.className).toMatch(/bg-\[rgba/);
    });

    test('renders "Workspace" section label', () => {
      renderSidebar({ isOpen: true });

      expect(screen.getByText('Workspace')).toBeInTheDocument();
    });
  });
});
