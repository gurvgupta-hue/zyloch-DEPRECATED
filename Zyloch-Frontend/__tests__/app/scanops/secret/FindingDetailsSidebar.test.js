import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import FindingDetailsSidebar from '@/app/scanops/components/scan/secret/FindingDetailsSidebar';

// ── Mocks ──────────────────────────────────────────────────────────────────────

jest.mock('lucide-react', () => {
  const icon = (name) => {
    const C = (props) => <svg data-testid={`icon-${name}`} aria-hidden="true" {...props} />;
    C.displayName = name;
    return C;
  };
  return {
    X: icon('X'),
    AlertCircle: icon('AlertCircle'),
    Copy: icon('Copy'),
    Check: icon('Check'),
    Eye: icon('Eye'),
    EyeOff: icon('EyeOff'),
  };
});

// ── Helpers ────────────────────────────────────────────────────────────────────

const makeFinding = (overrides = {}) => ({
  pattern_type: 'Secret Detected – AWS Access Key',
  severity: 'critical',
  category: 'Secrets and Credentials',
  description: 'Possible exposed secret or credential detected: AWS access key ID.',
  file_name: 'src/config.py',
  line_no: 10,
  redacted_value: 'AKIAIOSFODNN7EXAMPLE',
  remediation: 'Rotate the key immediately. Remove from source code.',
  policy_name: 'credentials/aws_access_key',
  policy_code: null,
  ...overrides,
});

const renderSidebar = (props = {}) =>
  render(
    <FindingDetailsSidebar
      finding={makeFinding()}
      isOpen={true}
      onClose={jest.fn()}
      {...props}
    />
  );

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('FindingDetailsSidebar (Secret)', () => {
  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: jest.fn().mockResolvedValue(undefined) },
      writable: true,
      configurable: true,
    });
  });

  // ── Null guard ───────────────────────────────────────────────────────────────

  describe('null guard', () => {
    it('renders nothing when finding is null', () => {
      const { container } = render(
        <FindingDetailsSidebar finding={null} isOpen={true} onClose={jest.fn()} />
      );
      expect(container.firstChild).toBeNull();
    });
  });

  // ── Open / closed state ──────────────────────────────────────────────────────

  describe('open / closed state', () => {
    it('sidebar panel has translate-x-0 class when isOpen is true', () => {
      const { container } = renderSidebar({ isOpen: true });
      expect(container.children[1].className).toContain('translate-x-0');
    });

    it('sidebar panel has translate-x-full class when isOpen is false', () => {
      const { container } = renderSidebar({ isOpen: false });
      expect(container.children[1].className).toContain('translate-x-full');
    });

    it('backdrop has opacity-100 class when isOpen is true', () => {
      const { container } = renderSidebar({ isOpen: true });
      expect(container.children[0].className).toContain('opacity-100');
    });

    it('backdrop has opacity-0 and pointer-events-none classes when isOpen is false', () => {
      const { container } = renderSidebar({ isOpen: false });
      expect(container.children[0].className).toContain('opacity-0');
      expect(container.children[0].className).toContain('pointer-events-none');
    });
  });

  // ── Header ───────────────────────────────────────────────────────────────────

  describe('header', () => {
    it('calls onClose when close button is clicked', () => {
      const onClose = jest.fn();
      renderSidebar({ onClose });
      fireEvent.click(screen.getByRole('button', { name: /close/i }));
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('calls onClose when backdrop overlay is clicked', () => {
      const onClose = jest.fn();
      const { container } = renderSidebar({ onClose });
      fireEvent.click(container.children[0]);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it.each([
      ['critical', 'Critical'],
      ['high', 'High'],
      ['medium', 'Medium'],
      ['low', 'Low'],
    ])('shows %s severity badge label', (severity, label) => {
      renderSidebar({ finding: makeFinding({ severity, category: undefined, description: undefined }) });
      expect(screen.getAllByText(label).length).toBeGreaterThanOrEqual(1);
    });

    it('defaults to Low badge for unrecognised severity', () => {
      renderSidebar({ finding: makeFinding({ severity: 'unknown', category: undefined, description: undefined }) });
      expect(screen.getAllByText('Low').length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Title ────────────────────────────────────────────────────────────────────

  describe('title', () => {
    it('renders pattern_type as h2 heading', () => {
      renderSidebar({ finding: makeFinding({ pattern_type: 'Secret Detected – GitHub Token' }) });
      expect(
        screen.getByRole('heading', { name: 'Secret Detected – GitHub Token' })
      ).toBeInTheDocument();
    });

    it('falls back to policy_name when pattern_type is absent', () => {
      renderSidebar({
        finding: makeFinding({ pattern_type: undefined, policy_name: 'credentials/github_token' }),
      });
      expect(
        screen.getByRole('heading', { name: 'credentials/github_token' })
      ).toBeInTheDocument();
    });

    it('falls back to description when both pattern_type and policy_name are absent', () => {
      renderSidebar({
        finding: makeFinding({
          pattern_type: undefined,
          policy_name: undefined,
          description: 'Fallback description text',
        }),
      });
      expect(
        screen.getByRole('heading', { name: 'Fallback description text' })
      ).toBeInTheDocument();
    });
  });

  // ── Metadata row ─────────────────────────────────────────────────────────────

  describe('metadata row', () => {
    it('renders Category label and value', () => {
      renderSidebar({ finding: makeFinding({ category: 'Secrets and Credentials' }) });
      expect(screen.getByText(/Category:/i)).toBeInTheDocument();
      expect(screen.getByText('Secrets and Credentials')).toBeInTheDocument();
    });

    it('does not render Category when absent', () => {
      renderSidebar({ finding: makeFinding({ category: undefined }) });
      expect(screen.queryByText(/Category:/i)).not.toBeInTheDocument();
    });

    it('renders Severity label in metadata row', () => {
      renderSidebar({ finding: makeFinding({ severity: 'high', category: undefined, description: undefined }) });
      expect(screen.getByText(/Severity:/i)).toBeInTheDocument();
    });

    it('does not render Severity metadata when severity is absent', () => {
      renderSidebar({ finding: makeFinding({ severity: undefined, category: undefined }) });
      expect(screen.queryByText(/Severity:/i)).not.toBeInTheDocument();
    });
  });

  // ── Description ──────────────────────────────────────────────────────────────

  describe('description section', () => {
    it('renders Description label and text', () => {
      renderSidebar({
        finding: makeFinding({ description: 'An exposed AWS access key was detected.' }),
      });
      expect(screen.getByText('Description')).toBeInTheDocument();
      expect(screen.getByText('An exposed AWS access key was detected.')).toBeInTheDocument();
    });

    it('does not render Description section when description is absent', () => {
      renderSidebar({ finding: makeFinding({ description: undefined }) });
      expect(screen.queryByText('Description')).not.toBeInTheDocument();
    });
  });

  // ── File section ─────────────────────────────────────────────────────────────

  describe('file section', () => {
    it('renders File label and file_name', () => {
      renderSidebar({ finding: makeFinding({ file_name: 'src/config.py' }) });
      expect(screen.getByText('File')).toBeInTheDocument();
      expect(screen.getByText('src/config.py')).toBeInTheDocument();
    });

    it('renders line number', () => {
      renderSidebar({ finding: makeFinding({ line_no: 42 }) });
      expect(screen.getByText('Line 42')).toBeInTheDocument();
    });

    it('does not render line label when line_no is "N/A"', () => {
      renderSidebar({ finding: makeFinding({ line_no: 'N/A' }) });
      expect(screen.queryByText(/Line N\/A/)).not.toBeInTheDocument();
    });

    it('does not render File section when file_name is absent', () => {
      renderSidebar({ finding: makeFinding({ file_name: undefined }) });
      expect(screen.queryByText('File')).not.toBeInTheDocument();
    });

    it('calls clipboard.writeText with file_name when copy path button is clicked', async () => {
      renderSidebar({ finding: makeFinding({ file_name: 'infra/secrets.tf' }) });
      fireEvent.click(screen.getByTitle('Copy file path'));
      await waitFor(() => {
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('infra/secrets.tf');
      });
    });
  });

  // ── Detected Value section ───────────────────────────────────────────────────

  describe('detected value section', () => {
    it('renders Detected Value label', () => {
      renderSidebar({ finding: makeFinding({ redacted_value: 'AKIAIOSFODNN7EXAMPLE' }) });
      expect(screen.getByText('Detected Value')).toBeInTheDocument();
    });

    it('shows bullet dots matching value length (up to 40) by default', () => {
      const value = 'AKIAIOSFODNN7EXAMPLE'; // 20 chars
      renderSidebar({ finding: makeFinding({ redacted_value: value }) });
      expect(screen.getByText('•'.repeat(20))).toBeInTheDocument();
    });

    it('caps dot count at 40 for values longer than 40 characters', () => {
      const value = 'A'.repeat(60);
      renderSidebar({ finding: makeFinding({ redacted_value: value }) });
      expect(screen.getByText('•'.repeat(40))).toBeInTheDocument();
    });

    it('reveals actual value when eye toggle is clicked', () => {
      const value = 'AKIAIOSFODNN7EXAMPLE';
      renderSidebar({ finding: makeFinding({ redacted_value: value }) });
      fireEvent.click(screen.getByTitle('Show value'));
      expect(screen.getByText(value)).toBeInTheDocument();
    });

    it('hides value again when eye toggle is clicked a second time', () => {
      const value = 'AKIAIOSFODNN7EXAMPLE';
      renderSidebar({ finding: makeFinding({ redacted_value: value }) });
      fireEvent.click(screen.getByTitle('Show value'));
      fireEvent.click(screen.getByTitle('Hide value'));
      expect(screen.queryByText(value)).not.toBeInTheDocument();
    });

    it('calls clipboard.writeText with redacted_value when copy button is clicked', async () => {
      const value = 'AKIAIOSFODNN7EXAMPLE';
      renderSidebar({ finding: makeFinding({ redacted_value: value }) });
      fireEvent.click(screen.getByTitle('Copy value'));
      await waitFor(() => {
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith(value);
      });
    });

    it('does not render Detected Value section when redacted_value is absent', () => {
      renderSidebar({ finding: makeFinding({ redacted_value: undefined }) });
      expect(screen.queryByText('Detected Value')).not.toBeInTheDocument();
    });
  });

  // ── Remediation section ──────────────────────────────────────────────────────

  describe('remediation section', () => {
    it('renders Remediation label and text when remediation is set', () => {
      renderSidebar({
        finding: makeFinding({ remediation: 'Rotate the key immediately.' }),
      });
      expect(screen.getByText('Remediation')).toBeInTheDocument();
      expect(screen.getByText('Rotate the key immediately.')).toBeInTheDocument();
    });

    it('does not render Remediation section when remediation is null', () => {
      renderSidebar({ finding: makeFinding({ remediation: null }) });
      expect(screen.queryByText('Remediation')).not.toBeInTheDocument();
    });

    it('does not render Remediation section when remediation is absent', () => {
      renderSidebar({ finding: makeFinding({ remediation: undefined }) });
      expect(screen.queryByText('Remediation')).not.toBeInTheDocument();
    });
  });
});
