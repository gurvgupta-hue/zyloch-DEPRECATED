import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import FindingDetailsSidebar from '@/app/scanops/components/scan/iac/FindingDetailsSidebar';

// ── Mocks ──────────────────────────────────────────────────────────────────────

jest.mock('lucide-react', () => {
  const icon = (name) => {
    const C = (props) => <svg data-testid={`icon-${name}`} {...props} />;
    C.displayName = name;
    return C;
  };
  return {
    X: icon('X'),
    AlertCircle: icon('AlertCircle'),
    AlertTriangle: icon('AlertTriangle'),
    Skull: icon('Skull'),
    Flame: icon('Flame'),
    Zap: icon('Zap'),
    Info: icon('Info'),
    Copy: icon('Copy'),
    Check: icon('Check'),
    ChevronDown: icon('ChevronDown'),
    Radar: icon('Radar'),
    ShieldAlert: icon('ShieldAlert'),
    ShieldCheck: icon('ShieldCheck'),
    Wrench: icon('Wrench'),
    BookOpen: icon('BookOpen'),
    XCircle: icon('XCircle'),
    CheckCircle2: icon('CheckCircle2'),
    ExternalLink: icon('ExternalLink'),
    LoaderCircle: icon('LoaderCircle'),
    WandSparkles: icon('WandSparkles'),
  };
});

jest.mock('@/app/scanops/components/scan/shared/textUtils', () => ({
  formatApiText: jest.fn((v) => v),
}));

// ── Helpers ────────────────────────────────────────────────────────────────────

const makeFinding = (overrides = {}) => ({
  title: 'Insecure IAM Policy',
  severity: 'high',
  policyCode: 'IAC-001',
  category: 'IAM',
  checkerKey: 'iam-checker',
  mappedIdentifier: 'CWE-284',
  file: 'infra/modules/main.tf',
  description: 'This policy allows unrestricted access.',
  whyFlagged: 'Overly permissive IAM policy detected.',
  riskImpact: 'Could lead to privilege escalation.',
  remediationGuidance: 'Restrict the IAM policy. Use least privilege.',
  references: [],
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

describe('FindingDetailsSidebar', () => {
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
    it('panel has translate-x-0 class when isOpen is true', () => {
      renderSidebar({ isOpen: true });
      expect(screen.getByRole('complementary').className).toContain('translate-x-0');
    });

    it('panel has translate-x-full class when isOpen is false', () => {
      renderSidebar({ isOpen: false });
      expect(screen.getByRole('complementary').className).toContain('translate-x-full');
    });

    it('backdrop has opacity-100 class when isOpen is true', () => {
      const { container } = renderSidebar({ isOpen: true });
      expect(container.firstChild.className).toContain('opacity-100');
    });

    it('backdrop has opacity-0 class when isOpen is false', () => {
      const { container } = renderSidebar({ isOpen: false });
      expect(container.firstChild.className).toContain('opacity-0');
    });
  });

  // ── Header ───────────────────────────────────────────────────────────────────

  describe('header', () => {
    it('calls onClose when close button is clicked', () => {
      const onClose = jest.fn();
      renderSidebar({ onClose });
      fireEvent.click(screen.getByRole('button', { name: /close details/i }));
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('calls onClose when backdrop overlay is clicked', () => {
      const onClose = jest.fn();
      const { container } = renderSidebar({ onClose });
      fireEvent.click(container.firstChild);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it.each([
      ['critical', 'CRITICAL'],
      ['high', 'HIGH'],
      ['medium', 'MEDIUM'],
      ['low', 'LOW'],
    ])('shows %s severity badge label', (severity, label) => {
      renderSidebar({ finding: makeFinding({ severity }) });
      expect(screen.getByText(label)).toBeInTheDocument();
    });

    it('defaults to UNKNOWN badge for unrecognised severity', () => {
      renderSidebar({ finding: makeFinding({ severity: 'unknown' }) });
      expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
    });

    it('shows the policyCode in the header', () => {
      renderSidebar({ finding: makeFinding({ policyCode: 'IAC-007' }) });
      expect(screen.getByText('IAC-007')).toBeInTheDocument();
    });

    it('shows "N/A" when policyCode is absent', () => {
      renderSidebar({ finding: makeFinding({ policyCode: undefined }) });
      expect(screen.getByText('N/A')).toBeInTheDocument();
    });
  });

  // ── Title and metadata chips ─────────────────────────────────────────────────

  describe('title and metadata chips', () => {
    it('renders finding.title as heading', () => {
      renderSidebar({ finding: makeFinding({ title: 'My Security Finding' }) });
      expect(screen.getByRole('heading', { name: 'My Security Finding' })).toBeInTheDocument();
    });

    it('falls back to finding.description when title is absent', () => {
      renderSidebar({ finding: makeFinding({ title: undefined, description: 'Fallback description' }) });
      expect(screen.getByRole('heading', { name: 'Fallback description' })).toBeInTheDocument();
    });

    it('falls back to "Security Finding" when both title and description are absent', () => {
      renderSidebar({ finding: makeFinding({ title: undefined, description: undefined, summary: undefined }) });
      expect(screen.getByRole('heading', { name: 'Security Finding' })).toBeInTheDocument();
    });

    it('renders Category metadata chip', () => {
      renderSidebar({ finding: makeFinding({ category: 'Networking' }) });
      expect(screen.getByText(/Category:/i)).toBeInTheDocument();
      expect(screen.getByText('Networking')).toBeInTheDocument();
    });

    it('renders Checker metadata chip', () => {
      renderSidebar({ finding: makeFinding({ checkerKey: 'tf-checker' }) });
      expect(screen.getByText(/Checker:/i)).toBeInTheDocument();
      expect(screen.getByText('tf-checker')).toBeInTheDocument();
    });

    it('renders Mapped ID metadata chip', () => {
      renderSidebar({ finding: makeFinding({ mappedIdentifier: 'CWE-200' }) });
      expect(screen.getByText(/Mapped ID:/i)).toBeInTheDocument();
      expect(screen.getByText('CWE-200')).toBeInTheDocument();
    });

    it('renders File chip using only the filename portion of a path', () => {
      renderSidebar({ finding: makeFinding({ file: 'infra/modules/network/vpc.tf' }) });
      expect(screen.getByText(/File:/i)).toBeInTheDocument();
      expect(screen.getByText('vpc.tf')).toBeInTheDocument();
    });

    it('uses finding.fullPath as fallback for File chip', () => {
      renderSidebar({ finding: makeFinding({ file: undefined, fullPath: 'src/k8s/deploy.yaml' }) });
      expect(screen.getByText('deploy.yaml')).toBeInTheDocument();
    });

    it('does not render Category chip when category is absent', () => {
      renderSidebar({ finding: makeFinding({ category: undefined }) });
      expect(screen.queryByText(/Category:/i)).not.toBeInTheDocument();
    });

    it('shows "Lines X-Y" label when matches has a line range', () => {
      renderSidebar({
        finding: makeFinding({
          matches: JSON.stringify([{ content: 'code', line_start: 5, line_end: 10 }]),
        }),
      });
      expect(screen.getByText('Lines 5-10')).toBeInTheDocument();
    });

    it('shows "Line X" label when matches has only line_start', () => {
      renderSidebar({
        finding: makeFinding({
          matches: JSON.stringify([{ content: 'code', line_start: 7 }]),
        }),
      });
      expect(screen.getByText('Line 7')).toBeInTheDocument();
    });

    it('shows "Line X" label from fallback finding.lineNo', () => {
      renderSidebar({ finding: makeFinding({ lineNo: 42, matches: undefined }) });
      expect(screen.getByText('Line 42')).toBeInTheDocument();
    });

    it('does not render a line label when no line info is available', () => {
      renderSidebar({ finding: makeFinding({ lineNo: undefined, matches: undefined }) });
      expect(screen.queryByText(/^Lines? \d/)).not.toBeInTheDocument();
    });
  });

  // ── Infrastructure as Code overview accordion ───────────────────────────────────────────────────

  describe('Infrastructure as Code overview accordion', () => {
    it('is expanded by default', () => {
      renderSidebar();
      expect(screen.getByRole('button', { name: /^Infrastructure as Code$/i })).toHaveAttribute('aria-expanded', 'true');
    });

    it('collapses when its toggle button is clicked', () => {
      renderSidebar();
      fireEvent.click(screen.getByRole('button', { name: /^Infrastructure as Code$/i }));
      expect(screen.getByRole('button', { name: /^Infrastructure as Code$/i })).toHaveAttribute('aria-expanded', 'false');
    });

    it('re-expands after a second click', () => {
      renderSidebar();
      const btn = screen.getByRole('button', { name: /^Infrastructure as Code$/i });
      fireEvent.click(btn);
      fireEvent.click(btn);
      expect(btn).toHaveAttribute('aria-expanded', 'true');
    });

    it('renders Description overview block', () => {
      renderSidebar({ finding: makeFinding({ description: 'Detailed desc' }) });
      expect(screen.getByText('Description')).toBeInTheDocument();
      expect(screen.getByText('Detailed desc')).toBeInTheDocument();
    });

    it('uses finding.summary when description is absent', () => {
      renderSidebar({ finding: makeFinding({ description: undefined, summary: 'Summary fallback' }) });
      expect(screen.getByText('Summary fallback')).toBeInTheDocument();
    });

    it('renders "Why This Was Flagged" overview block', () => {
      renderSidebar({ finding: makeFinding({ whyFlagged: 'Permissive rule' }) });
      expect(screen.getByText('Why This Was Flagged')).toBeInTheDocument();
      expect(screen.getByText('Permissive rule')).toBeInTheDocument();
    });

    it('renders "Risk & Impact" overview block', () => {
      renderSidebar({ finding: makeFinding({ riskImpact: 'Possible data breach' }) });
      expect(screen.getByText('Risk & Impact')).toBeInTheDocument();
      expect(screen.getByText('Possible data breach')).toBeInTheDocument();
    });

    it('shows "No Infrastructure as Code details available" placeholder when all overview blocks are absent', () => {
      renderSidebar({
        finding: makeFinding({
          description: undefined,
          summary: undefined,
          whyFlagged: undefined,
          riskImpact: undefined,
        }),
      });
      expect(screen.getByText('No Infrastructure as Code details available for this finding.')).toBeInTheDocument();
    });

    it('renders Source Context code block when codeBlock is present', () => {
      renderSidebar({
        finding: makeFinding({
          codeBlock: '@GetMapping("/api/user/{id}")\npublic User get(Long id) {\n  return service.find(id);\n}',
          lineNo: 41,
        }),
      });
      expect(screen.getByText('Source Context')).toBeInTheDocument();
      expect(screen.getByText(/return service\.find\(id\);/)).toBeInTheDocument();
    });

    it('renders Source Context placeholder when file/line exist but codeBlock is missing', () => {
      renderSidebar({
        finding: makeFinding({
          codeBlock: null,
          file: 'UserController.java',
          lineNo: 41,
        }),
      });
      expect(screen.getByText('Source Context')).toBeInTheDocument();
      expect(screen.getByText(/UserController\.java:41/)).toBeInTheDocument();
      expect(screen.getByText(/Source snippet unavailable/i)).toBeInTheDocument();
    });

    it('labels reconstructed source context when codeBlockCaptured is false', () => {
      renderSidebar({
        finding: makeFinding({
          codeBlock: '@GetMapping("/api/user/{id}")\npublic ResponseEntity<?> handler() {}',
          codeBlockCaptured: false,
          file: 'UserController.java',
          lineNo: 35,
        }),
      });
      expect(screen.getByText(/Reconstructed from endpoint metadata/i)).toBeInTheDocument();
      expect(screen.getByText(/@GetMapping/)).toBeInTheDocument();
    });

    it('renders affected code block when matches contain content', () => {
      renderSidebar({
        finding: makeFinding({
          matches: JSON.stringify([{ content: 'resource "aws_iam" {}', line_start: 1, line_end: 3 }]),
        }),
      });
      expect(screen.getByText('Affected Code')).toBeInTheDocument();
      expect(screen.getByText('resource "aws_iam" {}')).toBeInTheDocument();
    });

    it('renders affected code block from array matches', () => {
      renderSidebar({
        finding: makeFinding({
          matches: [{ content: 'var open = true', line_start: 10 }],
        }),
      });
      expect(screen.getByText('var open = true')).toBeInTheDocument();
    });

    it('does not render affected code block when matches are empty', () => {
      renderSidebar({ finding: makeFinding({ matches: '[]' }) });
      expect(screen.queryByText('Affected Code')).not.toBeInTheDocument();
    });

    it('copies affected code to clipboard when copy button is clicked', async () => {
      renderSidebar({
        finding: makeFinding({
          matches: JSON.stringify([{ content: 'sensitive_code_here', line_start: 1 }]),
        }),
      });
      fireEvent.click(screen.getByRole('button', { name: /copy code/i }));
      await waitFor(() => {
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('sensitive_code_here');
      });
    });
  });

  // ── Remediation Plan accordion ───────────────────────────────────────────────

  describe('Remediation Plan accordion', () => {
    it('is collapsed by default', () => {
      renderSidebar();
      expect(screen.getByRole('button', { name: /remediation plan/i })).toHaveAttribute(
        'aria-expanded',
        'false'
      );
    });

    it('expands when its toggle button is clicked', () => {
      renderSidebar();
      fireEvent.click(screen.getByRole('button', { name: /remediation plan/i }));
      expect(screen.getByRole('button', { name: /remediation plan/i })).toHaveAttribute(
        'aria-expanded',
        'true'
      );
    });

    it('shows only the autofix suggestion in the remediation plan', () => {
      renderSidebar({
        finding: makeFinding({
          remediationGuidance: 'Step alpha. Step beta.',
          examples: { bad: 'insecure code', good: 'secure code' },
          references: [{ name: 'AWS Docs', url: 'https://docs.aws.amazon.com' }],
        }),
      });
      fireEvent.click(screen.getByRole('button', { name: /remediation plan/i }));

      expect(screen.getByText('Autofix Suggestion')).toBeInTheDocument();
      expect(screen.queryByText('Fix Steps')).not.toBeInTheDocument();
      expect(screen.queryByText('Vulnerable Pattern')).not.toBeInTheDocument();
      expect(screen.queryByText('Secure Example')).not.toBeInTheDocument();
      expect(screen.queryByText('References')).not.toBeInTheDocument();
    });
  });
});
