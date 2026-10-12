import React from 'react';
import { render, screen } from '@testing-library/react';
import SecretScanner from '@/app/scanops/components/scan/secret/SecretScanner';

// ── Mocks ──────────────────────────────────────────────────────────────────────

let mockStoreState = { latestScan: null, loading: false, error: null };
jest.mock('@/store/useScanStore', () => ({
  useScanStore: () => mockStoreState,
}));

jest.mock('@/data/secretDetection.json', () => ({
  detections: [
    {
      id: 'test-001',
      title: 'Secret Detected – AWS Access Key',
      severity: 'Critical',
      category: 'Secrets and Credentials',
      finding: 'Possible exposed AWS access key ID.',
      infoTypes: ['aws_access_key'],
      recommendation: 'Immediately rotate the exposed API key.',
    },
    {
      id: 'test-002',
      title: 'Secret Detected – PostgreSQL Database URL',
      severity: 'Critical',
      category: 'Secrets and Credentials',
      finding: 'Possible exposed PostgreSQL connection string.',
      infoTypes: ['postgres_url'],
      recommendation: 'Immediately restrict access to the exposed connection string.',
    },
  ],
}));

jest.mock('@/app/scanops/components/scan/secret/LoadingState', () => {
  const LoadingState = () => <div data-testid="loading-state" />;
  LoadingState.displayName = 'LoadingState';
  return LoadingState;
});

jest.mock('@/app/scanops/components/scan/secret/ErrorState', () => {
  const ErrorState = ({ error }) => <div data-testid="error-state">{error}</div>;
  ErrorState.displayName = 'ErrorState';
  return ErrorState;
});

jest.mock('@/app/scanops/components/scan/secret/EmptyState', () => {
  const EmptyState = ({ message }) => <div data-testid="empty-state">{message}</div>;
  EmptyState.displayName = 'EmptyState';
  return EmptyState;
});

jest.mock('@/app/scanops/components/scan/secret/SecretScannerHeader', () => {
  const SecretScannerHeader = () => <div data-testid="secret-scanner-header" />;
  SecretScannerHeader.displayName = 'SecretScannerHeader';
  return SecretScannerHeader;
});


jest.mock('@/app/scanops/components/scan/secret/ChartsSection', () => {
  const ChartsSection = () => <div data-testid="charts-section" />;
  ChartsSection.displayName = 'ChartsSection';
  return ChartsSection;
});

let capturedFindingsProps = null;
jest.mock('@/app/scanops/components/scan/secret/FindingsList', () => {
  const MockFindingsList = (props) => {
    capturedFindingsProps = props;
    return <div data-testid="findings-list" />;
  };
  MockFindingsList.displayName = 'MockFindingsList';
  return MockFindingsList;
});

jest.mock('@/app/scanops/components/scan/shared/AIScannerPopup', () => {
  const AIScannerPopup = () => <div data-testid="ai-scanner-popup" />;
  AIScannerPopup.displayName = 'AIScannerPopup';
  return AIScannerPopup;
});

jest.mock('@/app/scanops/components/scan/shared/textUtils', () => ({
  formatApiText: jest.fn((v) => v),
}));

// ── Helpers ────────────────────────────────────────────────────────────────────

const makePolicy = (overrides = {}) => ({
  policy_name: 'credentials/aws_access_key',
  policy_code: null,
  severity: 'critical',
  description: 'AWS Access Key detected',
  Matches: 'AKIA1234567890',
  Line_No: 10,
  remediation: null,
  ...overrides,
});

const makeLatestScan = (policies = [makePolicy()]) => ({
  scan_metadata: { scan_id: 'scan-001', created_at: '2026-01-01' },
  scan_results: {
    scans_findings: {
      'Secret_Scanner-findings': [
        { file_name: 'src/config.py', violated_policies: policies },
      ],
    },
    scan_results: {
      summary: {
        score_summary: { score_by_subscan: { secret_scanner: 72 } },
        file_scanned: 5,
      },
      scanner_results: {
        secret_scanner: {
          files_scanned: 5,
          duration: 3.5,
          metadata: { overall_score: 72 },
        },
      },
    },
  },
});

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('SecretScanner', () => {
  beforeEach(() => {
    capturedFindingsProps = null;
    mockStoreState = { latestScan: null, loading: false, error: null };
  });

  // ── Guard states ─────────────────────────────────────────────────────────────

  describe('guard states', () => {
    it('renders LoadingState when loading is true', () => {
      mockStoreState = { latestScan: null, loading: true, error: null };
      render(<SecretScanner />);
      expect(screen.getByTestId('loading-state')).toBeInTheDocument();
    });

    it('renders ErrorState when error is set', () => {
      mockStoreState = { latestScan: null, loading: false, error: 'Network error' };
      render(<SecretScanner />);
      expect(screen.getByTestId('error-state')).toBeInTheDocument();
    });

    it('renders EmptyState when latestScan is null', () => {
      render(<SecretScanner />);
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    });

    it('renders EmptyState when Secret_Scanner-findings is an empty array', () => {
      mockStoreState = {
        loading: false,
        error: null,
        latestScan: {
          scan_metadata: {},
          scan_results: { scans_findings: { 'Secret_Scanner-findings': [] } },
        },
      };
      render(<SecretScanner />);
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    });

    it('does not render LoadingState when findings are present', () => {
      mockStoreState = { latestScan: makeLatestScan(), loading: false, error: null };
      render(<SecretScanner />);
      expect(screen.queryByTestId('loading-state')).not.toBeInTheDocument();
    });
  });

  // ── Main render ──────────────────────────────────────────────────────────────

  describe('main render', () => {
    beforeEach(() => {
      mockStoreState = { latestScan: makeLatestScan(), loading: false, error: null };
    });

    it('renders SecretScannerHeader', () => {
      render(<SecretScanner />);
      expect(screen.getByTestId('secret-scanner-header')).toBeInTheDocument();
    });


    it('renders ChartsSection', () => {
      render(<SecretScanner />);
      expect(screen.getByTestId('charts-section')).toBeInTheDocument();
    });

    it('renders FindingsList', () => {
      render(<SecretScanner />);
      expect(screen.getByTestId('findings-list')).toBeInTheDocument();
    });
  });

  // ── Finding enrichment ───────────────────────────────────────────────────────

  describe('finding enrichment via secretDetection.json', () => {
    it('enriches pattern_type from JSON title when policy_name matches an infoType', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ policy_name: 'credentials/aws_access_key' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].pattern_type).toBe('Secret Detected – AWS Access Key');
    });

    it('strips category prefix before infoType lookup', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ policy_name: 'database_urls/postgres_url' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].pattern_type).toBe('Secret Detected – PostgreSQL Database URL');
    });

    it('sets remediation from JSON recommendation when matched', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ policy_name: 'credentials/aws_access_key' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].remediation).toBe(
        'Immediately rotate the exposed API key.'
      );
    });

    it('sets category from JSON when matched', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ policy_name: 'credentials/aws_access_key' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].category).toBe('Secrets and Credentials');
    });

    it('falls back to policy_name for pattern_type when no infoType match', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ policy_name: 'custom/unknown_type' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].pattern_type).toBe('custom/unknown_type');
    });

    it('sets remediation to null when no infoType match', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ policy_name: 'custom/unknown_type' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].remediation).toBeNull();
    });

    it('uses policy.Matches as redacted_value', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ Matches: 'AKIA1234REDACTED' })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].redacted_value).toBe('AKIA1234REDACTED');
    });

    it('falls back to description when Matches is absent', () => {
      mockStoreState = {
        latestScan: makeLatestScan([
          makePolicy({ Matches: undefined, description: 'fallback desc' }),
        ]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].redacted_value).toBe('fallback desc');
    });

    it('preserves file_name and line_no on each finding', () => {
      mockStoreState = {
        latestScan: makeLatestScan([makePolicy({ Line_No: 25 })]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings[0].file_name).toBe('src/config.py');
      expect(capturedFindingsProps.findings[0].line_no).toBe(25);
    });
  });

  // ── Unique IDs ───────────────────────────────────────────────────────────────

  describe('unique finding IDs', () => {
    it('generates unique IDs for two policies with the same policy_name and line number', () => {
      const policy = makePolicy({ policy_name: 'credentials/aws_access_key', Line_No: 5 });
      mockStoreState = {
        latestScan: makeLatestScan([policy, { ...policy }]),
        loading: false,
        error: null,
      };
      render(<SecretScanner />);
      const ids = capturedFindingsProps.findings.map((f) => f.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('generates unique IDs across findings from different files', () => {
      mockStoreState = {
        loading: false,
        error: null,
        latestScan: {
          scan_metadata: {},
          scan_results: {
            scans_findings: {
              'Secret_Scanner-findings': [
                { file_name: 'file1.py', violated_policies: [makePolicy({ Line_No: 1 })] },
                { file_name: 'file2.py', violated_policies: [makePolicy({ Line_No: 1 })] },
              ],
            },
          },
        },
      };
      render(<SecretScanner />);
      const ids = capturedFindingsProps.findings.map((f) => f.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
  });

  // ── Totals passed to FindingsList ────────────────────────────────────────────

  describe('totals passed to FindingsList', () => {
    it('passes correct totalIssues count', () => {
      const policies = [
        makePolicy({ Line_No: 1 }),
        makePolicy({ Line_No: 2 }),
        makePolicy({ Line_No: 3 }),
      ];
      mockStoreState = { latestScan: makeLatestScan(policies), loading: false, error: null };
      render(<SecretScanner />);
      expect(capturedFindingsProps.totalIssues).toBe(3);
    });

    it('passes correct filesWithIssues count', () => {
      mockStoreState = { latestScan: makeLatestScan(), loading: false, error: null };
      render(<SecretScanner />);
      expect(capturedFindingsProps.filesWithIssues).toBe(1);
    });

    it('passes all enriched findings to FindingsList', () => {
      const policies = [makePolicy({ Line_No: 1 }), makePolicy({ Line_No: 2 })];
      mockStoreState = { latestScan: makeLatestScan(policies), loading: false, error: null };
      render(<SecretScanner />);
      expect(capturedFindingsProps.findings).toHaveLength(2);
    });
  });
});
