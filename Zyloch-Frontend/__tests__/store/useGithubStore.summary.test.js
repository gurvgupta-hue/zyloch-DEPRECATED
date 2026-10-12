import { useGithubStore } from '@/store/useGithubStore';
import {
  startInstallationSummary,
  pollInstallationSummary,
} from '@/lib/api/github';

jest.mock('@/lib/api/github', () => ({
  startInstallationSummary: jest.fn(),
  pollInstallationSummary: jest.fn(),
  refreshInstallationData: jest.fn(),
  retryFailedJob: jest.fn(),
  getRepoSelection: jest.fn(() => Promise.resolve({ selectionRequired: false })),
}));

const initialState = useGithubStore.getState();

beforeEach(() => {
  jest.clearAllMocks();
  useGithubStore.setState(initialState, true);
  useGithubStore.setState({ selectedInstallation: { installationId: 7 } });
});

describe('startSummaryAnalysis', () => {
  test('is "checking" (not "pending") until the server answers', async () => {
    let resolve;
    startInstallationSummary.mockReturnValue(new Promise((r) => { resolve = r; }));

    const run = useGithubStore.getState().startSummaryAnalysis(7);
    expect(useGithubStore.getState().summaryAnalysis.status).toBe('checking');

    resolve({ status: 'from_cache', jobId: 'j1', summary: { totalRepositories: 3 } });
    await run;
  });

  test('a cached summary goes straight to completed without polling', async () => {
    startInstallationSummary.mockResolvedValue({
      status: 'from_cache',
      jobId: 'j1',
      summary: { totalRepositories: 3 },
    });

    await useGithubStore.getState().startSummaryAnalysis(7);

    const { summaryAnalysis } = useGithubStore.getState();
    expect(summaryAnalysis.status).toBe('completed');
    expect(summaryAnalysis.data).toEqual({ totalRepositories: 3 });
    expect(summaryAnalysis.installationId).toBe(7);
    expect(pollInstallationSummary).not.toHaveBeenCalled();
  });

  test('a started job moves to pending and polls', async () => {
    jest.useFakeTimers();
    startInstallationSummary.mockResolvedValue({ status: 'processing_started', jobId: 'j2' });
    pollInstallationSummary.mockResolvedValue({ status: 'in_progress', progress: 10 });

    await useGithubStore.getState().startSummaryAnalysis(7);

    expect(pollInstallationSummary).toHaveBeenCalledWith('j2');
    expect(['pending', 'in_progress']).toContain(useGithubStore.getState().summaryAnalysis.status);
    useGithubStore.getState().resetSummaryAnalysis(); // stops the poll loop
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  test('keeps an existing summary on screen while revalidating', async () => {
    useGithubStore.setState({
      summaryAnalysis: {
        ...initialState.summaryAnalysis,
        installationId: 7,
        status: 'completed',
        data: { totalRepositories: 1 },
      },
    });
    let resolve;
    startInstallationSummary.mockReturnValue(new Promise((r) => { resolve = r; }));

    const run = useGithubStore.getState().startSummaryAnalysis(7);
    expect(useGithubStore.getState().summaryAnalysis.status).toBe('completed');
    expect(useGithubStore.getState().summaryAnalysis.data).toEqual({ totalRepositories: 1 });

    resolve({ status: 'from_cache', jobId: 'j1', summary: { totalRepositories: 2 } });
    await run;
    expect(useGithubStore.getState().summaryAnalysis.data).toEqual({ totalRepositories: 2 });
  });

  test('concurrent calls for the same installation share one request', async () => {
    startInstallationSummary.mockResolvedValue({ status: 'from_cache', jobId: 'j1', summary: {} });

    await Promise.all([
      useGithubStore.getState().startSummaryAnalysis(7),
      useGithubStore.getState().startSummaryAnalysis(7),
    ]);

    expect(startInstallationSummary).toHaveBeenCalledTimes(1);
  });
});
