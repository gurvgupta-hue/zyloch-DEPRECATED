import { useGithubStore } from '@/store/useGithubStore';
import {
  startInstallationSummary,
  pollInstallationSummary,
  refreshInstallationData,
  retryFailedJob,
} from '@/lib/api/github';

jest.mock('@/lib/api/github', () => ({
  startInstallationSummary: jest.fn(),
  pollInstallationSummary: jest.fn(),
  refreshInstallationData: jest.fn(),
  retryFailedJob: jest.fn(),
  getRepoSelection: jest.fn(() => Promise.resolve({ selectionRequired: false })),
}));

const initialState = useGithubStore.getState();
// Settles pending promises without advancing the poll timers.
const flush = () => jest.advanceTimersByTimeAsync(0);

const running = (progress, extra = {}) => ({
  ...initialState.summaryAnalysis,
  installationId: 7,
  jobId: 'j1',
  status: 'in_progress',
  progress,
  ...extra,
});

beforeEach(() => {
  jest.useFakeTimers();
  jest.clearAllMocks();
  useGithubStore.setState(initialState, true);
  useGithubStore.setState({ selectedInstallation: { installationId: 7 } });
});

afterEach(() => {
  useGithubStore.getState().resetSummaryAnalysis(); // stops any poll loop
  jest.clearAllTimers();
  jest.useRealTimers();
});

// The bar used to stall, jump back to the left and start over. These pin the
// client half of the fix; the server half is in the backend summaryRuns tests.
describe('sync progress stays stable', () => {
  test('never moves backwards while a run is going', async () => {
    useGithubStore.setState({ summaryAnalysis: running(0) });
    pollInstallationSummary
      .mockResolvedValueOnce({ status: 'in_progress', progress: 55 })
      .mockResolvedValueOnce({ status: 'in_progress', progress: 12 })
      .mockResolvedValueOnce({ status: 'in_progress', progress: 60 });

    useGithubStore.getState().pollSummaryAnalysis('j1');
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(55);

    await jest.advanceTimersByTimeAsync(2000);
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(55);

    await jest.advanceTimersByTimeAsync(2000);
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(60);
  });

  test('a newer poll loop silences the older one', async () => {
    useGithubStore.setState({ summaryAnalysis: running(0) });
    let resolveOld;
    pollInstallationSummary
      .mockImplementationOnce(() => new Promise((r) => { resolveOld = r; }))
      .mockResolvedValueOnce({ status: 'in_progress', progress: 30 });

    useGithubStore.getState().pollSummaryAnalysis('j1');
    useGithubStore.getState().pollSummaryAnalysis('j1');
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(30);

    // The first loop's late answer must not land, and it must not poll again.
    resolveOld({ status: 'failed', progress: 100, error: 'stale' });
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.status).toBe('in_progress');
    expect(pollInstallationSummary).toHaveBeenCalledTimes(2);
  });

  test('returning to the dashboard during a sync keeps the bar where it was', async () => {
    useGithubStore.setState({ summaryAnalysis: running(48) });
    let resolveStart;
    startInstallationSummary.mockReturnValue(new Promise((r) => { resolveStart = r; }));
    pollInstallationSummary.mockResolvedValue({ status: 'in_progress', progress: 50 });

    const start = useGithubStore.getState().startSummaryAnalysis(7);
    // No drop to the "checking" spinner and no reset to 0 while asking.
    expect(useGithubStore.getState().summaryAnalysis).toMatchObject({ status: 'in_progress', progress: 48 });

    resolveStart({ status: 'processing_started', jobId: 'j1', alreadyRunning: true });
    await start;
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(50);
  });

  test('refresh joining a running sync keeps its progress', async () => {
    useGithubStore.setState({ summaryAnalysis: running(70) });
    refreshInstallationData.mockResolvedValue({ jobId: 'j1', alreadyRunning: true });
    // A lagging read below the bar must not pull it back either.
    pollInstallationSummary.mockResolvedValue({ status: 'in_progress', progress: 69 });

    await useGithubStore.getState().refreshSummary();
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(70);
  });

  test('refresh joining a sync started elsewhere does not inherit a finished 100%', async () => {
    useGithubStore.setState({
      summaryAnalysis: running(100, { status: 'completed', data: { totalRepositories: 3 } }),
    });
    refreshInstallationData.mockResolvedValue({ jobId: 'j1', alreadyRunning: true });
    pollInstallationSummary.mockResolvedValue({ status: 'in_progress', progress: 40 });

    await useGithubStore.getState().refreshSummary();
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(40);
  });

  test('a retried run starts from 0, not from the failed run\'s 100', async () => {
    useGithubStore.setState({ summaryAnalysis: running(100, { status: 'failed', error: 'boom' }) });
    retryFailedJob.mockResolvedValue({ success: true });
    pollInstallationSummary.mockResolvedValue({ status: 'in_progress', progress: 5 });

    await useGithubStore.getState().retryFailedSummary();
    await flush();
    expect(useGithubStore.getState().summaryAnalysis.progress).toBe(5);
  });
});
