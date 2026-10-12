import { useGithubStore } from '@/store/useGithubStore';
import { checkInstallationLinked, getInstallations } from '@/lib/api/github';

jest.mock('@/lib/api/github', () => ({
  getInstallations: jest.fn(() => Promise.resolve({ installations: [], userRole: 'admin' })),
  checkInstallationLinked: jest.fn(),
}));

const initialState = useGithubStore.getState();
const install = { installationId: 162542487, account: { login: 'secure-code-demo', type: 'Organization' } };

beforeEach(() => {
  jest.clearAllMocks();
  useGithubStore.setState(initialState, true);
});

describe('waitForInstallation', () => {
  test('connects immediately when the installation is already linked', async () => {
    checkInstallationLinked.mockResolvedValue(true);
    getInstallations.mockResolvedValue({ installations: [install], userRole: 'admin' });

    const connected = await useGithubStore.getState().waitForInstallation(162542487, { intervalMs: 1 });

    expect(connected).toBe(true);
    expect(checkInstallationLinked).toHaveBeenCalledTimes(1);
    const state = useGithubStore.getState();
    expect(state.connectingInstallation).toBeNull();
    expect(state.connectedInstallationId).toBe('162542487');
    expect(state.installations).toEqual([install]);
    // The user picks the account themselves, guided by the tour.
    expect(state.selectedInstallation).toBeNull();
  });

  // The webhook that records the install can land after GitHub has already
  // redirected the browser back.
  test('shows the connecting state until the installation is linked', async () => {
    let resolveSecond;
    checkInstallationLinked
      .mockResolvedValueOnce(false)
      .mockImplementationOnce(() => new Promise((r) => { resolveSecond = r; }));

    const run = useGithubStore.getState().waitForInstallation('162542487', { intervalMs: 1 });

    await waitForCalls(checkInstallationLinked, 2);
    expect(useGithubStore.getState().connectingInstallation).toEqual({
      installationId: '162542487',
      timedOut: false,
    });

    resolveSecond(true);
    await expect(run).resolves.toBe(true);
    expect(useGithubStore.getState().connectingInstallation).toBeNull();
  });

  test('a failed check counts as "not yet" rather than an error', async () => {
    checkInstallationLinked
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce(true);

    await expect(
      useGithubStore.getState().waitForInstallation('162542487', { intervalMs: 1 })
    ).resolves.toBe(true);
    expect(checkInstallationLinked).toHaveBeenCalledTimes(2);
  });

  test('stops at the deadline and reports timedOut', async () => {
    checkInstallationLinked.mockResolvedValue(false);

    const connected = await useGithubStore
      .getState()
      .waitForInstallation('162542487', { intervalMs: 1, timeoutMs: 0 });

    expect(connected).toBe(false);
    expect(checkInstallationLinked).toHaveBeenCalledTimes(1);
    expect(useGithubStore.getState().connectingInstallation).toEqual({
      installationId: '162542487',
      timedOut: true,
    });
    expect(useGithubStore.getState().connectedInstallationId).toBeNull();
  });

  test('cancelling stops the checks and clears the connecting state', async () => {
    checkInstallationLinked.mockImplementation(async () => {
      useGithubStore.getState().cancelWaitForInstallation();
      return true;
    });

    const connected = await useGithubStore.getState().waitForInstallation('162542487', { intervalMs: 1 });

    expect(connected).toBe(false);
    expect(getInstallations).not.toHaveBeenCalled();
    expect(useGithubStore.getState().connectingInstallation).toBeNull();
    expect(useGithubStore.getState().connectedInstallationId).toBeNull();
  });

  test('acknowledging clears the connected flag', () => {
    useGithubStore.setState({ connectedInstallationId: '162542487' });
    useGithubStore.getState().acknowledgeConnectedInstallation();
    expect(useGithubStore.getState().connectedInstallationId).toBeNull();
  });
});

async function waitForCalls(mock, count) {
  for (let i = 0; i < 50 && mock.mock.calls.length < count; i += 1) {
    await new Promise((r) => setTimeout(r, 2));
  }
}
