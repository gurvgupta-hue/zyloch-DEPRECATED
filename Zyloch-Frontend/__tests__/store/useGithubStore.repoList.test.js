import { useGithubStore } from '@/store/useGithubStore';
import {
  getRepositoriesFromDB,
  getRepositories,
  saveRepoSelection,
  autoSelectRepos,
  startInstallationSummary,
  pollInstallationSummary,
} from '@/lib/api/github';

jest.mock('@/lib/api/github', () => ({
  getRepositoriesFromDB: jest.fn(),
  getRepositories: jest.fn(),
  saveRepoSelection: jest.fn(),
  autoSelectRepos: jest.fn(),
  startInstallationSummary: jest.fn(),
  pollInstallationSummary: jest.fn(),
  getRepoSelection: jest.fn(() => Promise.resolve({ selectionRequired: false })),
}));

const initialState = useGithubStore.getState();
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
const chosen = { repositories: [{ _id: 'r1', owner: 'acme', repositoryName: 'a' }] };

beforeEach(() => {
  jest.clearAllMocks();
  useGithubStore.setState(initialState, true);
  useGithubStore.setState({ selectedInstallation: { installationId: 7 } });
  startInstallationSummary.mockResolvedValue({ status: 'from_cache', jobId: 'j1', summary: {} });
  getRepositoriesFromDB.mockResolvedValue(chosen);
  getRepositories.mockResolvedValue([]);
});

afterEach(() => useGithubStore.getState().resetSummaryAnalysis());

// The repository list is loaded when the org is picked — before any repositories
// are chosen, when the server rightly offers none. It has to be loaded again once
// there is something to offer, or every dropdown stays empty.
describe('repository list follows the chosen repositories', () => {
  test.each([
    ['saving a selection', () => {
      saveRepoSelection.mockResolvedValue({ selectionRequired: false });
      return useGithubStore.getState().commitRepoSelection(7, ['acme/a']);
    }],
    ['auto-selecting', () => {
      autoSelectRepos.mockResolvedValue({ selectionRequired: false });
      return useGithubStore.getState().autoSelectRepoSelection(7);
    }],
  ])('reloads after %s', async (_label, act) => {
    useGithubStore.setState({ repositories: [] });

    await act();
    await settle();

    expect(getRepositoriesFromDB).toHaveBeenCalledWith(7);
    expect(useGithubStore.getState().repositories.map((r) => r.full_name)).toEqual(['acme/a']);
  });

  test('reloads from the stored repositories when the first sync finishes', async () => {
    useGithubStore.setState({
      summaryAnalysis: { ...initialState.summaryAnalysis, installationId: 7, jobId: 'j1', status: 'in_progress' },
    });
    pollInstallationSummary.mockResolvedValue({ status: 'completed', progress: 100, summary: {} });

    useGithubStore.getState().pollSummaryAnalysis('j1');
    await settle();
    await settle();

    expect(getRepositoriesFromDB).toHaveBeenCalledWith(7);
  });

  test('leaves the list alone once a repository has been picked', async () => {
    useGithubStore.setState({
      selectedRepo: { id: 'r1', full_name: 'acme/a' },
      summaryAnalysis: { ...initialState.summaryAnalysis, installationId: 7, jobId: 'j1', status: 'in_progress' },
    });
    pollInstallationSummary.mockResolvedValue({ status: 'completed', progress: 100, summary: {} });

    useGithubStore.getState().pollSummaryAnalysis('j1');
    await settle();
    await settle();

    expect(getRepositoriesFromDB).not.toHaveBeenCalled();
    expect(useGithubStore.getState().selectedRepo).toEqual({ id: 'r1', full_name: 'acme/a' });
  });
});
