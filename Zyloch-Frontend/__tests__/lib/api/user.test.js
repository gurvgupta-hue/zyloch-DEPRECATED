const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();
const mockReplaceLocation = jest.fn();

jest.mock("react-toastify", () => ({
  toast: {
    success: (...args) => mockToastSuccess(...args),
    error: (...args) => mockToastError(...args),
  },
}));

jest.mock("@/lib/api/navigation", () => ({
  replaceLocation: (...args) => mockReplaceLocation(...args),
}));

describe("user API logout", () => {
  const originalApiUrl = process.env.NEXT_PUBLIC_API_URL;
  let logout;

  beforeAll(() => {
    process.env.NEXT_PUBLIC_API_URL = "https://api.zyloch.test";
    jest.resetModules();
    ({ logout } = require("@/lib/api/user"));
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    if (originalApiUrl === undefined) {
      delete process.env.NEXT_PUBLIC_API_URL;
    } else {
      process.env.NEXT_PUBLIC_API_URL = originalApiUrl;
    }
  });

  test("posts to the provider-neutral endpoint and follows the redirect", async () => {
    sessionStorage.setItem("probe", "1");
    localStorage.setItem("authToken", "legacy");
    localStorage.setItem("zyloch-last-activity", "123");
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        redirectUrl: "https://app.zyloch.test/login?orgId=org-123",
      }),
    });

    await expect(logout(false)).resolves.toBe(
      "https://app.zyloch.test/login?orgId=org-123",
    );

    expect(sessionStorage.getItem("probe")).toBeNull();
    expect(localStorage.getItem("authToken")).toBeNull();
    expect(localStorage.getItem("zyloch-last-activity")).toBeNull();

    expect(global.fetch).toHaveBeenCalledWith(
      "https://api.zyloch.test/auth/logout",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
      }),
    );
    expect(mockReplaceLocation).toHaveBeenCalledWith(
      "https://app.zyloch.test/login?orgId=org-123",
    );
    expect(mockToastSuccess).not.toHaveBeenCalled();
  });

  test("shows an error and rejects when logout fails", async () => {
    jest.spyOn(console, "error").mockImplementation(() => {});
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ message: "Unable to log out" }),
    });

    await expect(logout()).rejects.toThrow("Logout request failed");

    expect(mockToastError).toHaveBeenCalledWith(
      "Logout failed: Logout request failed",
    );
    expect(mockReplaceLocation).not.toHaveBeenCalled();
    console.error.mockRestore();
  });
});