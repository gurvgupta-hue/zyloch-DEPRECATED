const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  getOAuthCallbackUrl,
  validateOAuthCallbackUrl,
  validatePositiveInteger,
} = require("../utils/validation");

describe("validation utils", () => {
  it("accepts positive integers", () => {
    assert.equal(validatePositiveInteger("42", "count"), 42);
  });

  it("derives provider callbacks from the backend OAuth origin", () => {
    const originalRedirectUri = process.env.OAUTH_REDIRECT_URI;
    process.env.OAUTH_REDIRECT_URI =
      "http://admin-vm.secure-labs.io:5000/auth/github/callback";

    try {
      assert.equal(
        getOAuthCallbackUrl(
          "google",
          "http://admin-vm.secure-labs.io:3000/auth/google/callback",
        ),
        "http://admin-vm.secure-labs.io:5000/auth/google/callback",
      );
    } finally {
      if (originalRedirectUri === undefined) {
        delete process.env.OAUTH_REDIRECT_URI;
      } else {
        process.env.OAUTH_REDIRECT_URI = originalRedirectUri;
      }
    }
  });

  it("rejects a redirect URI that points at the frontend", () => {
    const originalRedirectUri = process.env.OAUTH_REDIRECT_URI;
    process.env.OAUTH_REDIRECT_URI =
      "http://admin-vm.secure-labs.io:5000/auth/github/callback";

    try {
      assert.throws(
        () => validateOAuthCallbackUrl(
          "http://admin-vm.secure-labs.io:3000/auth/google/callback",
          "google",
        ),
        /Use http:\/\/admin-vm\.secure-labs\.io:5000\/auth\/google\/callback/,
      );
    } finally {
      if (originalRedirectUri === undefined) {
        delete process.env.OAUTH_REDIRECT_URI;
      } else {
        process.env.OAUTH_REDIRECT_URI = originalRedirectUri;
      }
    }
  });
});
