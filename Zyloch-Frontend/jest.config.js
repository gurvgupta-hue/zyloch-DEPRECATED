const nextJest = require("next/jest");

const createJestConfig = nextJest({ dir: "./" });

const customJestConfig = {
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
  testEnvironment: "jsdom",
  testTimeout: 15000,
  coverageProvider: "v8",
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/$1",
  },
  testMatch: [
    "**/__tests__/**/*.(test|spec).js",
    "**/?(*.)+(test|spec).js",
  ],
  collectCoverageFrom: [
    "app/**/*.js",
    "components/**/*.js",
    "hooks/**/*.js",
    "lib/**/*.js",
    "store/**/*.js",
    "!**/__tests__/**",
    "!**/node_modules/**",
  ],
};

module.exports = createJestConfig(customJestConfig);
