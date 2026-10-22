/**
 * Jest configuration for the Vanzik TypeScript SDK.
 *
 * ts-jest compiles the TS sources on demand. Tests live under
 * src/__tests__/ and are excluded from the production build via
 * tsconfig.json.
 */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.test.ts", "**/?(*.)+(spec|test).ts"],
  // Keep the production build free of test files; ts-jest still compiles
  // them on the fly for the test run.
  transform: {
    "^.+\\.ts$": ["ts-jest", { tsconfig: { rootDir: "./src" } }],
  },
  // A pending waitForApproval timer can briefly outlive a test; forceExit
  // avoids a CI hang. Use `npx jest --detectOpenHandles` to hunt real leaks.
  forceExit: true,
};
