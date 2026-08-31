// `server-only` is a Next marker package that throws if a module is pulled
// into a client bundle. It has no resolvable entry under vitest's node
// environment, so the runner aliases it here to keep server modules (
// lib/forms.ts) unit-testable. Not collected as a test: the runner's
// include pattern is *.test.ts.
export {};
