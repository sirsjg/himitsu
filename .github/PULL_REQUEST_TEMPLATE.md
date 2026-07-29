<!--
Security vulnerabilities do not go in a pull request. Report privately: see SECURITY.md.
-->

## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Checks

- [ ] `npm run build` then `npm run typecheck`, `npm test`, `npm run docs:check` pass
- [ ] Tests added or updated — a bug fix includes a test that failed before it
- [ ] Documentation in `docs/` updated if behavior changed

## Generated files

<!-- CI fails on stale generated output. Tick what applies, or leave blank if untouched. -->

- [ ] Routes or schemas changed → ran `npm run docs:openapi` and committed `docs/openapi.json`
- [ ] `integrations/github-action` changed → rebuilt and committed its `dist/`
- [ ] Operator API types changed → regenerated CRDs, RBAC, deepcopy and committed them
- [ ] Added a new forward migration rather than editing a shipped one

## Impact

- [ ] Touches encryption, authentication, authorization, or the tenant boundary
- [ ] Changes a stored data format or affects an existing deployment's upgrade path
- [ ] Adds a dependency

<!-- If any of the above is ticked, explain the reasoning here. -->
