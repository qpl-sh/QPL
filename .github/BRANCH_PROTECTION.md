Branch protection rules (manual apply)

These are the recommended branch protection settings to apply in the repository settings UI (Settings → Branches → Add rule) or via the REST API.

1) Rule: `main`
- Require pull requests before merging: enabled
- Require approvals: 1 (2 recommended for stricter control)
- Require review from CODEOWNERS: enabled (after CODEOWNERS is updated)
- Require status checks to pass before merging: Enabled. Required checks:
  - CI / Check Format (job name: "Check Format")
  - CI / Lint (clippy) (job name: "Lint (clippy)")
  - CI / Test (job name: "Test")
  - CI / Dependency Audit (job name: "Dependency Audit")
- Require branches to be up-to-date before merging: enabled
- Dismiss stale approvals when new commits are pushed: enabled
- Restrict who can push to matching branches: Maintain a small set of maintainers and automation accounts
- Do not allow force pushes: enabled
- Enforce for administrators: enabled

2) Rule: `release/*` (or `v*`)
- Require PRs and 2 approvals
- Require same status checks as `main`
- Restrict direct pushes to release team
- Disable force pushes

3) Tag protection (if available on plan)
- Protect tags matching `v*` and restrict who can create/update tags

If you'd like, I can provide the exact REST API payloads or a step-by-step UI walkthrough. Note: I was unable to set these settings automatically with the available repository write tools; please confirm if you'd like the API payloads or a guided UI walkthrough.
