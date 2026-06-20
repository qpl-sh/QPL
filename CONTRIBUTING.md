# Contributing to QPL

Thanks for wanting to contribute — we welcome fixes, improvements, and documentation updates.

Quick checklist for contributors:

- Fork the repo and create a topic branch for your work.
- Run formatting and lints locally:
  - cargo fmt --all -- --check
  - cargo clippy --workspace --all-targets -- -D warnings
- Run tests:
  - cargo test --workspace
- If you change public APIs or behavior, add a short note to CHANGELOG.md (or create one).
- Keep PRs small and focused. Reference an issue when appropriate.

How to open a good PR:

- Ensure CI passes on your branch.
- Include a brief description of the change and the motivation.
- Link to any related issues, design notes, or external references.

Maintainers: please review the CODEOWNER file and update reviewer assignments as needed.
