# ZAP_PTK workspace instructions

Status: current
Owner: workspace maintainer
Verified: 2026-10-04 — shared instruction routing; not product or fresh-session qualification

NEVER execute `rg`/ripgrep, directly or through wrappers.

This repository is part of the PTK multi-repository workspace. Before task work,
resolve the workspace as this repository's parent directory and read completely:

1. `../AGENTS.md`
2. `../.codex/AGENTS.md`
3. `../.codex/README.md`, then its task-specific route
4. `../.codex/zap/README.md`
5. `../.codex/ptk/README.md`

Resolve these paths from this repository root, not a deeper working directory.
If shared guidance is absent (for example in a standalone clone), stop before
implementation and ask for the workspace guidance; do not invent replacement rules.

Only the user commits and pushes. Preserve existing dirty worktrees. Shared
operating rules own authorization; this entry point grants no additional permission.
