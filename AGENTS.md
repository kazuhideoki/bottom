# Development guidance

## Change authority

- Stage, commit, push, create a PR, or publish changes only when the user explicitly requests that action for the current work.
- Preserve unrelated user changes, including staged and untracked files. Do not undo or rewrite them.

## Upstream separation policy for Agent Monitor

This fork adds a personal Codex/Claude resource dashboard while keeping upstream `bottom` easy to rebase. Treat the Agent Monitor as an optional feature with a narrow integration boundary.

### Ownership boundary

- Keep Agent-specific detection, process-family aggregation, lifecycle identity, history, findings, selection state, and rendering under `src/agent_monitor/`.
- Do not move provider-specific rules into upstream widgets, collectors, or platform implementations.
- Do not wildcard-re-export Agent Monitor internals. Export only the boundary type or functions required by core integration.
- Agent Monitor consumes `ProcessData` as read-only input. It must derive any extra identity or lifecycle state inside its own module.

### Feature and runtime isolation

- Keep all user-facing Agent surfaces behind the `agent-monitor` Cargo feature: `--agent`, the `a` shortcut, `type = "agent"`, help text, layout variants, collection events, and rendering.
- This personal fork may include `agent-monitor` in its default features, but `--no-default-features` must compile and behave without reserving Agent CLI, layout, or key surfaces.
- A normal layout must not collect process, CPU, or memory data solely because Agent Monitor is compiled. Enable that collection only while the overlay is open or an Agent widget exists in the active layout.
- Send runtime collection changes through the explicit collection-thread event. Do not make the collector inspect UI state directly.

### Upstream data structures

- Do not add fields to cross-platform types such as `ProcessHarvest` solely for Agent Monitor.
- In particular, do not modify every OS collector to expose process start time for Agent session identity. Keep PID reuse handling local by combining observed PID continuity with uptime/generation tracking.
- Keep changes in `App`, input dispatch, layout, canvas dispatch, and the collection loop to small feature-gated hooks. Prefer methods on the Agent boundary over direct field access.
- Do not widen upstream method visibility for production code just to support tests. Use feature-gated test helpers instead.

### Required tests before refactoring

Add or update characterization tests before changing integration behavior. Preserve coverage for:

- `--agent`, custom `agent` layouts, `a`, `Esc`, and process-search key capture;
- lazy collection enable/disable events;
- nested process aggregation, detached and zombie findings, and RSS-growth signals;
- PID reuse and disappeared/reappeared processes not inheriting history (keep separate regression tests for both cases);
- selection identity across resorting;
- tree viewport behavior at the top, middle, and bottom;
- absence of Agent CLI/layout/help surfaces without the feature.

### Verification matrix

Run at least:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --no-default-features --features deploy -- -D warnings
cargo test --all-targets
cargo test --all-targets --no-default-features
cargo test --all-targets --no-default-features --features deploy
```

On macOS, `test_get_config_path_macos` depends on whether a legacy real-user config already exists. If that upstream test is environment-blocked, document it and rerun the remaining full matrix with `--skip test_get_config_path_macos`; do not treat the skip as an Agent Monitor failure.

For UI-affecting changes, also build and exercise the real TUI in a PTY: start with `--agent`, toggle to the normal view and back with `a`, navigate to the first and last sessions, and confirm the process tree and graphs remain visible and aligned.

## Upstream sync discipline

- Before rebasing onto upstream, inspect Agent integration points separately from Agent-owned files.
- Resolve upstream changes in their original structure first, then reapply the smallest feature-gated hooks needed by `src/agent_monitor/`.
- If a proposed Agent change requires broad platform collector edits, stop and look for a local derivation or adapter at the Agent boundary first.
