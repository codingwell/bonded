# Bonded Implementation Instructions

These instructions are for the implementation agent working on Bonded.

## Primary Goal

Build the server, Linux client, and Android client for initial end-to-end testing, following the requirements in `docs/requirements/` and the phased plan in `docs/design/implementation-plan.md`.

## Source of Truth

Read these first and keep them aligned with your work:

1. `docs/requirements/product-requirements.md`
2. `docs/requirements/platform-requirements.md`
3. `docs/requirements/open-questions.md`
4. `docs/design/implementation-plan.md`

If code and docs disagree, update code to match the requirements unless the requirements are clearly stale. If you discover a necessary design decision not captured in the docs, add it to the implementation plan under `Key Implementation Decisions`.

## Required Working Style

1. Work in small vertical slices that produce a runnable checkpoint.
2. Prefer shared Rust code for protocol, auth, session, scheduler, and transport logic.
3. Keep the first transport as NaiveTCP until end-to-end flow works.
4. Do not start peer-sharing implementation until the base server + Linux client tunnel works reliably.
5. Keep the Android app thin at first: pairing, VPN plumbing, and a minimal connect/disconnect UI.

## Progress Tracking

`docs/design/implementation-plan.md` is the live checkpoint file and MUST be updated during implementation.

Update it when:

- a task starts
- a task completes
- a task is blocked
- a design decision is made
- a new subtask is discovered

For each touched task:

- change `Status`
- update `Notes` with concrete details
- record any new blocker in `Blockers / Issues`
- record any architecture or library decision in `Key Implementation Decisions`

Do not leave the document stale after a coding session.

## Phase Order

Follow this order unless blocked:

1. Cargo workspace and shared crates
2. Core framing, session layer, auth primitives, NaiveTCP transport
3. Server startup, config, pairing, QR emission, session acceptance
4. Linux CLI client with TUN integration and end-to-end tunnel test
5. Android shell app, QR scan, pairing, VPN integration
6. Production transport(s)
7. Peer-sharing feature work

## Definition of Done for Each Checkpoint

A checkpoint is complete only if:

- the code builds
- any available tests for the changed area pass
- the implementation plan is updated
- the checkpoint can be resumed by another agent from the docs alone

## Scope Discipline

Do not expand scope beyond the current phase without updating the plan.

Examples:

- Do not build a dashboard for device management in v1.
- Do not implement advanced scheduler strategies before naive scheduling works.
- Do not implement QUIC or WSS before NaiveTCP end-to-end tests pass.

## Preferred Early Libraries

These are suggestions, not mandates:

- `bytes` for framing buffers
- `tokio-util` for codecs if useful
- `serde` + `toml` for config
- `notify` for file watching
- `ed25519-dalek` or equivalent for signing/auth identity
- `qrcode` for terminal/log QR generation
- `tun` or platform-appropriate crate for Linux TUN handling

Choose libraries pragmatically and log the decision in the implementation plan.