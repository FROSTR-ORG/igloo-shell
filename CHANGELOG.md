# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, adapted for this repository.

## [0.2.0] - 2026-03-27

### Added
- First-class `rotate-key` and `rotate-keyset` operator workflows for rotated-share adoption and trusted-dealer rotation generation.
- Expanded CLI integration and smoke coverage across the shell command surface.

### Changed
- `igloo-shell` is now a CLI-only operator host with the old TUI surface removed.
- Managed profile and backup handling now preserve structured `group_package` data with embedded `group_name`.
- Generated devnet/runtime scratch output now lives under ignored `.tmp/devnet/` instead of tracked repo paths.

### Fixed
- Rotated remote `bfonboard` packages emitted by `rotate-keyset generate` are now consumable by both onboarding and in-place rotation flows.
