# Changelog

🇷🇺 Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)

All notable changes to this repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for public releases.

## [Unreleased]

### Added

- Repository CODEOWNERS, secret-scan workflow, and gitignore hygiene for local Go
  build binaries.
- Link from the worker README to the canonical orchestrator troubleshooting
  guide.

## [0.1.0] - 2026-06-18

### Added

- Initial public worker split with agent, Xray REALITY ingress, AmneziaWG gateway,
  in-tunnel distributor, smoke helper, and public Go transport core.
- Worker onboarding docs, architecture notes, threat model, CI workflow, and
  Russian documentation mirrors.

### Changed

- Upgraded AmneziaWG transport dependencies to build cleanly with gVisor and Go
  1.24 without the old netstack patch workaround.
- Aligned worker modules, agent Dockerfile, and CI with Go 1.24 where required
  by local `replace ../core`.

### Fixed

- Worker now refuses placeholder `CAMOUFLAGE_DOMAIN` values before starting
  REALITY.
- Startup Xray config restore tracks restart-pending state and propagates restart
  failures.
