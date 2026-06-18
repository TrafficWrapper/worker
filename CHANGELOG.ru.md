# Changelog

🇬🇧 English: [CHANGELOG.md](CHANGELOG.md)

Все заметные изменения этого repository документируются здесь.

Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), а
project следует [Semantic Versioning](https://semver.org/spec/v2.0.0.html) для
public releases.

## [Unreleased]

### Added

- Repository CODEOWNERS, secret-scan workflow и gitignore hygiene для local Go
  build binaries.
- Ссылка из worker README на канонический orchestrator troubleshooting guide.

## [0.1.0] - 2026-06-18

### Added

- Initial public worker split с agent, Xray REALITY ingress, AmneziaWG gateway,
  in-tunnel distributor, smoke helper и public Go transport core.
- Worker onboarding docs, architecture notes, threat model, CI workflow и
  русские documentation mirrors.

### Changed

- Обновлены AmneziaWG transport dependencies для чистой сборки с gVisor и Go
  1.24 без старого netstack patch workaround.
- Worker modules, agent Dockerfile и CI выровнены на Go 1.24 там, где этого
  требует local `replace ../core`.

### Fixed

- Worker теперь отказывается от placeholder `CAMOUFLAGE_DOMAIN` values до
  запуска REALITY.
- Startup Xray config restore отслеживает restart-pending state и пробрасывает
  restart failures.
