# Contributing to Bonded

Thank you for considering contributing to Bonded! This document outlines the process and guidelines.

## Development Workflow

1. Fork the repository
2. Create a feature branch from `main`: `git checkout -b feature/my-feature`
3. Make your changes
4. Ensure tests pass
5. Submit a pull request

## Branch Naming

- `feature/<description>` — New features
- `fix/<description>` — Bug fixes
- `docs/<description>` — Documentation changes
- `refactor/<description>` — Code refactoring

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<optional body>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`
Scopes: `server`, `client`, `proto`, `docs`

Examples:

```
feat(server): add connection multiplexing
fix(client): resolve Wi-Fi interface detection on Android
docs: update architecture diagram
```

## Code Style

- **Rust:** Follow `rustfmt` defaults. Run `cargo fmt` before committing.
- **Dart/Flutter:** Follow `dart format` defaults. Run `dart format .` before committing.

## Reporting Issues

Use GitHub Issues with the appropriate template. Include:

- Steps to reproduce
- Expected vs. actual behavior
- Platform and version information
