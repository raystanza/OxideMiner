# Contributing to OxideMiner

We are excited that you are interested in contributing to OxideMiner! This project is built with the Rust
community’s collaborative spirit and is licensed under the Business Source License 1.1 (BSL-1.1). By
contributing, you agree that your submissions are provided under the terms in [LICENSE](LICENSE) and will adopt
the change license on the schedule described there.

Whether you are fixing a bug, proposing a feature, or improving documentation, this guide will help you get
started.

## Ground Rules

- **Be respectful.** Our [Code of Conduct](CODE_OF_CONDUCT.md) outlines the expectations for all interactions.
- **Be transparent.** Disclose any affiliations or potential conflicts in issues and pull requests.
- **Be safe.** Do not submit code that circumvents the BSL-1.1 terms or introduces hidden behavior.
- **Be reproducible.** Include steps, logs, hardware details, or benchmarks so maintainers can validate changes.

## How to Contribute

### 1. Open an issue

Before investing significant effort, please search existing issues. If you have a new idea, open an issue using
one of the templates to describe the problem, context, and desired outcome. Early discussion helps align on
scope and design decisions.

### 2. Fork and branch

Fork the repository and work from a feature branch. Keep branches focused on a single change to make reviews
easier.

### 3. Develop your change

- Install the latest stable Rust toolchain via [`rustup`](https://rustup.rs/).
- Use the commands listed in the README to build and test locally.
- Add or update unit tests when fixing bugs or introducing features.
- Update documentation or configuration samples when behavior changes.

### 4. Run project checks

Before opening a pull request, ensure the workspace is clean:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --all
```

Please include any additional domain-specific checks (benchmarks, fuzzers, etc.) when relevant, and share the
output in your pull request description.

### 5. Submit a pull request

When you are ready, open a pull request against the `main` branch:

- Complete the pull request template so reviewers understand the change.
- Reference related issues (e.g., `Closes #123`).
- Keep commits logically organized and well-described. Squash or rebase as needed for clarity.
- Be responsive to review feedback; discussions are collaborative and respectful.

## Code Style and Quality

- Follow Rust 2021 edition idioms and prefer safe Rust.
- Use descriptive naming and doc comments for public APIs.
- Keep functions focused; favor smaller units with clear responsibilities.
- Include logging via the existing tracing infrastructure where helpful.
- Document unsafe blocks thoroughly. Avoid them unless absolutely necessary for performance.

## Security and Responsible Disclosure

If you believe you have found a security vulnerability, please follow the guidance in
[SECURITY.md](SECURITY.md). Do not open a public issue for security-sensitive reports.

## Recognition

We appreciate every contribution. Maintainers will acknowledge significant changes in release notes and will
credit contributors in changelog entries once established.

Thank you for helping make OxideMiner better and for respecting the BSL-1.1 licensing terms.
