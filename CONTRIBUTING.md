# Contributing to StrontiumDB

Thank you for your interest in contributing to StrontiumDB. This document provides guidelines for contributing.

## Code of Conduct

Be respectful. We are building database software, not fighting wars.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/strontiumdb.git`
3. Create a branch: `git checkout -b your-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run clippy: `cargo clippy --all-targets -- -D warnings`
7. Format code: `cargo fmt`
8. Commit and push
9. Open a pull request

## Code Style

### Rust

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- No `unwrap()` in library code (use proper error handling)
- Prefer descriptive variable names over comments
- Keep functions small and focused

### Comments

- Code should be self-documenting
- Only add comments when the "why" is not obvious from the "what"
- No redundant comments like `// increment counter` above `counter += 1`
- Use rustdoc for public API documentation

### Tests

- Write tests for new functionality
- Tests should be in the same file as the code they test
- Use descriptive test names: `test_timestamp_definitely_before_non_overlapping`
- Property-based tests for invariants (we use proptest)

## Pull Request Process

1. Ensure all CI checks pass
2. Update documentation if needed
3. Add tests for new functionality
4. Keep PRs focused - one feature or fix per PR
5. Write a clear description of what and why

### Commit Messages

- Use present tense: "Add feature" not "Added feature"
- First line should be a summary under 72 characters
- Reference issues if applicable: "Fix clock detection (#123)"

## Architecture

### TimeService Module (`src/time/`)

The core time synchronization module:

- `timestamp.rs` - The `Timestamp` type with uncertainty intervals
- `traits.rs` - The `TimeService` trait
- `detect.rs` - Clock source detection logic
- `phc.rs` - PTP Hardware Clock implementation
- `ntp.rs` - NTP/chrony integration
- `hlc.rs` - Hybrid Logical Clock fallback
- `gps.rs` - GPS/PPS support

Key principles:
- `now()` must complete in <100ns with zero allocations
- Use atomics for hot-path data, never locks
- Fail gracefully - always have a fallback

### Validation (`validation/`)

Cloud validation scripts for AWS, Azure, and GCP. These verify our uncertainty measurements match the actual clock quality.

## Running Benchmarks

```bash
cargo bench
```

Results are in `target/criterion/`. The key metric is `now()` latency.

## Cloud Testing

To test on cloud platforms:

```bash
# AWS (requires AWS CLI configured)
cd validation && ./aws-validate.sh m7i.large

# Azure (requires Azure CLI configured)
cd validation && ./azure-validate.sh Standard_D2s_v3 westus2

# GCP (requires gcloud CLI configured)
cd validation && ./gcp-validate.sh
```

## Questions

Open an issue for questions or discussions. We prefer public discussions so others can benefit.

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
