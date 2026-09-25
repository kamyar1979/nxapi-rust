# nxapi

Shared Rust library for Cisco NX-API **enforcement**. PCEF will consume it
through its own `EnforcementTarget`. The SDK does not depend on Qanat routing,
OSS event contracts, RabbitMQ, BSS, or customer inventory storage.

## Current status

This is the initial project scaffold, not a functioning switch client yet.
It provides validated Ethernet identifiers and typed operation descriptions.
No network requests are made and PCEF has not been migrated to this crate.

The first implementation will cover only:

- Interface administrative enable/disable.
- Create/update and attach per-interface bandwidth policers.
- Remove SDK-owned throttling without changing link state.
- Read back policy configuration and attachment to verify results.
- Login/session handling, secure-by-default TLS, an explicit lab bypass,
  injectable HTTP transport, and structured Cisco/partial-operation errors.

Provisioning features and support for other Cisco operating systems are out
of scope. NX-OS version and platform limitations must be verified on devices.
An HTTP success response alone must not be reported as verified enforcement.

## Development

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
```

## GitHub Actions and releases

`.github/workflows/release.yml` follows Qanat's release workflow. Pushing a
`v*` tag runs formatting, Clippy, tests and package verification. The tag must
match the Cargo version (for example, `v0.1.0`). Successful verification is
followed by publication to crates.io and a GitHub release with generated notes.
Tags containing a hyphen produce a GitHub prerelease. Like Qanat, this workflow
is tag-triggered; normal branch pushes and pull requests do not trigger it.

Before releasing:

1. Create the public GitHub repository and configure its Git remote. Add the
   actual repository URL to Cargo.toml once it exists.
2. Create the GitHub `release` environment, preferably with required approval.
3. Add a crates.io publishing token as `CARGO_REGISTRY_TOKEN` in that environment.
4. Commit the sources and Cargo.lock, then push a matching version tag when the
   crate is ready for public release.

No workflow has been run remotely and the crate has not been published. The
name `nxapi` was absent from crates.io when checked on 2026-09-25; this does not
reserve it. Publication is restricted to crates.io, not the private registry.

## License

Apache-2.0, matching Qanat. See [LICENSE](LICENSE).
