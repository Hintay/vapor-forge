# steam-runtime-rs

Rust-first Steam runtime instrumentation experiment.

This repository is currently limited to read-only observation through Phase 4B, Phase 5A release and supply-chain hardening, Phase 5B disk-only public symbol reporting, Track C option 2 bounded mapped-byte sampling, Track D-6 synthetic/no-write hook Go/No-Go readiness, and Track E planning-only real-hook prototype design:

- workspace and provenance skeleton;
- minimal Linux `LD_AUDIT` `cdylib` entrypoints;
- i686 build configuration hooks;
- bounded lifecycle, module, `/proc/self/maps`, and disk ELF metadata diagnostics for public Steam target module names;
- disk-only public dynamic symbol report for public Steam target module files;
- bounded mapped-byte sampling for public target module mappings, emitting only digest/structural results;
- synthetic-only hook boundary tests using local `extern "C"` function pointers, without real Steam hooks;
- synthetic/no-write raw hook eligibility checks for module name, architecture, target address range, replacement address, and write-request rejection;
- synthetic/no-write raw hook action gating that accepts validate-only decisions and rejects install requests;
- synthetic/no-write patch-plan verification for relative-jump reachability and patch length;
- synthetic byte-buffer patch simulation using test-owned memory only;
- Track D-6 Go/No-Go decision documentation before any real hook prototype;
- Track E planning-only real-hook prototype documentation, without implementation authorization;
- pinned Rust toolchain and full read-only verification entrypoint;
- no Steam entitlement, ticket, package, depot, or authorization-control behavior.

The implementation policy is independent authorship. Do not copy or mechanically translate SLSsteam source, comments, file layout, or project-specific naming.

## Initial checks

The pinned Rust toolchain is declared in `rust-toolchain.toml` and currently uses Rust `1.96.0` with `rustfmt`, `clippy`, and the `i686-unknown-linux-gnu` target.

Fast workspace checks:

```sh
./scripts/check.sh
```

Linux/i686 audit-loader check:

```sh
./scripts/check-i686.sh
```

Full read-only validation, including native/i686 release builds and Phase 4A/4B/5B plus Track C and Track D synthetic smoke tests:

```sh
sh ./scripts/verify-readonly.sh
```

The full validation script does not run real Steam. Real Steam validation remains an explicit manual/remote validation step because it interacts with the desktop Steam session.
