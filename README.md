# steam-runtime-rs

Rust-first Steam runtime instrumentation and hook-runtime experiment.

The repository has moved beyond the earlier read-only observation phases. The current workspace contains:

- Linux `LD_AUDIT` `cdylib` entrypoints that wait for Steam loader lifecycle milestones before installing hooks;
- i686 build configuration for Steam's 32-bit runtime path;
- bounded lifecycle, module, `/proc/self/maps`, disk ELF metadata, and mapped-byte diagnostics for public Steam target module names;
- hook boundary validation for module name, architecture, executable range, replacement address, and write-request rejection;
- pattern registry support with embedded defaults and runtime TOML overrides;
- hook installation for ownership, package, cloud, DLC, ticket, manifest, depot key, and network packet surfaces;
- feature modules that keep most business decisions outside the unsafe hook callbacks;
- Lua scripting and config hot-reload support for runtime state;
- diagnostics CLI tools and smoke scripts for read-only and hook-boundary checks.

The crate layout is intentionally layered:

- `audit-loader` owns LD_AUDIT entrypoints and lifecycle handoff;
- `hooks` owns unsafe hook installation, detour lifecycle, VMT swaps, and thin callback shells;
- `features` owns testable business behavior for apps, DLC, cloud, tickets, manifests, achievements, and online pattern fetching;
- `config`, `scripting`, `patterns`, `steam-abi`, `memory`, `diagnostics`, and `runtime-core` provide typed support code;
- `hook-boundary` provides synthetic validation and patch-planning checks.

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
