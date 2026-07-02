# Vapor Forge

Yet another mod for the Linux Steam client, built with Rust.

## Features

- SteamUI library management, purchase time stamps, and app removal
- Cloud save redirection and sync control
- Rich presence spoofing and app avatar override
- Achievement unlock and progress modification
- In-game toast notifications through CEF injection
- Proton/Wine per-game native library injection
- Lua scripting and config hot-reload

## Prerequisites

- **Rust** 1.80+ (MSRV), toolchain **1.96.0** pinned in `rust-toolchain.toml`
- **Targets:** `i686-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`
- **i686 linker:** `gcc` with 32-bit libc headers (`-m32`)

`rustup` will install the pinned toolchain and targets automatically on first build.

## Build

```sh
cargo build-main            # 32-bit main library  (libvapor_forge.so)
cargo build-inject          # 64-bit Proton helper (libvapor_forge_proton_inject.so)

cargo build-main-release    # release variants
cargo build-inject-release
```

## Install

Vapor Forge loads through the `LD_AUDIT` mechanism. Add it to your Steam launch environment:

```sh
LD_AUDIT=/path/to/libvapor_forge.so
```

### File layout

```
~/.config/vapor-forge/
  config.toml               # main configuration
  patterns.toml             # optional pattern overrides
  scripts/                  # user Lua scripts
  cache/                    # ticket and session cache
```

Lua scripts are also loaded from `{Steam}/config/lua/` if the directory exists.

## Configuration

All configuration lives in `~/.config/vapor-forge/config.toml`. The file is optional. Defaults are applied for every missing field. Changes are picked up automatically through hot-reload.

### Minimal example

```toml
[runtime]
log_level = "info"          # trace, debug, info, warn, error

[cloud]
enabled = true

[toast]
enabled = true

[scripting]
paths = ["/home/deck/my-scripts"]
```

### Sections

| Section | Purpose |
| --- | --- |
| `[runtime]` | Log level, diagnostics toggle, online pattern URL |
| `[toast]` | Enable/disable in-game toast notifications |
| `[cloud]` | Cloud save control |
| `[achievements]` | Offline schema toggle |
| `[app_avatar]` | App ID remapping for online presence |
| `[library_inject]` | Native `.so`/`.dll` injection rules per game |
| `[scripting]` | Extra Lua script directory paths |

### Lua scripting

Lua scripts can register apps, set avatars, provide stat donors, and more. Scripts are loaded from (in priority order):

1. `{Steam}/config/lua/`
2. `~/.config/vapor-forge/scripts/`
3. Paths listed in `[scripting].paths`

## Check

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## License

AGPL-3.0-only
