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
- **x86_64 Linux linker:** `x86_64-linux-gnu-gcc` when cross-building from a non-Linux host

`rustup` will install the pinned toolchain and targets automatically on first build.

## Build

```sh
cargo build-main            # 32-bit main library  (libvapor_forge.so)
cargo build-main64          # 64-bit main library  (libvapor_forge.so)
cargo build-inject          # 64-bit Proton helper (libvapor_forge_proton_inject.so)

cargo build-main-release    # release variants
cargo build-main64-release
cargo build-inject-release
```

## Install

Vapor Forge loads through the `LD_AUDIT` mechanism. Add it to your Steam launch environment.
Use the library whose target architecture matches the Steam process:

- 32-bit Steam: `target/i686-unknown-linux-gnu/{debug,release}/libvapor_forge.so`
- 64-bit Steam: `target/x86_64-unknown-linux-gnu/{debug,release}/libvapor_forge.so`

```sh
LD_AUDIT=/path/to/libvapor_forge.so
```

The 64-bit audit loader initializes configuration, scripting, diagnostics, debug IPC, SteamClient
hooks, SteamUI hooks, VMT-scanner hooks, and launch-environment injection. pkg0 PackageInfo field
offsets are verified for the current 64-bit Steam baseline (`PackageId` at `+0x00`, `status` at
`+0x18`, `m_vecAppIDs` at `+0x40`). The 64-bit `CPackageInfo::GetPackageInfo` hook captures the
package-store object and calls Steam's token-map lookup with pkg0's known access token.

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

All configuration lives in `~/.config/vapor-forge/config.toml`. The file is optional. If no config exists, Vapor Forge creates a starter file from `res/config.default.toml` with recommended defaults and commented examples. On later launches, missing recommended fields and commented examples are synced from that template without overwriting existing values. If a commented example is uncommented, it becomes normal user config and is preserved on future syncs. Defaults are applied for every missing field. Changes are picked up automatically through hot-reload.

See `res/config.default.toml` for the full generated template and commented examples.

### Cumulus cloud saves

Set the Cumulus origin and a device bearer token under `[cloud]`. A complete
Cumulus configuration enables cloud sync for controlled, unowned apps even when
the legacy `enabled` flag is left false. Owned apps remain on Steam's normal
cloud path.

```toml
[cloud]
server_url = "https://cloud.example.com"
token = "device-bearer-token"
timeout_connect_ms = 5000
timeout_ms = 15000
```

The token is sent to Cumulus by both the metadata adapter and Steam's HTTP byte
transfers. Use HTTPS outside a trusted private network.

`IClientRemoteStorage` is used only to keep Steam's per-app cloud enable gate
open. Save synchronization is handled separately by intercepting the Steam
client's decoded `Cloud.*#1` service RPCs on the CM connection; game-facing
`FileRead`/`FileWrite` calls are not redirected.

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
