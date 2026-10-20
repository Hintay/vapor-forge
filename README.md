# Vapor Forge

Yet another mod for the Linux Steam client, built with Rust.

## Features

- SteamUI library management, purchase time stamps, and app removal
- Cloud save redirection and sync control
- Rich presence spoofing and app avatar override
- Per-game SteamID override for account-bound saves
- Achievement unlock, clear, and progress synchronization
- In-game toast notifications through CEF injection
- Proton/Wine per-game native library injection
- Lua scripting and config hot-reload

## Prerequisites

- **Rust** 1.85+ (MSRV), toolchain **1.96.0** pinned in `rust-toolchain.toml`
- **Targets:** `i686-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`
- **i686 linker:** `gcc` with 32-bit libc headers (`-m32`)
- **x86_64 Linux linker:** `x86_64-linux-gnu-gcc` when cross-building from a non-Linux host
- **Binary runtime:** glibc 2.17 or newer

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

Published artifacts are cross-linked with Zig against glibc 2.17. Local builds using the commands above inherit the host system's glibc baseline.

## Install

Download `vapor-forge-<version>-linux.tar.gz` from [Releases](https://github.com/Hintay/vapor-forge/releases), extract it, and run the installer as your normal user:

```sh
tar -xzf vapor-forge-<version>-linux.tar.gz
cd vapor-forge-<version>
./install.sh
```

Then restart Steam. On a Steam Deck, run these commands in Konsole in Desktop Mode, then reboot.

The installer only writes to your home directory, so it needs no root access and survives SteamOS updates. It:

- copies the libraries to `~/.local/share/vapor-forge/{i686,x86_64}/`
- adds a systemd user drop-in that sets `LD_AUDIT` for `steam-launcher.service` (Steam Deck Gaming Mode) and for `app-steam@autostart.service` (Steam started at login in a desktop session)
- if `~/.env.steam` exists (for example from the Decky Env Editor plugin), adds the libraries to its `LD_AUDIT` line, because that file overrides the drop-in. Other entries on the line are kept.
- writes `~/.local/share/applications/steam.desktop`, a copy of the system Steam launcher with `LD_AUDIT` added, so Steam started from the application menu loads Vapor Forge too. If you already have this file, the installer leaves it unchanged.

To update, run `./install.sh` from a newer release. `./install.sh uninstall` removes the libraries, the drop-ins, and the launcher, and keeps your configuration in `~/.config/vapor-forge/`. The installer covers the native Steam client; Flatpak Steam is not supported.

### Manual setup

Vapor Forge loads through the `LD_AUDIT` mechanism. List both libraries: the dynamic loader skips the one whose architecture does not match the process, so the same value works for the 32-bit and the 64-bit Steam client.

```sh
LD_AUDIT=/path/to/i686/libvapor_forge.so:/path/to/x86_64/libvapor_forge.so steam
```

Local builds place the libraries in `target/{i686,x86_64}-unknown-linux-gnu/{debug,release}/`. The 64-bit Proton helper `libvapor_forge_proton_inject.so` is looked up next to the loaded library, then in `/usr/lib` and `/usr/lib64`. Releases ship it in both architecture directories. If you keep it elsewhere, set `[library_inject] helper_path`.

The 64-bit audit loader initializes configuration, scripting, diagnostics, debug IPC, SteamClient hooks, SteamUI hooks, VMT-scanner hooks, and launch-environment injection. pkg0 PackageInfo field offsets are verified for the current 64-bit Steam baseline (`PackageId` at `+0x00`, `status` at `+0x18`, `m_vecAppIDs` at `+0x40`). The 64-bit `CPackageInfo::GetPackageInfo` hook captures the package-store object and calls Steam's token-map lookup with pkg0's known access token.

### File layout

```
~/.config/vapor-forge/
  config.toml               # main configuration
  patterns.*.toml           # managed hotfix candidates and active caches
  scripts/                  # user Lua scripts
  cache/                    # ticket and session cache
```

Lua scripts are also loaded from `{Steam}/config/lua/` if the directory exists.

## Configuration

All configuration lives in `~/.config/vapor-forge/config.toml`. The file is optional. If no config exists, Vapor Forge creates a starter file from `res/config.default.toml` with recommended defaults and commented examples. Existing files are never rewritten by the runtime. Defaults are applied for every missing field, unknown fields are rejected, and changes are picked up automatically through hot-reload. The `vapor-forge-config-check` tool can preview template updates explicitly.

See `res/config.default.toml` for the full generated template and commented examples.

`runtime.patterns_url` configures an optional HTTPS hotfix source. The URL must contain `{arch}` and `{family}` placeholders. A downloaded candidate becomes active for a module only after that module validates it against the live Steam binary during a later hook installation, normally on the next Steam start. Source changes made after SteamClient hooks are installed also take effect on the next Steam start. Clearing the URL stops downloads and candidate promotion; it does not remove or disable an active cache, which is revalidated before every use.

### Cumulus cloud saves

Select the Cumulus backend and configure its origin and device bearer token. Owned apps remain on Steam's normal cloud path.

```toml
[cloud]
backend = "cumulus"

[cloud.cumulus]
server_url = "https://cloud.example.com"
token = "device-bearer-token"
timeout_connect_ms = 5000
timeout_ms = 15000
```

The token is sent to Cumulus by both the metadata adapter and Steam's HTTP byte transfers. Use HTTPS outside a trusted private network.

`IClientRemoteStorage` is used only to keep Steam's per-app cloud enable gate open. Save synchronization is handled separately by intercepting the Steam client's decoded `Cloud.*#1` service RPCs on the CM connection; game-facing `FileRead`/`FileWrite` calls are not redirected.

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
