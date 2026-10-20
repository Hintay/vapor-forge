#!/usr/bin/env bash
# Install Vapor Forge for the current user and load it into Steam through
# LD_AUDIT. Only files under $HOME are written, so the install survives
# SteamOS updates. Run it from the extracted release directory.
#
#   ./install.sh            install or update
#   ./install.sh uninstall  remove the libraries and launch hooks

set -euo pipefail

SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}
CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}
LIB_DIR=$DATA_HOME/vapor-forge
UNIT_DIR=$CONFIG_HOME/systemd/user
DROPIN_NAME=vapor-forge.conf
# Gaming mode on SteamOS runs Steam as steam-launcher.service. Desktop
# sessions start Steam from its XDG autostart entry as app-steam@autostart.
UNITS=(steam-launcher.service app-steam@autostart.service)
# Env Editor (a Decky plugin) keeps Steam's environment in this file, and
# Steam's launcher loads it after the drop-in, so its LD_AUDIT line wins.
# The plugin can move the file; resolve_env_file follows its setting.
ENV_FILE=$HOME/.env.steam
DECKY_HOME=$HOME/homebrew
SYSTEM_DESKTOP=/usr/share/applications/steam.desktop
USER_DESKTOP=$DATA_HOME/applications/steam.desktop
DESKTOP_MARK=X-Vapor-Forge-Override=true
LIBS=(libvapor_forge.so libvapor_forge_proton_inject.so)
ARCHES=(i686 x86_64)

# The loader skips the entry whose ELF class does not match the process, so
# listing both covers the 32-bit and the 64-bit Steam client.
LD_AUDIT_VALUE=$LIB_DIR/i686/libvapor_forge.so:$LIB_DIR/x86_64/libvapor_forge.so

reload_units() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl --user daemon-reload || echo "warning: systemctl --user daemon-reload failed" >&2
	fi
}

install_libraries() {
	local arch lib
	for arch in "${ARCHES[@]}"; do
		for lib in "${LIBS[@]}"; do
			if [ ! -e "$SRC_DIR/$arch/$lib" ]; then
				echo "error: $SRC_DIR/$arch/$lib is missing; run this script from the extracted release" >&2
				exit 1
			fi
		done
	done
	for arch in "${ARCHES[@]}"; do
		mkdir -p "$LIB_DIR/$arch"
		for lib in "${LIBS[@]}"; do
			# Write a temporary file first so a running Steam keeps its mapping.
			cp -L "$SRC_DIR/$arch/$lib" "$LIB_DIR/$arch/$lib.tmp"
			chmod 755 "$LIB_DIR/$arch/$lib.tmp"
			mv -f "$LIB_DIR/$arch/$lib.tmp" "$LIB_DIR/$arch/$lib"
		done
	done
	echo "Installed libraries to $LIB_DIR"
}

install_dropins() {
	local unit
	for unit in "${UNITS[@]}"; do
		mkdir -p "$UNIT_DIR/$unit.d"
		printf '[Service]\nEnvironment="LD_AUDIT=%s"\n' "$LD_AUDIT_VALUE" >"$UNIT_DIR/$unit.d/$DROPIN_NAME"
		echo "Wrote $UNIT_DIR/$unit.d/$DROPIN_NAME"
	done
}

resolve_env_file() {
	local manifest dir path
	for manifest in "$DECKY_HOME"/plugins/*/plugin.json; do
		[ -f "$manifest" ] || continue
		grep -q '"name": *"Env Editor"' "$manifest" || continue
		dir=$(basename "$(dirname "$manifest")")
		path=$(sed -n 's/.*"env_path": *"\([^"]*\)".*/\1/p' \
			"$DECKY_HOME/settings/$dir/settings.json" 2>/dev/null || true)
		if [ -n "$path" ]; then
			ENV_FILE=$path
		fi
		return
	done
}

# Rewrite LD_AUDIT in $ENV_FILE in the format Env Editor reads and writes:
# `# ` marks a disabled entry, an optional `  # comment` follows the value,
# and the value is double-quoted only when it needs to be. Vapor Forge paths
# are removed from every LD_AUDIT line, enabled or not. In add mode ours are
# appended to the last enabled line, or to a new line if none is enabled.
# Other entries and lines are kept as they are.
update_env_file() {
	local mode=$1 tmp
	tmp=$(mktemp "$ENV_FILE.XXXXXX")
	awk -v ours="$LD_AUDIT_VALUE" -v mode="$mode" '
		function parse(rest,   quote, end, cut, alt) {
			sub(/^[ \t]+/, "", rest)
			value = rest
			comment = ""
			quote = substr(rest, 1, 1)
			if ((quote == "\"" || quote == "\047") && (end = index(substr(rest, 2), quote)) > 0) {
				value = substr(rest, 2, end - 1)
				rest = substr(rest, end + 2)
			} else {
				cut = index(rest, " #")
				alt = index(rest, "\t#")
				if (alt > 0 && (cut == 0 || alt < cut)) cut = alt
				if (cut > 0) {
					value = substr(rest, 1, cut - 1)
					rest = substr(rest, cut + 1)
				} else {
					rest = ""
				}
			}
			sub(/[ \t]+$/, "", value)
			sub(/^[ \t]+/, "", rest)
			if (substr(rest, 1, 1) == "#") {
				comment = substr(rest, 2)
				sub(/^[ \t]+/, "", comment)
			}
		}
		function others(entries,   count, parts, i, kept) {
			count = split(entries, parts, ":")
			kept = ""
			for (i = 1; i <= count; i++) {
				if (parts[i] == "" || parts[i] ~ /\/libvapor_forge\.so$/) continue
				kept = kept (kept == "" ? "" : ":") parts[i]
			}
			return kept
		}
		function emit(entries, note, disabled,   line) {
			if (entries ~ /[ \t"\047#]/) {
				gsub(/\\/, "\\\\", entries)
				gsub(/"/, "\\\"", entries)
				entries = "\"" entries "\""
			}
			line = "LD_AUDIT=" entries
			if (note != "") line = line "  # " note
			if (disabled) line = "# " line
			print line
		}
		NR == FNR {
			if ($0 ~ /^[ \t]*LD_AUDIT=/) on = FNR
			next
		}
		/^[ \t]*LD_AUDIT=/ {
			rest = $0
			sub(/^[ \t]*LD_AUDIT=/, "", rest)
			parse(rest)
			kept = others(value)
			if (mode == "add" && FNR == on) {
				if (kept != "") print "note: LD_AUDIT also loads " kept > "/dev/stderr"
				kept = kept (kept == "" ? "" : ":") ours
			}
			if (kept != "") emit(kept, comment, 0)
			next
		}
		/^[ \t]*#[ \t]*LD_AUDIT=/ {
			rest = $0
			sub(/^[ \t]*#[ \t]*LD_AUDIT=/, "", rest)
			parse(rest)
			kept = others(value)
			if (kept == value) print
			else if (kept != "") emit(kept, comment, 1)
			next
		}
		{ print }
		END { if (mode == "add" && !on) emit(ours, "", 0) }
	' "$ENV_FILE" "$ENV_FILE" >"$tmp"
	cat "$tmp" >"$ENV_FILE"
	rm -f "$tmp"
}

install_env_file() {
	resolve_env_file
	if [ ! -f "$ENV_FILE" ]; then
		return
	fi
	if [ ! -w "$ENV_FILE" ]; then
		echo "warning: cannot write $ENV_FILE; add $LD_AUDIT_VALUE to its LD_AUDIT entry in Env Editor" >&2
		return
	fi
	update_env_file add
	echo "Updated LD_AUDIT in $ENV_FILE"
}

uninstall_env_file() {
	resolve_env_file
	if [ ! -f "$ENV_FILE" ]; then
		return
	fi
	if [ ! -w "$ENV_FILE" ]; then
		echo "warning: cannot write $ENV_FILE; remove the Vapor Forge paths from its LD_AUDIT entry in Env Editor" >&2
		return
	fi
	update_env_file remove
}

install_desktop_entry() {
	if [ ! -f "$SYSTEM_DESKTOP" ]; then
		echo "No $SYSTEM_DESKTOP; skipping the menu launcher"
		return
	fi
	if [ -f "$USER_DESKTOP" ] && ! grep -qx "$DESKTOP_MARK" "$USER_DESKTOP"; then
		echo "warning: $USER_DESKTOP exists and was not written by this script; leaving it unchanged" >&2
		return
	fi
	mkdir -p "$(dirname "$USER_DESKTOP")"
	awk -v audit="$LD_AUDIT_VALUE" -v mark="$DESKTOP_MARK" '
		/^Exec=/ { $0 = "Exec=env \"LD_AUDIT=" audit "\" " substr($0, 6) }
		{ print }
		/^\[Desktop Entry\]$/ { print mark }
	' "$SYSTEM_DESKTOP" >"$USER_DESKTOP"
	echo "Wrote $USER_DESKTOP"
}

uninstall() {
	local unit arch lib
	for unit in "${UNITS[@]}"; do
		rm -f "$UNIT_DIR/$unit.d/$DROPIN_NAME"
		rmdir "$UNIT_DIR/$unit.d" 2>/dev/null || true
	done
	if [ -f "$USER_DESKTOP" ] && grep -qx "$DESKTOP_MARK" "$USER_DESKTOP"; then
		rm -f "$USER_DESKTOP"
	fi
	uninstall_env_file
	for arch in "${ARCHES[@]}"; do
		for lib in "${LIBS[@]}"; do
			rm -f "$LIB_DIR/$arch/$lib"
		done
		rmdir "$LIB_DIR/$arch" 2>/dev/null || true
	done
	rmdir "$LIB_DIR" 2>/dev/null || true
	reload_units
	echo "Uninstalled. Configuration in $CONFIG_HOME/vapor-forge was kept."
	echo "Restart Steam to unload Vapor Forge."
}

case "${1:-install}" in
install)
	install_libraries
	install_dropins
	install_env_file
	install_desktop_entry
	reload_units
	echo "Done. Restart Steam (on a Steam Deck, reboot) to load Vapor Forge."
	;;
uninstall)
	uninstall
	;;
*)
	echo "usage: $0 [install|uninstall]" >&2
	exit 2
	;;
esac
