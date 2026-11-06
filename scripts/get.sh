#!/usr/bin/env bash
# Download a Vapor Forge release and run its installer.
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hintay/vapor-forge/main/scripts/get.sh)" @ install
#
# Run `@ help` for the other commands and options.

set -euo pipefail

REPO=https://github.com/Hintay/vapor-forge
# Global so the EXIT trap still sees it after main returns.
WORK_DIR=""

usage() {
	cat <<'EOF'
usage: get.sh [command] [--version TAG]

commands:
  install     install or update Vapor Forge (default)
  uninstall   remove the libraries and launch hooks; configuration is kept
  help        show this message

options:
  --version TAG   use the release TAG, such as v0.1.2, instead of the latest
EOF
}

fail() {
	echo "error: $*" >&2
	exit 1
}

latest_version() {
	local url
	# The latest-release page redirects to the tag page of that release.
	url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPO/releases/latest") ||
		fail "cannot reach $REPO/releases/latest"
	case "$url" in
	*/releases/tag/*) echo "${url##*/}" ;;
	*) fail "no published release found at $REPO" ;;
	esac
}

main() {
	local command=install version="" archive
	while [ $# -gt 0 ]; do
		case "$1" in
		install | uninstall) command=$1 ;;
		help | -h | --help)
			usage
			return
			;;
		--version)
			[ $# -ge 2 ] || fail "--version needs a release tag"
			version=$2
			shift
			;;
		--version=*) version=${1#--version=} ;;
		*)
			usage >&2
			exit 2
			;;
		esac
		shift
	done

	command -v curl >/dev/null 2>&1 || fail "curl is required"
	command -v tar >/dev/null 2>&1 || fail "tar is required"

	version=${version:-$(latest_version)}
	archive=vapor-forge-$version-linux.tar.gz
	WORK_DIR=$(mktemp -d)
	trap 'rm -rf "$WORK_DIR"' EXIT

	echo "Downloading Vapor Forge $version"
	curl -fL --progress-bar -o "$WORK_DIR/$archive" "$REPO/releases/download/$version/$archive" ||
		fail "cannot download $archive"
	tar -xzf "$WORK_DIR/$archive" -C "$WORK_DIR"
	[ -f "$WORK_DIR/vapor-forge-$version/install.sh" ] || fail "$archive has no install.sh"
	bash "$WORK_DIR/vapor-forge-$version/install.sh" "$command"
}

main "$@"
