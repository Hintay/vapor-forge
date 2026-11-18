#!/usr/bin/env bash
# Run the ignored two-device simulation tests against a throwaway Cumulus
# server. The server gets a fresh SQLite database and data directory, listens
# on 127.0.0.1:18080 by default, and is stopped when the script exits.
#
# Usage: scripts/cumulus-sim.sh [extra cargo test args]
# Environment:
#   CUMULUS_DIR       Cumulus checkout (default: ../cumulus next to this repo)
#   CUMULUS_SIM_PORT  listen port (default: 18080)
#   CUMULUS_SIM_KEEP  set to 1 to keep the server running after the tests
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cumulus_dir="${CUMULUS_DIR:-$(cd "$repo_dir/../cumulus" && pwd)}"
port="${CUMULUS_SIM_PORT:-18080}"
sim_dir="$cumulus_dir/target/sim"
export TMPDIR="${TMPDIR_OVERRIDE:-$cumulus_dir/target/tmp}"
mkdir -p "$TMPDIR"

admin_user="sim-admin"
admin_password="SimPassphrase!2026-cumulus"

echo "building cumulus server"
(cd "$cumulus_dir" && cargo build -p cumulus-server)
bin="$cumulus_dir/target/debug/cumulus"

rm -rf "$sim_dir/db" "$sim_dir/data"
mkdir -p "$sim_dir/db" "$sim_dir/data"
export CUMULUS_DATABASE__URL="sqlite://$sim_dir/db/cumulus-sim.db?mode=rwc"
export CUMULUS_STORAGE__DATA_DIR="$sim_dir/data"
export CUMULUS_LISTEN="127.0.0.1:$port"
# No config file: defaults plus the overrides above.
config="$sim_dir/cumulus-sim.toml"
: >"$config"

RUST_LOG=warn "$bin" --config "$config" account create "$admin_user" \
    --role admin --password "$admin_password" >/dev/null

if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $port is already in use" >&2
    exit 1
fi

RUST_LOG="${RUST_LOG:-info,sqlx=warn}" "$bin" --config "$config" serve \
    >"$sim_dir/server.log" 2>&1 &
server_pid=$!
stop_server() {
    if [[ "${CUMULUS_SIM_KEEP:-0}" == 1 ]]; then
        echo "server left running (pid $server_pid, log $sim_dir/server.log)"
        return
    fi
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap stop_server EXIT

for _ in $(seq 1 100); do
    if curl -s -o /dev/null "http://127.0.0.1:$port/api/v1/auth/registration"; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "server exited early; see $sim_dir/server.log" >&2
        exit 1
    fi
    sleep 0.1
done

export CUMULUS_SIM_URL="http://127.0.0.1:$port"
export CUMULUS_SIM_ADMIN_USER="$admin_user"
export CUMULUS_SIM_ADMIN_PASSWORD="$admin_password"

cd "$repo_dir"
status=0
for package in vapor-forge-cloud-rpc vapor-forge-cloud-cumulus vapor-forge-hooks; do
    echo "running simulation tests in $package"
    cargo test -p "$package" "$@" -- --ignored --nocapture cumulus_sim || status=1
done
exit "$status"
