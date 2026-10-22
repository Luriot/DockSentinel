#!/bin/sh
# Runs as root only long enough to prepare the data directory, then drops privileges.
set -eu

if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR:-/data}"
  chown -R "${PUID:-10001}:${PGID:-10001}" "${DATA_DIR:-/data}"
  exec gosu "${PUID:-10001}:${PGID:-10001}" "$@"
fi

exec "$@"
