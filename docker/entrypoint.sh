#!/bin/sh
# Runs as root only long enough to prepare the data directory, then drops privileges.
set -eu

if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR:-/data}"
  chown -R "${PUID:-10001}:${PGID:-10001}" "${DATA_DIR:-/data}"

  # gosu resets supplementary groups to the numeric user's (usually absent) passwd entry, which drops
  # groups Docker added with --group-add (the Docker socket group). setpriv keeps them; root's own
  # group is removed so the app does not run with extra privileges.
  extra_groups="$(id -G | tr ' ' '\n' | grep -vx 0 | paste -sd, -)"
  if command -v setpriv >/dev/null 2>&1; then
    if [ -n "$extra_groups" ]; then
      exec setpriv --reuid "${PUID:-10001}" --regid "${PGID:-10001}" --groups "$extra_groups" "$@"
    fi
    exec setpriv --reuid "${PUID:-10001}" --regid "${PGID:-10001}" --clear-groups "$@"
  fi

  exec gosu "${PUID:-10001}:${PGID:-10001}" "$@"
fi

exec "$@"
