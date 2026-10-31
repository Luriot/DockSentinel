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

  # A container recreated from an old or stale template may not pass --group-add. Grant the group
  # that owns the mounted Docker socket here, so updating the image never loses socket access.
  # Group 0 is skipped on purpose: adding the root group would widen privileges. A missing or
  # unmounted socket simply skips this step.
  socket_group=""
  if [ -S /var/run/docker.sock ]; then
    socket_group="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || true)"
  fi
  if [ -n "$socket_group" ] && [ "$socket_group" != "0" ]; then
    case ",${extra_groups}," in
      *",${socket_group},"*) ;;
      *)
        echo "DockSentinel: granting Docker socket group ${socket_group}" >&2
        extra_groups="${extra_groups:+${extra_groups},}${socket_group}"
        ;;
    esac
  fi

  if command -v setpriv >/dev/null 2>&1; then
    if [ -n "$extra_groups" ]; then
      exec setpriv --reuid "${PUID:-10001}" --regid "${PGID:-10001}" --groups "$extra_groups" "$@"
    fi
    exec setpriv --reuid "${PUID:-10001}" --regid "${PGID:-10001}" --clear-groups "$@"
  fi

  exec gosu "${PUID:-10001}:${PGID:-10001}" "$@"
fi

exec "$@"
