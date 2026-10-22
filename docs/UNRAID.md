# Unraid

DockSentinel runs on Unraid as an ordinary Docker container. The core product does not use any
Unraid-specific API; it talks to the standard Docker Engine over `/var/run/docker.sock` or a remote
endpoint.

## Install with the template

A Community Applications–style template is provided at `unraid/docksentinel.xml`.

1. The template points at `ghcr.io/luriot/docksentinel:latest`. The GHCR package is currently private:
   make it public in the package settings, or authenticate Unraid's Docker daemon to GHCR with a token
   that has `read:packages`.
2. Copy the XML to `/boot/config/plugins/dockerMan/templates-user/docksentinel.xml` on the Unraid server,
   or add the container manually in the Docker tab using the same settings.
3. The template creates:
   - `/data` → `/mnt/user/appdata/docksentinel`
   - `/var/run/docker.sock` → the host socket
   - Web UI on port `8080`
4. Start the container and read the first-run setup token:

```bash
docker logs docksentinel 2>&1 | grep -i "setup token"
```

5. Open `http://<unraid-ip>:8080`, complete setup, then add an environment:
   - Kind: **Local Unix socket**
   - Address: `/var/run/docker.sock`

## Socket permissions on Unraid

By default the template runs the application as `PUID=99` / `PGID=100` (Unraid's `nobody:users`). Whether
that can read the Docker socket depends on the socket's group:

```bash
stat -c '%g' /var/run/docker.sock
```

- If the group matches `PGID`, discovery works.
- Otherwise add the socket group with an extra parameter in the template (or the container's
  **Extra Parameters** field in the Unraid UI):

```
--group-add=<socket-gid>
```

After changing the parameter, restart the container and run **Test connection** for the environment.

Do not work around permission errors by making the socket world-writable. Running the container as root
(`PUID=0`) would also grant access, but it widens the blast radius and is not recommended. A read-only
socket proxy is a better alternative; see the deployment guide.

If the appdata directory is not writable, set `PUID`/`PGID` to the owner of
`/mnt/user/appdata/docksentinel`; the entrypoint corrects ownership on `/data` at startup.

## Updates

- The template uses `ghcr.io/luriot/docksentinel:latest`. Prefer pinning a version tag (create one with
  `git tag v0.1.0 && git push origin v0.1.0`) for reproducible upgrades.
- Updating the container image runs schema migrations automatically on start. Back up `/data` first.
- The Trivy cache lives in the appdata directory and persists updates across container restarts.

## Backups

Appdata contains the database, encryption key and scanner cache. Back up the whole folder or use the
built-in snapshot script:

```bash
docker exec docksentinel node scripts/backup.ts
```

Restore by stopping the container, replacing `docksentinel.db` and `secret.key` from the same backup, and
starting it again. See [Deployment](DEPLOYMENT.md#restore).

## Unraid-specific notes

- **Unraid is not required.** The template is a convenience; any Docker host works.
- **Remote endpoints:** to monitor a second Docker host, add it in the UI as a TLS endpoint (for example
  `host:2376` with client certificates). Do not use an unauthenticated TCP API.
- **Do not enable Privileged.** DockSentinel does not need it.
- **Resource limits:** large images are temporarily exported under `/data/tmp`; monitor the appdata disk.
  Lower `MAX_IMAGE_EXPORT_BYTES` if necessary.
- **Unraid's own containers** are scanned like any other Docker workload. The product only reads container
  metadata and never modifies containers.
