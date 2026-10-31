# Unraid

DockSentinel runs on Unraid as an ordinary Docker container. The core product does not use any
Unraid-specific API; it talks to the standard Docker Engine over `/var/run/docker.sock` or a remote
endpoint.

## Install with the template

A Community Applications–ready template is provided at `templates/docksentinel.xml`; the repository also has
`ca_profile.xml` and `unraid-icon.png` for submission.

1. The template points at the public `ghcr.io/luriot/docksentinel:latest`, so no registry login is
   required.
2. Copy the template to the Unraid template directory, or add the container manually in the Docker tab:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/Luriot/DockSentinel/main/templates/docksentinel.xml \
     -o /boot/config/plugins/dockerMan/templates-user/docksentinel.xml
   ```

   Then use **Docker → Add Container → DockSentinel**.
3. The template creates:
   - `/data` → `/mnt/user/appdata/docksentinel`
   - `/var/run/docker.sock` → the host socket
   - Web UI on host port `8080` → container port `8080`. If 8080 is already used on your
     Unraid host, change **only the host side** in the container's port setting (for example
     `8090` → `8080`) before starting it.
4. Start the container and read the first-run setup token:

```bash
docker logs DockSentinel 2>&1 | grep -i "setup token"
```

5. Open `http://<unraid-ip>:<host-port>` (8080 unless you changed it), complete setup, then click
   **Use Docker on this computer**. If you prefer the manual form:
   - Kind: **Local Unix socket**
   - Address: `/var/run/docker.sock`

> Updating from a copy of this template resets customised values to the defaults here. For an
> existing install, edit the container once (see [Keeping settings across updates](#keeping-settings-across-updates))
> instead of re-adding it from the template.

## Community Applications listing

The app is **not automatically searchable in Community Apps** just because the image and template are public.
Community Apps is curated; the repository must pass the CA submission scan and manual review.

The repository is prepared for that submission:

- `ca_profile.xml` in the repository root
- `templates/docksentinel.xml` as the canonical Docker template
- `unraid-icon.png`
- public `ghcr.io/luriot/docksentinel:latest` image, MIT license, support/project links

To submit:

1. Make sure the repository is public and `templates/docksentinel.xml` is at the raw URL referenced by
   `<TemplateURL>`.
2. Sign in at <https://ca.unraid.net/submit/new> with your Unraid forum account.
3. Point the submission at `https://github.com/Luriot/DockSentinel`, run **Validate** and **Scan**, fix any
   reported template/metadata issues, then submit for review.
4. After approval, it becomes searchable in Community Apps. Review timing is controlled by Unraid.

Until it is approved, use the manual template install above. If CA asks for a forum support thread, create one
in the Unraid forums and replace the `<Support>` URL; GitHub Issues is valid for the repository itself but the
reviewer may require a forum thread.

## Socket permissions on Unraid

The image is self-contained for the local Docker socket: at startup it reads the GID that owns
`/var/run/docker.sock` and grants that group to the application process before dropping to
`PUID`/`PGID`. **You no longer need `--group-add` for a current image**, even if the container was
recreated from a template that predates this behaviour.

The template still passes `--group-add=281` (Unraid's usual Docker socket group) so that pinned
older image tags keep working; the auto-detection adds the real group when 281 is absent or
different. A stale template missing the parameter is therefore no longer a reason for discovery to
fail after an update.

> Keep the container's default entrypoint (it starts as root and drops to `PUID`/`PGID` itself). If
> you add `--user` to Extra Parameters, the detection cannot run; keep and set `--group-add` instead.

Verify what the running process got:

```bash
docker logs DockSentinel 2>&1 | grep "socket group"  # only when it had to add the group
docker exec DockSentinel id                          # groups= should include the socket GID
stat -c '%g' /var/run/docker.sock                    # host-side value to compare against
```

- If the socket GID is `0` (Docker Desktop arrangement), it is skipped on purpose: adding the root
  group would widen privileges. Use a socket proxy or set `PUID` appropriately.
- If you only use remote TLS endpoints, remove the socket mapping; nothing is detected and no
  group is added.
- Do not make the socket world-writable. Running the container as root (`PUID=0`) would also work but
  widens the blast radius and is not recommended. A read-only socket proxy is the better alternative;
  see the deployment guide.

If the appdata directory is not writable, set `PUID`/`PGID` to the owner of
`/mnt/user/appdata/docksentinel`; the entrypoint corrects ownership on `/data` at startup.

## Keeping settings across updates

A container update does **not** pull settings from the image. Unraid recreates the container from the
template saved locally in `/boot/config/plugins/dockerMan/templates-user/`. If that saved template is
old, the update silently reapplies its old port (`8080`) and its old Extra Parameters (possibly
without the socket group). That is the loop described by “every update resets my port and my
`--group-add`”.

Fix the **saved local template once**:

1. **Docker** tab → DockSentinel → **Edit**.
2. Set the Web UI **host** port to the one you want (for example `8090`). Keep the container side
   `8080`.
3. For a current image, Extra Parameters can stay as they are; `--group-add=281` is optional now.
   For a pinned older image, keep `--group-add=<socket-gid>` (use the value from
   `stat -c '%g' /var/run/docker.sock`).
4. Click **Apply**. This writes the values into the local template.
5. Back up the resulting XML:

   ```bash
   ls /boot/config/plugins/dockerMan/templates-user/ | grep -i dock
   cp /boot/config/plugins/dockerMan/templates-user/<that-file>.xml /boot/config/docksentinel-template-backup.xml
   ```

Then update in place:

- **Docker tab → Update** (or the container's “Check for Updates” → Update) recreates it from the
  saved template, so your host port and parameters survive.
- Do **not** use **Remove** + **Add Container** from Community Applications, and do not re-apply the
  repository template just to update: both reset the values to the defaults in
  `templates/docksentinel.xml` (host `8080`, `--group-add=281`).
- The DockSentinel **System status → Check for updates** button is informational. It does not recreate
  the container; follow your platform's update path.
- If you maintain a **custom local template** with a different name, Community Applications will not
  overwrite it; use it for the container and update from the Docker tab.

If you prefer Compose on Unraid, keep `WEBUI_PORT` in a persistent `.env` next to
`docker-compose.yml` (`docker compose pull && docker compose up -d`); the compose file no longer
needs `group_add` and will not reset the port while that `.env` exists.

## Updates

- The template uses `ghcr.io/luriot/docksentinel:latest`. Prefer pinning a version tag (create one with
  `git tag v0.1.0 && git push origin v0.1.0`) and update deliberately.
- Schema migrations run automatically on start. Back up `/data` first.
- The Trivy cache and `/data` survive container updates; the host port and Extra Parameters survive
  only if the saved local template is current, as described above.

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
