# Scanner coverage and behaviour

DockSentinel bundles and orchestrates [Trivy](https://trivy.dev/) as its scanner. All vulnerability
intelligence, package detection and OS/package matching is Trivy's. DockSentinel never re-implements a
feed parser, package database, layer analyser or matching engine.

Tested scanner version: **Trivy 0.75.0** (pinned in the production image). The development test suite also
runs against a locally installed Trivy and its cached vulnerability database.

## Invocation

For each scan DockSentinel:

1. Streams `GET /images/{imageID}/get` from the Docker endpoint to a temporary `image.tar` (immutable
   image ID, never a tag).
2. Runs, without a shell:

```
trivy image --input <tmp>/image.tar \
  --format json --output <tmp>/report.json --quiet \
  --scanners vuln \
  --vuln-type <os|os,library> \
  --cache-dir <TRIVY_CACHE_DIR> \
  --timeout <profile timeout + 30s> \
  [--skip-java-db-update] [--skip-db-update]
```

3. Validates the exit code, the report size and the JSON structure, then records `trivy version -f json`
   output for the scanner version and database timestamp.
4. Removes the archive, report and scratch directory.

Trivy copies the `--input` argument into each result's `Target` field. DockSentinel runs Trivy with its
working directory set to the scratch directory and passes the archive by its relative filename, so targets
remain stable (`image.tar (alpine 3.13.5)`) across scans. Without this, every scan would embed a random
temporary path and finding identities would be recreated each time.

The child process receives a minimal environment: `PATH`, home/temp paths, locale, proxy variables and
`TRIVY_CACHE_DIR`. It never receives DockSentinel secrets or Docker credentials.

## Image identity and attribution

Docker's image ID and Trivy's reported `Metadata.ImageID` are not always the same digest. On
containerd-backed engines (including recent Docker Desktop), `/images/json` exposes the **manifest**
digest as the image ID, while `docker save` contains the **config** blob whose digest Trivy reports. Both
digests are immutable, but they differ.

DockSentinel therefore attributes findings to the exact image ID it asked Docker to export, and does not
compare it with Trivy's reported ID. The requested ID is immutable, so a tag moving during the scan cannot
change the result. One consequence: if two hosts use different image-store implementations, the same image
may appear under two IDs and be scanned twice rather than deduplicated. This is a deliberate trade-off;
changing the identity to a parsed config digest would require reading/unpacking every image archive.

## Profiles

| Profile | Trivy options | Coverage | Target timeout |
| --- | --- | --- | --- |
| Quick | `--vuln-type os`, `--skip-java-db-update` | Operating-system packages only | 5 minutes |
| Standard | `--vuln-type os,library` | OS packages **and** language/application packages | 15 minutes |

These are genuinely different scans, not cosmetic labels. Quick is suitable for frequent rescans of OS
packages; standard is the default first scan and the weekly/deep scan. Neither profile filters out
unfixed findings: `--ignore-unfixed` is deliberately not used, because fix availability is displayed and
used for prioritisation.

A hard ceiling (`SCAN_TIMEOUT_MS`, default 15 minutes) applies to every profile.

## Opt-in content scans

When enabled in Settings, an image drawer can queue a separate **content scan**. It never changes
vulnerability counts, image scan status or alerts. It uses the same exported archive and scratch directory:

```bash
trivy image --input image.tar --format json --output report-content.json --quiet \
  --scanners misconfig,secret \
  --image-config-scanners misconfig,secret \
  --cache-dir <TRIVY_CACHE_DIR> --timeout <10 minutes + 30s>
```

- **Misconfigurations** come from Dockerfile-converted image configuration and IaC files inside the image.
  Trivy itself notes that image content misconfiguration is rarely useful unless the image contains IaC
  files. This is not a host, daemon, Kubernetes-cluster or running-container audit.
- **Secrets** come from files inside image layers and the image config (for example environment variables).
  Only rule ID, category, title, path, line range and severity are stored. The raw `Match`, code lines and
  layer contents are discarded during parsing and are never written to SQLite, logs, API responses,
  notifications or tests. A secret scan can produce false positives and cannot prove an image is clean.
- Content scans are manual and opt-in (`misconfigScanEnabled`, `secretScanEnabled`, both default false).
  They use a separate `content_findings` lifecycle and UI page; failed/incomplete scans never resolve
  previous content findings. No content alert is sent.
- The first misconfiguration scan may download Trivy's checks bundle; offline deployments need a prepared
  Trivy cache. Secret scanning uses Trivy's built-in rules and allow rules.
- Content scans do not run the vulnerability DB update, so no vulnerability DB timestamp is recorded.

## What image scanning can detect here

- **Operating-system package vulnerabilities** for images Trivy recognises (Debian/Ubuntu, Alpine, Red Hat
  family, SUSE, Amazon Linux, Distroless, Chainguard, Wolfi, and others supported by Trivy).
- **Language/application dependency vulnerabilities** in the standard profile for ecosystems Trivy parses
  (npm/yarn/pnpm lockfiles, Python, PHP, Ruby, Go binaries/modules, Java archives/pom/gradle, .NET,
  Rust, and more). Detection depends on the files being present in the image and parseable.
- **Fix availability** as reported by the scanner's data sources.
- **CVE identifiers and references**, CVSS scores where the scanner provides them.

## What it does not detect

- **Runtime compromise, backdoors in memory, active attacks.** This is not an intrusion detection
  system or host security agent. A scanned image can be exploited at runtime through zero-days, logic
  flaws, weak credentials or live configuration.
- **Host/daemon/Kubernetes misconfigurations and runtime secrets.** The opt-in content scan only
  inspects the image config and files in the image. It does not inspect the running container, Docker
  daemon, host, cluster or mounted volumes. Secret findings can be false positives.
- **License compliance.** Trivy's license scanner is not enabled.
- **Host kernel, host packages, Docker daemon configuration.** DockSentinel scans images, not hosts.
- **Every dependency.** Statically linked code, vendored libraries without metadata, distroless/scratch
  images with no package metadata, proprietary binaries and build artifacts may be invisible to the
  scanner. No scanner can guarantee complete coverage.
- **Exploitability of a particular deployment.** KEV membership and published ports are signals, not
  proof.
- **Network exposure verification.** Published Docker ports are interpreted as potential exposure only.

These limitations are shown in the UI and in notification footers where the distinction matters.

## Failure semantics

| Condition | Result |
| --- | --- |
| Exit 0 + valid JSON + zero findings | Successful clean scan (qualified by profile/age in the UI) |
| Exit 0 + valid JSON + findings | Successful scan with findings |
| Exit 0 + empty/missing report | Failed — `invalid_output` |
| Malformed/truncated JSON | Failed — never treated as clean |
| Non-zero exit | Failed with exit code and a sanitized stderr tail |
| Timeout / cancellation | Failed (cancelled scans are marked cancelled) |
| Report above `SCAN_MAX_OUTPUT_BYTES` | Failed — `output_too_large` |
| Database download failure | Retried once with the cached DB and a warning; without a cache → `db_unavailable` |
| Scanner binary missing | Failed — `scanner_unavailable` |

Previous findings are preserved on failure. Only a successful scan can resolve findings. Failed scans are
retried according to the retry budget; the final failure is visible in scan activity and can alert.

## Vulnerability database

- Trivy maintains its own database cache under `TRIVY_CACHE_DIR` (default `DATA_DIR/trivy-cache`).
- Updates are attempted by Trivy at scan time; the cache persists across restarts and containers via the
  `/data` volume.
- The database timestamp is captured per scan. The UI warns when it is older than seven days and shows it
  in scan details.
- Vulnerability intelligence changes even when an image digest does not. This is why images are rescanned
  on schedule rather than only when their digest changes.

### Air-gapped / offline operation

1. Populate the cache on a connected machine with the same architecture, then copy it into the volume:

```bash
trivy --cache-dir ./trivy-cache image --download-db-only
# copy ./trivy-cache into the DockSentinel DATA_DIR as trivy-cache
```

2. Keep `TRIVY_CACHE_DIR` pointed at the populated directory.
3. Scans will still attempt a database update; when it fails, DockSentinel falls back to
   `--skip-db-update` once and records a warning. To avoid unnecessary outbound attempts you can block
   egress and rely on the fallback, or refresh the cache periodically out of band.
4. Disable the KEV feed in Settings if the CISA catalogue cannot be reached; findings will show
   `KEV unknown` rather than pretending exploitation data was checked.

## Performance notes

Each scan is a fresh Trivy process, which loads the vulnerability database (~250 MB on disk) per
invocation. That is acceptable for a home/small-lab host scanned on a daily/weekly cadence. For hosts with
hundreds of unique images, a Trivy client/server mode (one long-lived server holding the database) would
amortise startup and DB loading; it is not implemented in this MVP and would need its own orchestration and
security review.

## Adding another scanner

The boundary is intentionally small:

```ts
interface ScannerAdapter {
  readonly name: string;
  run(input: {
    archivePath;
    workDir;
    profile;
    mode?: 'vulnerability' | 'content';
    contentScanners?: { misconfig: boolean; secret: boolean };
    signal;
  }): Promise<ScannerRunResult>;
}
```

A new adapter must:

1. Keep its own CLI/API details local (no shell, explicit argument arrays, timeouts, caps).
2. Return normalised findings (`NormalizedFinding`) plus scanner name/version/database metadata and
   warnings.
3. Map failures onto the existing scanner error codes so retry and alert semantics stay consistent.

Only add a scanner when it covers a class of issue Trivy does not. Runtime monitoring is a different
product category and should not be squeezed into this adapter.
