import { createHash } from 'node:crypto';
import { createTar, type TarEntry } from './tar.ts';

export interface SyntheticImage {
  /** docker-save archive usable with `trivy image --input`. */
  archive: Buffer;
  /** sha256 of the config blob; this is what Docker reports as the image ID and what Trivy reports in Metadata.ImageID. */
  imageId: string;
  repositoryTag: string;
  sizeBytes: number;
}

const VULNERABLE_STATUS = `Package: libssl1.1
Status: install ok installed
Priority: optional
Section: libs
Architecture: amd64
Version: 1.1.1k-1+deb11u1
Description: Secure Sockets Layer toolkit - shared libraries

Package: zlib1g
Status: install ok installed
Priority: optional
Section: libs
Architecture: amd64
Version: 1:1.2.11.dfsg-2+deb11u1
Description: compression library - runtime

Package: bash
Status: install ok installed
Priority: required
Section: shells
Architecture: amd64
Version: 5.1-2+deb11u1
Description: GNU Bourne Again SHell

Package: libc6
Status: install ok installed
Priority: required
Section: libs
Architecture: amd64
Version: 2.31-13+deb11u5
Description: GNU C Library: Shared libraries

Package: curl
Status: install ok installed
Priority: optional
Section: web
Architecture: amd64
Version: 7.74.0-1.3+deb11u3
Description: command line tool for transferring data with URL syntax
`;

export interface SyntheticImageOptions {
  tag?: string;
  /** Add extra layer content, e.g. an application dependency file. */
  extraEntries?: TarEntry[];
  /** Set to false to produce an image with no known-vulnerable packages. */
  vulnerable?: boolean;
}

/**
 * Builds a tiny Debian 11 docker-save archive with deliberately outdated packages so the real
 * Trivy binary can be exercised without a Docker daemon.
 */
export function buildSyntheticImage(options: SyntheticImageOptions = {}): SyntheticImage {
  const tag = options.tag ?? 'docksentinel-test:1';
  const status = options.vulnerable === false ? '' : VULNERABLE_STATUS;
  const layerEntries: TarEntry[] = [
    { name: 'etc', type: 'directory' },
    {
      name: 'etc/os-release',
      content:
        'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nNAME="Debian GNU/Linux"\nVERSION_ID="11"\nVERSION="11 (bullseye)"\nVERSION_CODENAME=bullseye\nID=debian\n',
    },
    { name: 'etc/debian_version', content: '11.7\n' },
    { name: 'var', type: 'directory' },
    { name: 'var/lib', type: 'directory' },
    { name: 'var/lib/dpkg', type: 'directory' },
    { name: 'var/lib/dpkg/status', content: status },
    ...(options.extraEntries ?? []),
  ];
  const layerTar = createTar(layerEntries);
  const diffId = createHash('sha256').update(layerTar).digest('hex');

  const config = {
    architecture: 'amd64',
    os: 'linux',
    config: { Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'] },
    rootfs: { type: 'layers', diff_ids: [`sha256:${diffId}`] },
    history: [{ created: '2025-01-01T00:00:00Z', created_by: 'docksentinel synthetic test image' }],
  };
  const configBuffer = Buffer.from(JSON.stringify(config), 'utf8');
  const imageId = `sha256:${createHash('sha256').update(configBuffer).digest('hex')}`;
  const layerName = `${diffId}.tar`;
  const manifest = [
    {
      Config: 'config.json',
      RepoTags: [tag],
      Layers: [layerName],
    },
  ];

  const archive = createTar([
    { name: 'manifest.json', content: JSON.stringify(manifest) },
    { name: 'config.json', content: configBuffer },
    { name: layerName, content: layerTar },
  ]);

  return {
    archive,
    imageId,
    repositoryTag: tag,
    sizeBytes: layerTar.length,
  };
}
