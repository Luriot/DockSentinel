import type { Db } from './db/index.ts';
import { DockerClient, DockerError, type DockerVersionInfo } from './docker/client.ts';
import { normalizeContainer, normalizeImage, type NormalizedContainer, type NormalizedImage } from './docker/normalize.ts';
import {
  ensureImageFromContainer,
  replaceImageLocations,
  syncContainers,
  upsertImage,
} from './repo/images.ts';
import { setEnvironmentStatus, toDockerConnection, type EnvironmentRecord } from './repo/environments.ts';
import type { Logger } from './logger.ts';
import { nowIso } from './util/time.ts';

export interface DiscoverySummary {
  environmentId: number;
  environmentName: string;
  containers: number;
  images: number;
  warnings: string[];
  dockerVersion: DockerVersionInfo | null;
  durationMs: number;
}

export interface ConnectionTestResult {
  ok: boolean;
  version: DockerVersionInfo | null;
  containers: number;
  images: number;
  message: string;
  durationMs: number;
}

function describeError(error: unknown): string {
  if (error instanceof DockerError) return `${error.code}: ${error.message}`;
  if (error instanceof Error) return error.message;
  return 'Unknown error';
}

export class DiscoveryService {
  private readonly db: Db;
  private readonly secretKey: Buffer;
  private readonly log: Logger;

  constructor(db: Db, secretKey: Buffer, log: Logger) {
    this.db = db;
    this.secretKey = secretKey;
    this.log = log;
  }

  async discover(environment: EnvironmentRecord): Promise<DiscoverySummary> {
    const started = Date.now();
    const startedAt = nowIso();
    let client: DockerClient;
    try {
      client = new DockerClient(toDockerConnection(environment, this.secretKey));
    } catch (error) {
      const message = describeError(error);
      setEnvironmentStatus(this.db, environment.id, 'offline', message);
      throw new Error(`Environment "${environment.name}" is misconfigured: ${message}`);
    }

    try {
      const version = await client.version();
      const rawContainers = await client.listContainers();
      const containers = rawContainers
        .map((entry) => normalizeContainer(entry))
        .filter((entry): entry is NormalizedContainer => entry !== null);

      let rawImages: Awaited<ReturnType<DockerClient['listImages']>> = [];
      const warnings: string[] = [];
      let imagesOk = true;
      try {
        rawImages = await client.listImages();
      } catch (error) {
        imagesOk = false;
        warnings.push(`Image inventory incomplete: ${describeError(error)}`);
        this.log.warn({ environmentId: environment.id, err: describeError(error) }, 'image list failed');
      }

      const images = rawImages
        .map((entry) => normalizeImage(entry))
        .filter((entry): entry is NormalizedImage => entry !== null);

      const summary = this.db.transaction(() => {
        const now = startedAt;
        for (const image of images) upsertImage(this.db, image, now, imagesOk);

        const knownImages = new Set(images.map((image) => image.imageId));
        const extraImages: NormalizedImage[] = [];
        for (const container of containers) {
          if (!container.imageId || knownImages.has(container.imageId)) continue;
          knownImages.add(container.imageId);
          ensureImageFromContainer(this.db, container.imageId, now);
          extraImages.push({
            imageId: container.imageId,
            repoDigests: [],
            repoTags: container.imageRef.includes('@sha256:') ? [] : [container.imageRef],
            sizeBytes: null,
            createdTs: null,
          });
        }

        if (imagesOk) {
          replaceImageLocations(this.db, environment.id, now, images);
        }
        for (const image of [...images, ...extraImages]) {
          if (image.repoDigests.length === 0 && image.repoTags.length === 0) {
            this.db.run(
              `INSERT OR IGNORE INTO image_locations (image_id, environment_id, reference, tag, last_seen_at)
               VALUES (?, ?, ?, NULL, ?)`,
              [image.imageId, environment.id, image.imageId, now],
            );
          }
        }
        for (const container of containers) {
          if (!container.imageId) continue;
          this.db.run(
            `INSERT OR IGNORE INTO image_locations (image_id, environment_id, reference, tag, last_seen_at)
             VALUES (?, ?, ?, ?, ?)`,
            [
              container.imageId,
              environment.id,
              container.imageRef,
              container.imageRef.includes('@sha256:') ? null : container.imageRef,
              now,
            ],
          );
        }

        const synced = syncContainers(this.db, environment.id, containers, startedAt);
        setEnvironmentStatus(this.db, environment.id, 'online', warnings[0] ?? null, {
          contact: true,
          discovered: true,
        });
        return synced;
      });

      this.log.info(
        {
          environmentId: environment.id,
          containers: containers.length,
          images: images.length,
          inserted: summary.inserted,
          updated: summary.updated,
        },
        'discovery completed',
      );

      return {
        environmentId: environment.id,
        environmentName: environment.name,
        containers: containers.length,
        images: images.length,
        warnings,
        dockerVersion: version,
        durationMs: Date.now() - started,
      };
    } catch (error) {
      const message = describeError(error);
      setEnvironmentStatus(this.db, environment.id, 'offline', message);
      this.log.warn({ environmentId: environment.id, error: message }, 'discovery failed');
      throw new Error(`Environment "${environment.name}" is unavailable: ${message}`);
    }
  }

  /** Connectivity check used by the UI. It never writes inventory, only the endpoint status. */
  async test(environment: EnvironmentRecord): Promise<ConnectionTestResult> {
    const started = Date.now();
    try {
      const client = new DockerClient(toDockerConnection(environment, this.secretKey));
      const [version, containers, images] = await Promise.all([
        client.version(),
        client.listContainers(),
        client.listImages(),
      ]);
      setEnvironmentStatus(this.db, environment.id, 'online', null, { contact: true });
      return {
        ok: true,
        version,
        containers: containers.length,
        images: images.length,
        message: `Connected to Docker ${version.Version ?? 'unknown'} (API ${version.ApiVersion ?? 'unknown'})`,
        durationMs: Date.now() - started,
      };
    } catch (error) {
      const message = describeError(error);
      setEnvironmentStatus(this.db, environment.id, 'offline', message);
      return {
        ok: false,
        version: null,
        containers: 0,
        images: 0,
        message,
        durationMs: Date.now() - started,
      };
    }
  }
}
