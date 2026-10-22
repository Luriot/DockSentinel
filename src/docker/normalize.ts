import type { DockerContainerInfo, DockerImageInfo, DockerPort } from '../docker/client.ts';
import { classifyExposure, type ExposureState } from '../domain/exposure.ts';
import { filterDocksentinelLabels } from '../domain/labels.ts';

export interface NormalizedPort {
  ip: string | null;
  privatePort: number | null;
  publicPort: number | null;
  type: string | null;
}

export interface NormalizedContainer {
  id: string;
  name: string;
  imageRef: string;
  imageId: string | null;
  state: string;
  labels: Record<string, string>;
  ports: NormalizedPort[];
  networkMode: string | null;
  createdTs: string | null;
  exposureState: ExposureState;
  exposureReason: string;
}

export interface NormalizedImage {
  imageId: string;
  repoDigests: string[];
  repoTags: string[];
  sizeBytes: number | null;
  createdTs: string | null;
}

export function normalizePorts(ports: DockerPort[] | undefined): NormalizedPort[] {
  if (!Array.isArray(ports)) return [];
  return ports
    .filter((port) => port && typeof port === 'object')
    .slice(0, 200)
    .map((port) => ({
      ip: typeof port.IP === 'string' ? port.IP.slice(0, 64) : null,
      privatePort: typeof port.PrivatePort === 'number' ? port.PrivatePort : null,
      publicPort: typeof port.PublicPort === 'number' ? port.PublicPort : null,
      type: typeof port.Type === 'string' ? port.Type.slice(0, 12) : null,
    }));
}

export function normalizeContainer(raw: DockerContainerInfo): NormalizedContainer | null {
  if (!raw || typeof raw.Id !== 'string' || raw.Id.length === 0) return null;
  const labels = filterDocksentinelLabels(raw.Labels);
  const ports = normalizePorts(raw.Ports);
  const state = typeof raw.State === 'string' ? raw.State : 'unknown';
  const name = (raw.Names ?? [])
    .map((value) => value.replace(/^\//, ''))
    .find((value) => value.length > 0) ?? raw.Id.slice(0, 12);
  const exposure = classifyExposure({
    state,
    ports,
    networkMode: raw.HostConfig?.NetworkMode ?? null,
    labels,
  });

  return {
    id: raw.Id.slice(0, 128),
    name: name.slice(0, 200),
    imageRef: (typeof raw.Image === 'string' ? raw.Image : '').slice(0, 300) || 'unknown',
    imageId: normalizeImageId(raw.ImageID),
    state: state.slice(0, 32),
    labels,
    ports,
    networkMode: raw.HostConfig?.NetworkMode ? String(raw.HostConfig.NetworkMode).slice(0, 64) : null,
    createdTs: typeof raw.Created === 'number' ? new Date(raw.Created * 1000).toISOString() : null,
    exposureState: exposure.state,
    exposureReason: exposure.reasons.join('; '),
  };
}

/** Accepts only sha256 image IDs; anything else is discarded rather than guessed. */
export function normalizeImageId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return /^sha256:[a-f0-9]{64}$/.test(trimmed) ? trimmed : null;
}

export function normalizeImage(raw: DockerImageInfo): NormalizedImage | null {
  const imageId = normalizeImageId(raw?.Id);
  if (!imageId) return null;
  const repoTags = (Array.isArray(raw.RepoTags) ? raw.RepoTags : [])
    .filter((tag): tag is string => typeof tag === 'string' && tag !== '<none>:<none>')
    .slice(0, 50);
  const repoDigests = (Array.isArray(raw.RepoDigests) ? raw.RepoDigests : [])
    .filter((digest): digest is string => typeof digest === 'string' && digest.includes('@sha256:'))
    .slice(0, 50);
  return {
    imageId,
    repoDigests,
    repoTags,
    sizeBytes: typeof raw.Size === 'number' && raw.Size >= 0 ? raw.Size : null,
    createdTs: typeof raw.Created === 'number' ? new Date(raw.Created * 1000).toISOString() : null,
  };
}
