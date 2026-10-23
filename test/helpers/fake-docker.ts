import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface FakeDockerContainer {
  id: string;
  name: string;
  image: string;
  imageId: string;
  state: string;
  ports?: { IP?: string; PrivatePort?: number; PublicPort?: number; Type?: string }[];
  labels?: Record<string, string>;
  networkMode?: string;
  created?: number;
}

export interface FakeDockerImage {
  id: string;
  repoTags: string[];
  repoDigests: string[];
  created?: number;
  size?: number;
}

export interface FakeDockerOptions {
  containers?: FakeDockerContainer[];
  images?: FakeDockerImage[];
  /** Image archives keyed by image ID, served by GET /images/{id}/get. */
  archives?: Map<string, Buffer>;
  /** Force specific endpoints to fail, keyed by path suffix (e.g. "/images/json"). */
  failures?: Map<string, { status: number; body?: string }>;
  /** Bind address; use 0.0.0.0 for a container/host smoke test. Defaults to loopback. */
  host?: string;
}

export interface FakeDocker {
  host: string;
  port: number;
  url: string;
  requests: { method: string; path: string }[];
  setFailure(pathSuffix: string, failure: { status: number; body?: string } | null): void;
  close(): Promise<void>;
}

const IMAGE_TO_CONTAINER = (container: FakeDockerContainer): Record<string, unknown> => ({
  Id: container.id,
  Names: [`/${container.name}`],
  Image: container.image,
  ImageID: container.imageId,
  Command: 'php-fpm',
  Created: container.created ?? 1710000000,
  Ports: container.ports ?? [],
  Labels: container.labels ?? {},
  State: container.state,
  Status: container.state === 'running' ? 'Up 3 hours' : 'Exited (0) 2 hours ago',
  HostConfig: { NetworkMode: container.networkMode ?? 'bridge' },
});

const IMAGE_TO_DOCKER = (image: FakeDockerImage): Record<string, unknown> => ({
  Id: image.id,
  RepoTags: image.repoTags,
  RepoDigests: image.repoDigests,
  Created: image.created ?? 1710000000,
  Size: image.size ?? 12345,
  Labels: {},
  ParentId: '',
});

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  response.end(payload);
}

export async function startFakeDocker(options: FakeDockerOptions = {}): Promise<FakeDocker> {
  const containers = [...(options.containers ?? [])];
  const images = [...(options.images ?? [])];
  const archives = options.archives ?? new Map<string, Buffer>();
  const failures = options.failures ?? new Map<string, { status: number; body?: string }>();
  const requests: { method: string; path: string }[] = [];

  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const method = request.method ?? 'GET';
    const rawUrl = request.url ?? '/';
    requests.push({ method, path: rawUrl });

    const withoutVersion = rawUrl.replace(/^\/v\d+\.\d+/, '');
    const path = withoutVersion.split('?')[0] ?? '/';

    for (const [suffix, failure] of failures) {
      if (path.endsWith(suffix)) {
        sendJson(response, failure.status, { message: failure.body ?? `Forced failure ${failure.status}` });
        return;
      }
    }

    if (method !== 'GET') {
      sendJson(response, 405, { message: 'DockSentinel never performs mutating Docker API calls' });
      return;
    }

    if (path === '/_ping') {
      response.writeHead(200, { 'Content-Type': 'text/plain', 'Api-Version': '1.44' });
      response.end('OK');
      return;
    }
    if (path === '/version') {
      sendJson(response, 200, { Version: '25.0.9', ApiVersion: '1.44', Os: 'linux', Arch: 'amd64' });
      return;
    }
    if (path === '/containers/json') {
      sendJson(response, 200, containers.map(IMAGE_TO_CONTAINER));
      return;
    }
    if (path === '/images/json') {
      sendJson(response, 200, images.map(IMAGE_TO_DOCKER));
      return;
    }
    if (path.startsWith('/images/') && path.endsWith('/get')) {
      const encoded = path.slice('/images/'.length, -'/get'.length);
      const imageId = decodeURIComponent(encoded);
      const archive = archives.get(imageId);
      if (!archive) {
        sendJson(response, 404, { message: `No such image: ${imageId}` });
        return;
      }
      response.writeHead(200, { 'Content-Type': 'application/x-tar', 'Content-Length': archive.length });
      response.end(archive);
      return;
    }
    sendJson(response, 404, { message: `Unsupported fixture endpoint: ${method} ${path}` });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, options.host ?? '127.0.0.1', () => resolve());
  });
  const address = server.address() as AddressInfo;

  return {
    host: options.host ?? '127.0.0.1',
    port: address.port,
    url: `http://${options.host === '0.0.0.0' ? '127.0.0.1' : (options.host ?? '127.0.0.1')}:${address.port}`,
    requests,
    setFailure(pathSuffix, failure) {
      if (failure) failures.set(pathSuffix, failure);
      else failures.delete(pathSuffix);
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export function containerFixture(overrides: Partial<FakeDockerContainer> & { id: string; imageId: string }): FakeDockerContainer {
  return {
    name: 'php-app',
    image: 'docksentinel-test:1',
    state: 'running',
    ports: [],
    labels: {},
    ...overrides,
  };
}
