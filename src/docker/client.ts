import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { IncomingHttpHeaders, OutgoingHttpHeaders } from 'node:http';
import { isIP } from 'node:net';
import { createWriteStream } from 'node:fs';

export type DockerErrorCode =
  | 'misconfigured'
  | 'unreachable'
  | 'timeout'
  | 'http_error'
  | 'invalid_response'
  | 'response_too_large'
  | 'unsupported_address';

export class DockerError extends Error {
  readonly code: DockerErrorCode;
  readonly statusCode: number | null;

  constructor(code: DockerErrorCode, message: string, statusCode: number | null = null) {
    super(message);
    this.name = 'DockerError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export interface DockerConnection {
  kind: 'unix' | 'tcp' | 'tls';
  /** Absolute socket path for unix, host:port for tcp/tls. */
  address: string;
  tlsCa?: string | null;
  tlsCert?: string | null;
  tlsKey?: string | null;
  skipVerify?: boolean;
}

export interface DockerPort {
  IP?: string;
  PrivatePort?: number;
  PublicPort?: number;
  Type?: string;
}

export interface DockerContainerInfo {
  Id: string;
  Names?: string[];
  Image?: string;
  ImageID?: string;
  Created?: number;
  Ports?: DockerPort[];
  Labels?: Record<string, string>;
  State?: string;
  Status?: string;
  HostConfig?: { NetworkMode?: string };
}

export interface DockerImageInfo {
  Id: string;
  RepoTags?: string[] | null;
  RepoDigests?: string[] | null;
  Created?: number;
  Size?: number;
}

export interface DockerVersionInfo {
  Version?: string;
  ApiVersion?: string;
  Os?: string;
  Arch?: string;
}

const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;

interface ParsedTarget {
  socketPath?: string;
  hostname?: string;
  port?: number;
}

/**
 * Parses a user-supplied endpoint address into a transport target. Only the schemes DockSentinel
 * supports are accepted; anything else is rejected before a connection is attempted.
 */
export function parseAddress(connection: DockerConnection): ParsedTarget {
  const address = connection.address.trim();
  if (!address) throw new DockerError('misconfigured', 'Endpoint address is empty');

  if (connection.kind === 'unix') {
    if (!address.startsWith('/')) {
      throw new DockerError('unsupported_address', 'Unix socket addresses must be absolute paths (e.g. /var/run/docker.sock)');
    }
    if (address.includes('\n') || address.includes('\r') || address.includes('\0')) {
      throw new DockerError('unsupported_address', 'Unix socket address contains invalid characters');
    }
    return { socketPath: address };
  }

  let parsed: URL;
  try {
    parsed = new URL(`tcp://${address}`);
  } catch {
    throw new DockerError('unsupported_address', 'TCP address must be in host:port form');
  }
  if (!parsed.hostname || !parsed.port) {
    throw new DockerError('unsupported_address', 'TCP address must include an explicit port (e.g. 10.0.0.5:2376)');
  }
  if ((parsed.pathname !== '' && parsed.pathname !== '/') || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new DockerError('unsupported_address', 'TCP address must be a bare host:port');
  }
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new DockerError('unsupported_address', 'TCP address has an invalid port');
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!isIP(hostname) && !/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/.test(hostname)) {
    throw new DockerError('unsupported_address', 'TCP address has an invalid hostname');
  }
  return { hostname, port };
}

function sanitizeMessage(body: string): string {
  return body.replace(/\s+/g, ' ').trim().slice(0, 400);
}

function buildRequestOptions(
  connection: DockerConnection,
  path: string,
  signal?: AbortSignal,
): { useTls: boolean; options: import('node:https').RequestOptions } {
  const target = parseAddress(connection);
  const useTls = connection.kind === 'tls';
  const headers: OutgoingHttpHeaders = { Accept: 'application/json', Host: 'docker' };
  return {
    useTls,
    options: {
      method: 'GET',
      path,
      headers,
      signal,
      ...(target.socketPath ? { socketPath: target.socketPath } : { hostname: target.hostname, port: target.port }),
      ...(useTls
        ? {
            ca: connection.tlsCa || undefined,
            cert: connection.tlsCert || undefined,
            key: connection.tlsKey || undefined,
            rejectUnauthorized: !connection.skipVerify,
            servername: target.hostname,
          }
        : {}),
    },
  };
}

function requestDocker(
  connection: DockerConnection,
  path: string,
  maxBytes = MAX_RESPONSE_BYTES,
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  const { useTls, options } = buildRequestOptions(connection, path);

  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    options.signal = controller.signal;

    const req = (useTls ? httpsRequest : httpRequest)(options, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxBytes) {
          controller.abort();
          reject(new DockerError('response_too_large', 'Docker API response exceeded the size limit'));
          res.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        clearTimeout(timer);
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
      res.on('error', (error) => {
        clearTimeout(timer);
        reject(new DockerError('unreachable', `Docker API response failed: ${error.message}`));
      });
    });

    req.on('error', (error) => {
      clearTimeout(timer);
      if (controller.signal.aborted) {
        reject(new DockerError('timeout', `Docker API request timed out after ${REQUEST_TIMEOUT_MS}ms`));
      } else if (error && typeof error === 'object' && 'code' in error && /CERT|TLS|SSL/i.test(String(error.code))) {
        reject(new DockerError('unreachable', `TLS connection failed: ${error.message}`));
      } else {
        reject(new DockerError('unreachable', `Docker API unreachable: ${error.message}`));
      }
    });

    req.end();
  });
}

function parseJson<T>(body: string, what: string): T {
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new DockerError('invalid_response', `Docker API returned invalid JSON for ${what}`);
  }
}

export class DockerClient {
  private readonly connection: DockerConnection;

  constructor(connection: DockerConnection) {
    this.connection = connection;
  }

  async version(): Promise<DockerVersionInfo> {
    const response = await requestDocker(this.connection, '/version');
    if (response.status !== 200) {
      throw new DockerError('http_error', `Docker /version returned HTTP ${response.status}: ${sanitizeMessage(response.body)}`, response.status);
    }
    return parseJson<DockerVersionInfo>(response.body, '/version');
  }

  async ping(): Promise<void> {
    const response = await requestDocker(this.connection, '/_ping', 4096);
    if (response.status !== 200 || !response.body.trim().startsWith('OK')) {
      throw new DockerError('http_error', `Docker ping failed with HTTP ${response.status}`, response.status);
    }
  }

  async listContainers(): Promise<DockerContainerInfo[]> {
    const response = await requestDocker(this.connection, '/containers/json?all=1');
    if (response.status !== 200) {
      throw new DockerError('http_error', `Docker container list returned HTTP ${response.status}: ${sanitizeMessage(response.body)}`, response.status);
    }
    const parsed = parseJson<unknown>(response.body, 'container list');
    if (!Array.isArray(parsed)) throw new DockerError('invalid_response', 'Docker container list was not an array');
    return parsed as DockerContainerInfo[];
  }

  async listImages(): Promise<DockerImageInfo[]> {
    const response = await requestDocker(this.connection, '/images/json');
    if (response.status !== 200) {
      throw new DockerError('http_error', `Docker image list returned HTTP ${response.status}: ${sanitizeMessage(response.body)}`, response.status);
    }
    const parsed = parseJson<unknown>(response.body, 'image list');
    if (!Array.isArray(parsed)) throw new DockerError('invalid_response', 'Docker image list was not an array');
    return parsed as DockerImageInfo[];
  }

  /**
   * Streams a docker-save archive of an image, addressed by its immutable image ID. Using the ID
   * (never a tag) guarantees that findings can never be attributed to an image that was replaced
   * between discovery and scan.
   */
  async exportImage(
    imageId: string,
    destination: string,
    options: { maxBytes: number; timeoutMs: number; signal?: AbortSignal },
  ): Promise<{ bytes: number }> {
    if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) {
      throw new DockerError('misconfigured', 'Refusing to export an image without a valid immutable image ID');
    }
    const { useTls, options: requestOptions } = buildRequestOptions(
      this.connection,
      `/images/${encodeURIComponent(imageId)}/get`,
    );

    return new Promise((resolve, reject) => {
      let settled = false;
      let bytes = 0;
      const controller = new AbortController();
      if (options.signal) {
        if (options.signal.aborted) {
          reject(new DockerError('unreachable', 'Image export cancelled'));
          return;
        }
        options.signal.addEventListener('abort', () => controller.abort(), { once: true });
      }
      requestOptions.signal = controller.signal;
      const timer = setTimeout(() => controller.abort(), options.timeoutMs);

      const fail = (error: DockerError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      };

      const req = (useTls ? httpsRequest : httpRequest)(requestOptions, (res) => {
        if (res.statusCode !== 200) {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => {
            if (chunks.length < 8) chunks.push(chunk);
          });
          res.on('end', () =>
            fail(
              new DockerError(
                'http_error',
                `Docker image export returned HTTP ${res.statusCode}: ${sanitizeMessage(Buffer.concat(chunks).toString('utf8'))}`,
                res.statusCode ?? null,
              ),
            ),
          );
          return;
        }

        const out = createWriteStream(destination, { mode: 0o600 });
        res.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > options.maxBytes) {
            controller.abort();
            res.destroy();
            out.destroy();
            fail(
              new DockerError(
                'response_too_large',
                `Image archive exceeded the ${Math.round(options.maxBytes / (1024 * 1024))} MiB export limit`,
              ),
            );
          }
        });
        res.on('error', (error) => fail(new DockerError('unreachable', `Image export failed: ${error.message}`)));
        out.on('error', (error) => {
          controller.abort();
          fail(new DockerError('unreachable', `Unable to write image archive: ${error.message}`));
        });
        out.on('finish', () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve({ bytes });
        });
        res.pipe(out);
      });

      req.on('error', (error) => {
        if (controller.signal.aborted) {
          fail(new DockerError('timeout', 'Image export timed out or was cancelled'));
        } else {
          fail(new DockerError('unreachable', `Image export request failed: ${error.message}`));
        }
      });
      req.end();
    });
  }
}
