import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface CapturedNotification {
  topic: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface FakeNtfy {
  url: string;
  requests: CapturedNotification[];
  failNext(count: number, status?: number, body?: string): void;
  close(): Promise<void>;
}

export async function startFakeNtfy(): Promise<FakeNtfy> {
  const requests: CapturedNotification[] = [];
  let failures: { remaining: number; status: number; body: string } | null = null;

  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    if (request.method !== 'POST') {
      response.writeHead(405).end();
      return;
    }
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const topic = decodeURIComponent((request.url ?? '/').replace(/^\//, ''));
      requests.push({ topic, headers: request.headers, body: Buffer.concat(chunks).toString('utf8') });

      if (failures && failures.remaining > 0) {
        failures.remaining -= 1;
        response.writeHead(failures.status, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ error: failures.body }));
        return;
      }
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ id: `fake-${requests.length}`, time: Math.floor(Date.now() / 1000) }));
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    failNext(count, status = 500, body = 'simulated ntfy failure') {
      failures = { remaining: count, status, body };
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
