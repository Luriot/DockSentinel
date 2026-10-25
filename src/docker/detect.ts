import { DockerClient, type DockerConnection, type DockerVersionInfo } from './client.ts';

export interface LocalDockerCandidate {
  label: string;
  kind: DockerConnection['kind'];
  address: string;
}

export interface ProbedDockerCandidate extends LocalDockerCandidate {
  available: boolean;
  version: DockerVersionInfo | null;
  error: string | null;
}

/** Common local Docker endpoints, ordered so the most likely one is probed first. */
export function localDockerCandidates(platform: NodeJS.Platform = process.platform): LocalDockerCandidate[] {
  const candidates: LocalDockerCandidate[] = [];
  const fromEnv = process.env.DOCKER_HOST?.trim();
  if (fromEnv) {
    if (fromEnv.startsWith('unix://')) {
      candidates.push({ label: 'Docker (DOCKER_HOST)', kind: 'unix', address: fromEnv.slice('unix://'.length) });
    } else if (fromEnv.startsWith('npipe://')) {
      const address = fromEnv.slice('npipe://'.length).replace(/^\/+/, '//');
      candidates.push({ label: 'Docker (DOCKER_HOST)', kind: 'unix', address });
    } else if (fromEnv.startsWith('tcp://')) {
      candidates.push({ label: 'Docker (DOCKER_HOST)', kind: 'tcp', address: fromEnv.slice('tcp://'.length) });
    }
  }
  if (platform === 'win32') {
    candidates.push(
      { label: 'Docker Desktop', kind: 'unix', address: '//./pipe/dockerDesktopLinuxEngine' },
      { label: 'Docker Desktop', kind: 'unix', address: '//./pipe/docker_engine' },
    );
  } else {
    candidates.push({ label: 'Local Docker', kind: 'unix', address: '/var/run/docker.sock' });
  }
  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    const key = `${candidate.kind}\u0000${candidate.address}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function probeDockerCandidate(candidate: LocalDockerCandidate): Promise<ProbedDockerCandidate> {
  try {
    const client = new DockerClient({ kind: candidate.kind, address: candidate.address });
    await client.ping();
    const version = await client.version();
    return { ...candidate, available: true, version, error: null };
  } catch (error) {
    return {
      ...candidate,
      available: false,
      version: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Explains why local detection found nothing. A container that can reach the socket but cannot read
 * it is a permission problem, not a missing Docker engine.
 */
export function localDockerFailure(candidates: ProbedDockerCandidate[]): { code: string; message: string } {
  const denied = candidates.some((candidate) => /EACCES|EPERM|permission denied/i.test(candidate.error ?? ''));
  if (denied) {
    return {
      code: 'docker_socket_permission',
      message:
        'Docker is running, but DockSentinel cannot access its socket (permission denied). Add the socket ' +
        'group to the container, for example Extra Parameters "--group-add=<socket GID>" (find it with: ' +
        "stat -c '%g' /var/run/docker.sock), then restart the container.",
    };
  }
  return {
    code: 'docker_not_found',
    message:
      'Docker was not reachable on this computer. Start Docker, or mount /var/run/docker.sock into the ' +
      'container when DockSentinel runs in Docker. You can also connect a remote Docker host.',
  };
}

/** Probes candidates in order. The API never creates an environment from an unresponsive endpoint. */
export async function detectLocalDocker(
  candidates: LocalDockerCandidate[] = localDockerCandidates(),
): Promise<ProbedDockerCandidate[]> {
  const results: ProbedDockerCandidate[] = [];
  for (const candidate of candidates) results.push(await probeDockerCandidate(candidate));
  return results;
}
