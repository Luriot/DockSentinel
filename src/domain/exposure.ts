export interface ContainerPort {
  readonly ip?: string | null;
  readonly privatePort?: number | null;
  readonly publicPort?: number | null;
  readonly type?: string | null;
}

export type ExposureState = 'confirmed' | 'potential' | 'internal' | 'unknown';

export interface ExposureResult {
  state: ExposureState;
  /** Plain-language evidence, safe to show in the UI and alerts. */
  reasons: string[];
}

export interface ExposureInput {
  state: string;
  ports: ContainerPort[];
  networkMode?: string | null;
  labels?: Record<string, string> | null;
}

function isWildcardHost(ip: string | null | undefined): boolean {
  if (!ip) return true; // Docker reports an empty HostIp for 0.0.0.0 bindings.
  return ip === '0.0.0.0' || ip === '::' || ip === '[::]';
}

function isLoopback(ip: string | null | undefined): boolean {
  if (!ip) return false;
  return ip === '127.0.0.1' || ip === '::1' || ip === '[::1]' || ip.startsWith('127.');
}

/**
 * Classifies network exposure from Docker metadata. Published ports are evidence of potential
 * reachability, not proof that the service is reachable from the public Internet: firewalls,
 * reverse proxies, NAT and provider security groups all sit in between.
 */
export function classifyExposure(input: ExposureInput): ExposureResult {
  const labels = input.labels ?? {};
  const declared = (labels['docksentinel.exposure'] ?? '').trim().toLowerCase();
  if (declared === 'internet' || declared === 'public' || declared === 'confirmed') {
    return {
      state: 'confirmed',
      reasons: ['Declared Internet-facing by the docksentinel.exposure container label'],
    };
  }
  if (declared === 'internal' || declared === 'none' || declared === 'private') {
    return { state: 'internal', reasons: ['Declared internal by the docksentinel.exposure container label'] };
  }

  if (input.state.toLowerCase() !== 'running') {
    return { state: 'unknown', reasons: ['Container is not running; exposure cannot be assessed'] };
  }

  const published = input.ports.filter((port) => typeof port.publicPort === 'number' && port.publicPort > 0);
  const wildcard = published.filter((port) => isWildcardHost(port.ip));
  if (wildcard.length > 0) {
    const ports = wildcard.map((port) => `${port.publicPort}/${port.type || 'tcp'}`).join(', ');
    return { state: 'potential', reasons: [`Published host port ${ports} on all interfaces`] };
  }
  if (published.length > 0 && published.every((port) => isLoopback(port.ip))) {
    return { state: 'internal', reasons: ['Published only on loopback addresses'] };
  }
  if (published.length > 0) {
    return { state: 'potential', reasons: ['Published on a specific host interface'] };
  }
  if ((input.networkMode ?? '').toLowerCase() === 'host') {
    return { state: 'potential', reasons: ['Uses host networking; services may be reachable directly'] };
  }
  return { state: 'internal', reasons: ['No published host ports'] };
}

