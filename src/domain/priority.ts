import type { ExposureState } from './exposure.ts';
import type { Severity } from './severity.ts';

export type PriorityTier = 'P1' | 'P2' | 'P3' | 'P4';

export interface PriorityInput {
  severity: Severity;
  /** -1 = KEV data unavailable, 0 = not listed, 1 = listed. */
  kev: -1 | 0 | 1;
  hasFix: boolean;
  running: boolean;
  exposure: ExposureState;
  criticality?: 'critical' | 'high' | 'normal' | 'low' | null;
}

export interface PriorityResult {
  score: number;
  tier: PriorityTier;
  /** Human-readable reasons behind the score, shown in the UI so the ranking is never a black box. */
  factors: string[];
}

const BASE: Record<Severity, number> = {
  CRITICAL: 50,
  HIGH: 30,
  MEDIUM: 10,
  LOW: 2,
  UNKNOWN: 0,
};

/**
 * A deliberately small, documented ranking: severity plus four contextual signals. It is not a
 * risk score and never claims to quantify exploitability.
 */
export function prioritiseFinding(input: PriorityInput): PriorityResult {
  const factors: string[] = [];
  let score = BASE[input.severity];
  factors.push(`${input.severity} severity`);

  if (input.kev === 1) {
    score += 40;
    factors.push('Known exploited (CISA KEV)');
  }
  if (input.hasFix) {
    score += 10;
    factors.push('Fix available');
  }
  if (input.running) {
    score += 8;
    factors.push('Used by a running container');
  }
  if (input.exposure === 'confirmed') {
    score += 15;
    factors.push('Internet exposure declared');
  } else if (input.exposure === 'potential') {
    score += 6;
    factors.push('Potentially externally exposed');
  }
  switch (input.criticality) {
    case 'critical':
      score += 10;
      factors.push('Workload marked critical');
      break;
    case 'high':
      score += 5;
      factors.push('Workload marked important');
      break;
    case 'low':
      score -= 5;
      factors.push('Workload marked low priority');
      break;
    default:
      break;
  }

  const tier: PriorityTier = score >= 70 ? 'P1' : score >= 50 ? 'P2' : score >= 30 ? 'P3' : 'P4';
  return { score, tier, factors };
}

