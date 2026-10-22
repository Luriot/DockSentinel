export function isValidDateString(value: unknown): boolean {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (!/^\d{4}-\d{2}-\d{2}/.test(value)) return false;
  return Number.isFinite(Date.parse(value));
}

export function validateReference(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 1000) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.toString();
  } catch {
    return null;
  }
}

export interface CvssSelection {
  score: number | null;
  source: string | null;
  vector: string | null;
}

/** Selects the highest reported CVSS score and keeps the scoring source so it can be attributed. */
export function parseCvss(raw: unknown): CvssSelection {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { score: null, source: null, vector: null };
  let best: CvssSelection = { score: null, source: null, vector: null };
  for (const [source, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    const entry = value as Record<string, unknown>;
    for (const scoreKey of ['V3Score', 'V2Score'] as const) {
      const score = entry[scoreKey];
      if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10) continue;
      if (best.score === null || score > best.score) {
        const vectorKey = scoreKey === 'V3Score' ? 'V3Vector' : 'V2Vector';
        const vector = typeof entry[vectorKey] === 'string' ? String(entry[vectorKey]).slice(0, 200) : null;
        best = { score, source: source.slice(0, 40), vector };
      }
    }
  }
  return best;
}
