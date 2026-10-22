export function nowIso(): string {
  return new Date().toISOString();
}

export function isoAfter(milliseconds: number, from: Date = new Date()): string {
  return new Date(from.getTime() + milliseconds).toISOString();
}


export function ageHours(value: string | null | undefined, now: Date = new Date()): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return null;
  return Math.max(0, (now.getTime() - time) / 3_600_000);
}

export function isoDay(date: Date = new Date()): string {
  return date.toISOString().slice(0, 10);
}
