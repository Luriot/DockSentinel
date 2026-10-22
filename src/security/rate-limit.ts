export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs: number;
  remaining: number;
}

/**
 * Small fixed-window limiter for authentication endpoints. In-memory is acceptable because the
 * application is a single instance; restarting resets counters, which is documented.
 */
export class RateLimiter {
  private readonly max: number;
  private readonly windowMs: number;
  private readonly entries = new Map<string, { count: number; resetAt: number }>();

  constructor(max: number, windowMs: number) {
    this.max = max;
    this.windowMs = windowMs;
  }

  hit(key: string): RateLimitResult {
    const now = Date.now();
    this.prune(now);
    const entry = this.entries.get(key);
    if (!entry || entry.resetAt <= now) {
      this.entries.set(key, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, retryAfterMs: 0, remaining: this.max - 1 };
    }
    entry.count += 1;
    if (entry.count > this.max) {
      return { allowed: false, retryAfterMs: Math.max(0, entry.resetAt - now), remaining: 0 };
    }
    return { allowed: true, retryAfterMs: 0, remaining: this.max - entry.count };
  }

  reset(key: string): void {
    this.entries.delete(key);
  }

  private prune(now: number): void {
    if (this.entries.size < 5000) return;
    for (const [key, value] of this.entries) {
      if (value.resetAt <= now) this.entries.delete(key);
    }
  }
}
