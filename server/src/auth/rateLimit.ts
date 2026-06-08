import type { NextFunction, Request, Response } from "express";

/**
 * Fixed-window-ish sliding rate limiter. Tracks recent hit timestamps per key
 * and allows up to `max` within `windowMs`. The clock is injectable so the logic
 * is deterministically testable.
 */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Returns true if the request is allowed (and records it), false if limited. */
  check(key: string): boolean {
    const t = this.now();
    const recent = (this.hits.get(key) ?? []).filter((ts) => t - ts < this.windowMs);
    if (recent.length >= this.max) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(t);
    this.hits.set(key, recent);
    return true;
  }
}

/** Express middleware: limit requests per client IP. */
export function rateLimit(max: number, windowMs: number) {
  const limiter = new RateLimiter(max, windowMs);
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip ?? "unknown";
    if (!limiter.check(key)) {
      res.status(429).json({ error: "too many requests — please slow down and try again shortly" });
      return;
    }
    next();
  };
}
