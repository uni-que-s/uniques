import type { NextFunction, Request, Response } from "express";

/**
 * Structured (JSON-per-line) access logging. Emits one line per completed
 * request with method, path, status, latency, and the resolved org — friendly
 * to log aggregators. Health checks are skipped to avoid drowning real traffic.
 * Set QV_LOG=off to silence (used in tests).
 */
export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  if (process.env.QV_LOG === "off") return next();
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    if (req.path === "/api/health") return;
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    console.log(
      JSON.stringify({
        t: new Date().toISOString(),
        method: req.method,
        path: req.path,
        status: res.statusCode,
        ms: Math.round(ms * 10) / 10,
        org: req.orgId,
      }),
    );
  });
  next();
}
