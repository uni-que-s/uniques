import type { NextFunction, Request, Response } from "express";
import type { CorsOptions } from "cors";

/**
 * CORS policy from the environment. `QV_CORS_ORIGIN` is a comma-separated
 * allowlist of origins; unset or "*" allows any origin (the dev default). In
 * production set it to the dashboard's origin so a stolen bearer token can't be
 * replayed from an arbitrary site.
 */
export function corsOptions(): CorsOptions {
  const raw = process.env.QV_CORS_ORIGIN?.trim();
  if (!raw || raw === "*") return { origin: "*" };
  const allow = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return { origin: allow };
}

/** Conservative response headers applied to every request. No external dependency. */
export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  next();
}
