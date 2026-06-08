import type { NextFunction, Request, Response } from "express";
import { resolveSession, type AuthContext } from "./service.js";
import { DEFAULT_ORG_ID } from "../store/db.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
      /** Org to scope data to: the authenticated org, or the public demo org. */
      orgId: string;
    }
  }
}

function tokenFrom(req: Request): string | null {
  const h = req.header("authorization");
  if (h?.startsWith("Bearer ")) return h.slice(7).trim();
  return null;
}

/** Attaches req.auth (if a valid session) and always sets req.orgId. */
export function withAuth(req: Request, _res: Response, next: NextFunction): void {
  const token = tokenFrom(req);
  const ctx = token ? resolveSession(token) : null;
  if (ctx) req.auth = ctx;
  req.orgId = ctx?.orgId ?? DEFAULT_ORG_ID;
  next();
}

/** Rejects unauthenticated requests. Use for endpoints that must be scoped. */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.auth) {
    res.status(401).json({ error: "authentication required" });
    return;
  }
  next();
}
