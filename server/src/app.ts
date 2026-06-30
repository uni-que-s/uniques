import express, { type Express, type NextFunction, type Request, type Response } from "express";
import cors from "cors";
import { api } from "./routes/api.js";
import { authRouter } from "./routes/auth.js";
import { licenseRouter } from "./routes/license.js";
import { withAuth } from "./auth/middleware.js";
import { corsOptions, securityHeaders } from "./security.js";
import { requestLogger } from "./logging.js";

/**
 * Build the Express app (middleware + routes) without starting a listener or
 * seeding data. Keeping this pure makes it trivial to boot in tests against an
 * isolated database. The runtime entrypoint (index.ts) seeds and listens.
 */
export function createApp(): Express {
  const app = express();
  // Behind nginx in the container; trust the proxy so req.ip is the real client
  // (used for rate limiting), via the X-Forwarded-For header nginx sets.
  app.set("trust proxy", true);
  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.use(requestLogger);
  app.use(cors(corsOptions()));
  app.use(express.json());
  app.use("/api", withAuth);
  app.use("/api/auth", authRouter);
  // License status/activation is mounted before the gated `api` router so it
  // stays reachable even when the trial has lapsed and no key is active.
  app.use("/api/license", licenseRouter);
  app.use("/api", api);

  // Unmatched API routes get a JSON 404 rather than Express's default HTML.
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "not found" });
  });

  // Centralized error envelope. Client errors (parse failures, etc.) keep their
  // status and message; unexpected 5xx are logged server-side and returned as a
  // generic message so internals never leak to the caller.
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const e = err as { status?: number; statusCode?: number; message?: string };
    const status = typeof e?.status === "number" ? e.status : typeof e?.statusCode === "number" ? e.statusCode : 500;
    if (status >= 500) {
      console.error("[error]", err);
      res.status(status).json({ error: "internal server error" });
    } else {
      res.status(status).json({ error: e?.message ?? "request error" });
    }
  });

  return app;
}
