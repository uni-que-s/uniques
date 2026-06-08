import express, { type Express } from "express";
import cors from "cors";
import { api } from "./routes/api.js";
import { authRouter } from "./routes/auth.js";
import { withAuth } from "./auth/middleware.js";

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
  app.use(cors());
  app.use(express.json());
  app.use("/api", withAuth);
  app.use("/api/auth", authRouter);
  app.use("/api", api);
  return app;
}
