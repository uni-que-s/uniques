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
  app.use(cors());
  app.use(express.json());
  app.use("/api", withAuth);
  app.use("/api/auth", authRouter);
  app.use("/api", api);
  return app;
}
