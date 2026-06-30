import { Router } from "express";
import { getLicenseStatus, activateLicense } from "../license/service.js";
import { rateLimit } from "../auth/rateLimit.js";

export const licenseRouter = Router();

// GET /api/license — current license/trial status. Always reachable (it's how an
// operator checks state and the dashboard renders its banner), so it is exempt
// from the license gate.
licenseRouter.get("/", (_req, res) => {
  res.json(getLicenseStatus());
});

// POST /api/license/activate { key } — validate + persist a signed key. Forging a
// key requires the private signing key (not guessing), but we still throttle to
// keep the endpoint from being hammered.
licenseRouter.post("/activate", rateLimit(20, 5 * 60_000), (req, res, next) => {
  try {
    res.json(activateLicense(req.body?.key));
  } catch (err) {
    next(err);
  }
});
