import { db } from "../store/db.js";
import { verifyLicenseToken } from "./verify.js";

/**
 * License + trial state machine for the self-hosted platform.
 *
 * Two ways to be "active" (commercial features unlocked):
 *   - licensed: an authentic, unexpired signed key has been activated.
 *   - trial:    no key yet, and we're within the trial window from first boot.
 * Otherwise "expired" (trial ran out, or the activated key lapsed).
 *
 * State lives in the local `app_meta` table — no phone-home. The trial clock is
 * the DB volume; a determined self-hoster could reset it by wiping the volume.
 * That's an accepted limit for v0.1 (the signed key, not the trial, is the real
 * control for paid use) — consistent with the air-gap / no-tamper-callback ethos.
 */

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_TRIAL_DAYS = 30;
const DEFAULT_GRACE_DAYS = 7;

/**
 * Trial length in days (override with QV_TRIAL_DAYS, mainly for tests). Hardened
 * against operator fat-fingers: a blank/whitespace value means "use the default"
 * (note `Number("")` is 0, which would otherwise lock instantly), non-finite
 * values fall back to the default, and the result is clamped to a sane integer
 * range so a bad env can never produce an invalid Date / 500 the open endpoints.
 */
function parseDays(raw: string | undefined, def: number): number {
  if (raw == null || raw.trim() === "") return def;
  const n = Number(raw);
  if (!Number.isFinite(n)) return def;
  return Math.max(0, Math.min(36_500, Math.trunc(n)));
}
export const TRIAL_DAYS = parseDays(process.env.QV_TRIAL_DAYS, DEFAULT_TRIAL_DAYS);
/**
 * Days of FULL access after an entitlement expires before the platform drops to
 * the read-only resting state (override QV_GRACE_DAYS). A lapsed buyer keeps
 * full access during grace with a loud renew banner; after it, they can still
 * VIEW their inventory but can't run new scans — seeing your own exposure
 * converts better than a hard wall.
 */
export const GRACE_DAYS = parseDays(process.env.QV_GRACE_DAYS, DEFAULT_GRACE_DAYS);

const META_TRIAL_START = "trial_started_at";
const META_LICENSE_KEY = "license_key";

export type LicenseState = "licensed" | "trial" | "grace" | "readonly";

export interface LicenseStatus {
  state: LicenseState;
  /** Full commercial access (licensed, in-trial, or within the grace window). */
  active: boolean;
  /** Read-only resting state: existing data is viewable, but new scans / mutations are blocked. */
  readOnly: boolean;
  edition: string | null;
  org: string | null;
  /** ISO date (YYYY-MM-DD) the current entitlement runs through, or null. */
  expiresAt: string | null;
  daysRemaining: number;
  reason: "licensed" | "trial" | "trial_grace" | "license_grace" | "trial_readonly" | "license_readonly";
  /** Human-readable, safe to surface in the UI / API (carries no key material). */
  message: string;
}

function getMeta(key: string): string | null {
  const row = db.prepare("SELECT value FROM app_meta WHERE key = ?").get(key) as { value: string } | undefined;
  return row?.value ?? null;
}
function setMeta(key: string, value: string): void {
  db.prepare(
    "INSERT INTO app_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  ).run(key, value);
}

function isoDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}
/** Whole days from `fromISO` (00:00Z) to `toISO` (00:00Z); negative if past. */
function daysUntil(fromISO: string, toISO: string): number {
  return Math.round((Date.parse(`${toISO}T00:00:00Z`) - Date.parse(`${fromISO}T00:00:00Z`)) / DAY_MS);
}

/** Auto-start the trial clock on first read; returns its start time in ms. */
function trialStartMs(): number {
  let ts = getMeta(META_TRIAL_START);
  if (!ts) {
    ts = new Date().toISOString();
    setMeta(META_TRIAL_START, ts);
  }
  return Date.parse(ts);
}

interface Entitlement {
  kind: "trial" | "license";
  edition: string | null;
  org: string | null;
  /** Moment access ends (exclusive), in ms. */
  expiryMs: number;
  /** ISO date shown to the user as the run-through date. */
  expiresAt: string;
}

/** The currently-governing entitlement: an activated, verifiable license if one
 *  is stored; otherwise the (auto-started) trial. A stored key that no longer
 *  verifies is ignored — we fall back to the trial rather than failing open. */
function currentEntitlement(): Entitlement {
  const stored = getMeta(META_LICENSE_KEY);
  if (stored) {
    const payload = verifyLicenseToken(stored);
    if (payload) {
      // `expires` is inclusive through that day, so access ends at the start of
      // the following day.
      const expiryMs = Date.parse(`${payload.expires}T00:00:00Z`) + DAY_MS;
      return { kind: "license", edition: payload.edition, org: payload.org, expiryMs, expiresAt: payload.expires };
    }
  }
  const expiryMs = trialStartMs() + TRIAL_DAYS * DAY_MS;
  return { kind: "trial", edition: "trial", org: null, expiryMs, expiresAt: isoDate(expiryMs) };
}

/**
 * Entitlement lifecycle: active → grace → read-only.
 *  - active:   before expiry (licensed / trial) — full access.
 *  - grace:    up to GRACE_DAYS past expiry — still full access, loud renew banner.
 *  - readonly: after grace — existing inventory stays viewable (GET), but new
 *              scans and mutations are blocked. The free CLI is never affected.
 */
export function getLicenseStatus(now: Date = new Date()): LicenseStatus {
  const ent = currentEntitlement();
  const nowMs = now.getTime();
  const graceEndMs = ent.expiryMs + GRACE_DAYS * DAY_MS;
  const isLic = ent.kind === "license";
  const base = { edition: ent.edition, org: ent.org, expiresAt: ent.expiresAt };

  if (nowMs < ent.expiryMs) {
    const daysRemaining = Math.max(0, Math.ceil((ent.expiryMs - nowMs) / DAY_MS));
    const d = `${daysRemaining} day${daysRemaining === 1 ? "" : "s"}`;
    return {
      ...base,
      state: isLic ? "licensed" : "trial",
      active: true,
      readOnly: false,
      daysRemaining,
      reason: isLic ? "licensed" : "trial",
      message: isLic
        ? `Licensed to ${ent.org} · ${ent.edition} — ${d} remaining.`
        : `Trial — ${d} remaining. Activate a license key to continue after the trial.`,
    };
  }

  if (nowMs < graceEndMs) {
    const graceLeft = Math.max(0, Math.ceil((graceEndMs - nowMs) / DAY_MS));
    const g = `${graceLeft} day${graceLeft === 1 ? "" : "s"} of grace`;
    return {
      ...base,
      state: "grace",
      active: true,
      readOnly: false,
      daysRemaining: 0,
      reason: isLic ? "license_grace" : "trial_grace",
      message: isLic
        ? `Your ${ent.edition} license expired on ${ent.expiresAt} — ${g} left. Renew to avoid going read-only.`
        : `Your trial has ended — ${g} left. Activate a license key to avoid going read-only.`,
    };
  }

  return {
    ...base,
    state: "readonly",
    active: false,
    readOnly: true,
    daysRemaining: 0,
    reason: isLic ? "license_readonly" : "trial_readonly",
    message: isLic
      ? `Your ${ent.edition} license expired on ${ent.expiresAt}. You can still view your inventory — activate a key to run new scans again.`
      : `Your trial has ended. You can still view your existing inventory — activate a license key to run new scans again. (The free CLI is unaffected.)`,
  };
}

/**
 * Validate and persist a license key. Rejects forgeries (bad signature) and
 * already-expired keys with distinct messages. On success the key is stored and
 * the fresh status is returned.
 */
export function activateLicense(key: unknown): LicenseStatus {
  const payload = verifyLicenseToken(key);
  if (!payload) {
    throw httpError(400, "that license key is not valid");
  }
  const remaining = daysUntil(isoDate(Date.now()), payload.expires);
  if (remaining < 0) {
    throw httpError(400, `that license key expired on ${payload.expires}`);
  }
  setMeta(META_LICENSE_KEY, String(key).trim());
  return getLicenseStatus();
}

function httpError(status: number, message: string): Error & { status: number } {
  return Object.assign(new Error(message), { status });
}
