import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { db } from "../store/db.js";

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface AuthContext {
  userId: string;
  orgId: string;
  email: string;
  orgName: string;
}

function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  const dk = scryptSync(pw, salt, 64);
  return `${salt.toString("hex")}:${dk.toString("hex")}`;
}

function verifyPassword(pw: string, stored: string): boolean {
  const [saltHex, keyHex] = stored.split(":");
  if (!saltHex || !keyHex) return false;
  const key = Buffer.from(keyHex, "hex");
  const dk = scryptSync(pw, Buffer.from(saltHex, "hex"), 64);
  return key.length === dk.length && timingSafeEqual(key, dk);
}

function createSession(userId: string): string {
  const token = randomBytes(32).toString("hex");
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
  ).run(token, userId, new Date(now).toISOString(), new Date(now + SESSION_TTL_MS).toISOString());
  return token;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function signup(email: string, password: string, orgName?: string): { token: string; ctx: AuthContext } {
  const normEmail = email.trim().toLowerCase();
  if (!EMAIL_RE.test(normEmail)) throw new Error("a valid email is required");
  if (password.length < 8) throw new Error("password must be at least 8 characters");

  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(normEmail);
  if (existing) throw new Error("an account with that email already exists");

  const orgId = `org_${randomUUID().slice(0, 8)}`;
  const userId = `user_${randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();
  const name = orgName?.trim() || `${normEmail.split("@")[0]}'s Organization`;

  db.exec("BEGIN");
  try {
    db.prepare(`INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)`).run(orgId, name, now);
    db.prepare(
      `INSERT INTO users (id, org_id, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
    ).run(userId, orgId, normEmail, hashPassword(password), now);
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }

  const token = createSession(userId);
  return { token, ctx: { userId, orgId, email: normEmail, orgName: name } };
}

export function login(email: string, password: string): { token: string; ctx: AuthContext } {
  const normEmail = email.trim().toLowerCase();
  const user = db
    .prepare(`SELECT id, org_id, email, password_hash FROM users WHERE email = ?`)
    .get(normEmail) as { id: string; org_id: string; email: string; password_hash: string } | undefined;
  if (!user || !verifyPassword(password, user.password_hash)) {
    throw new Error("invalid email or password");
  }
  const org = db.prepare(`SELECT name FROM organizations WHERE id = ?`).get(user.org_id) as
    | { name: string }
    | undefined;
  const token = createSession(user.id);
  return {
    token,
    ctx: { userId: user.id, orgId: user.org_id, email: user.email, orgName: org?.name ?? "Organization" },
  };
}

export function logout(token: string): void {
  db.prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
}

export function resolveSession(token: string): AuthContext | null {
  const row = db
    .prepare(
      `SELECT s.expires_at, u.id AS user_id, u.org_id, u.email, o.name AS org_name
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       JOIN organizations o ON o.id = u.org_id
       WHERE s.token = ?`,
    )
    .get(token) as
    | { expires_at: string; user_id: string; org_id: string; email: string; org_name: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
    return null;
  }
  return { userId: row.user_id, orgId: row.org_id, email: row.email, orgName: row.org_name };
}
