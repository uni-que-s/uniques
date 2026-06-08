import { Router } from "express";
import { login, logout, signup } from "../auth/service.js";

export const authRouter = Router();

authRouter.post("/signup", (req, res) => {
  const { email, password, orgName } = req.body ?? {};
  try {
    const { token, ctx } = signup(String(email ?? ""), String(password ?? ""), orgName);
    res.status(201).json({ token, user: { email: ctx.email, orgName: ctx.orgName } });
  } catch (err: any) {
    res.status(400).json({ error: err?.message ?? "signup failed" });
  }
});

authRouter.post("/login", (req, res) => {
  const { email, password } = req.body ?? {};
  try {
    const { token, ctx } = login(String(email ?? ""), String(password ?? ""));
    res.json({ token, user: { email: ctx.email, orgName: ctx.orgName } });
  } catch (err: any) {
    res.status(401).json({ error: err?.message ?? "login failed" });
  }
});

authRouter.post("/logout", (req, res) => {
  const h = req.header("authorization");
  if (h?.startsWith("Bearer ")) logout(h.slice(7).trim());
  res.json({ ok: true });
});

authRouter.get("/me", (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "not authenticated" });
  res.json({ user: { email: req.auth.email, orgName: req.auth.orgName } });
});
