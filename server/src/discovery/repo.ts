import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const ALLOWED_HOSTS = new Set([
  "github.com",
  "www.github.com",
  "gitlab.com",
  "www.gitlab.com",
  "bitbucket.org",
]);

export interface NormalizedRepo {
  cloneUrl: string;
  /** Human label, e.g. "github.com/owner/repo". */
  label: string;
}

/**
 * Validate and normalize a user-supplied repository reference into an https
 * clone URL. Accepts full URLs or "owner/repo" shorthand (assumed GitHub).
 * Rejects anything that isn't a known public host to avoid SSRF / arbitrary
 * command surfaces.
 */
export function normalizeRepo(input: string): NormalizedRepo {
  const raw = input.trim();
  if (!raw) throw new Error("repository url is required");

  // "owner/repo" shorthand -> GitHub
  if (/^[\w.-]+\/[\w.-]+$/.test(raw)) {
    const clean = raw.replace(/\.git$/, "");
    return { cloneUrl: `https://github.com/${clean}.git`, label: `github.com/${clean}` };
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("invalid repository url");
  }

  if (url.protocol !== "https:") throw new Error("only https git URLs are supported");
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    throw new Error(`unsupported host: ${url.hostname} (allowed: github.com, gitlab.com, bitbucket.org)`);
  }
  if (url.username || url.password) throw new Error("credentials in URL are not allowed");

  const path = url.pathname.replace(/^\/+/, "").replace(/\.git$/, "");
  if (!/^[\w.-]+\/[\w.-]+/.test(path)) throw new Error("url must point to a repository");

  const host = url.hostname.replace(/^www\./, "");
  return { cloneUrl: `https://${host}/${path}.git`, label: `${host}/${path}` };
}

export interface ClonedRepo {
  dir: string;
  label: string;
  cleanup: () => void;
}

const TOKEN_USER: Record<string, string> = {
  "github.com": "x-access-token",
  "gitlab.com": "oauth2",
  "bitbucket.org": "x-token-auth",
};

/**
 * Shallow-clone a repository into a temp directory. If `token` is provided the
 * clone authenticates via an HTTP auth header (kept out of the remote URL and
 * never logged), enabling private-repo scanning. Times out so a slow or huge
 * clone can't hang a request. Caller must invoke cleanup().
 */
export async function cloneRepo(
  input: string,
  timeoutMs = 60_000,
  token?: string,
): Promise<ClonedRepo> {
  const { cloneUrl, label } = normalizeRepo(input);
  const dir = mkdtempSync(join(tmpdir(), "qv-scan-"));

  const host = label.split("/")[0];
  const args: string[] = [];
  if (token) {
    const user = TOKEN_USER[host] ?? "x-access-token";
    const basic = Buffer.from(`${user}:${token}`).toString("base64");
    args.push("-c", `http.extraHeader=Authorization: Basic ${basic}`);
  }
  args.push("clone", "--depth", "1", "--single-branch", "--no-tags", cloneUrl, dir);

  try {
    await execFileAsync("git", args, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "true" },
    });
  } catch (err: any) {
    rmSync(dir, { recursive: true, force: true });
    const msg = String(err?.stderr || err?.message || err);
    if (/not found|repository .* not found|could not read/i.test(msg)) {
      throw new Error(`repository not found or private: ${label}`);
    }
    if (err?.killed) throw new Error(`clone timed out after ${timeoutMs / 1000}s: ${label}`);
    throw new Error(`failed to clone ${label}`);
  }

  return {
    dir,
    label,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}
