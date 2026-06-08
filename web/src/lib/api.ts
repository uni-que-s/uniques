import axios from "axios";

const http = axios.create({ baseURL: "/api" });

const TOKEN_KEY = "qv_token";
export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

http.interceptors.request.use((config) => {
  const t = tokenStore.get();
  if (t) config.headers.Authorization = `Bearer ${t}`;
  return config;
});

export interface AuthUser {
  email: string;
  orgName: string;
}

export const signup = (email: string, password: string, orgName?: string) =>
  http.post<{ token: string; user: AuthUser }>("/auth/signup", { email, password, orgName }).then((r) => r.data);
export const login = (email: string, password: string) =>
  http.post<{ token: string; user: AuthUser }>("/auth/login", { email, password }).then((r) => r.data);
export const logout = () => http.post("/auth/logout").then(() => undefined);
export const getMe = () => http.get<{ user: AuthUser }>("/auth/me").then((r) => r.data.user);

export type Severity = "critical" | "high" | "medium" | "low";
export type ComplianceStatus = "pass" | "gap" | "fail";
export type AssetStatus = "open" | "in_progress" | "migrated" | "accepted";
export const ASSET_STATUSES: AssetStatus[] = ["open", "in_progress", "migrated", "accepted"];

export interface RiskScore {
  score: number;
  priority: Severity;
  factors: {
    dataSensitivity: number;
    retentionExposure: number;
    hndlExposure: number;
    complianceImpact: number;
    businessImpact: number;
  };
  recommendation: string;
  migrationEffortDays: number;
}

export interface CryptoAsset {
  id: string;
  scanId: string;
  file: string;
  line: number;
  family: string;
  algorithm: string;
  keyBits: number | null;
  language: string;
  snippet: string;
  patternId: string;
  quantumVulnerable: boolean;
  pqcReplacement: string;
  status: AssetStatus;
  risk?: RiskScore;
}

export interface Dashboard {
  totalAssets: number;
  quantumVulnerable: number;
  byFamily: Record<string, number>;
  byPriority: Record<string, number>;
  byStatus: Record<AssetStatus, number>;
  migrationProgressPct: number;
  migrationEffortDays: number;
  remainingEffortDays: number;
  avgCompliancePct: number;
  frameworks: { framework: string; scorePct: number; status: ComplianceStatus }[];
  lastScan: { id: string; filesScanned: number; durationMs: number; finishedAt: string } | null;
}

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  status: ComplianceStatus;
  affectedAssets: number;
  remediation: string;
}

export interface ComplianceReport {
  framework: string;
  generatedAt: string;
  scanId: string;
  overallStatus: ComplianceStatus;
  scorePct: number;
  controls: ComplianceControl[];
  summary: string;
}

export interface ScanJob {
  id: string;
  target: string;
  startedAt: string;
  finishedAt: string;
  filesScanned: number;
  durationMs: number;
  assetCount: number;
  status: string;
}

export const getDashboard = () => http.get<Dashboard>("/dashboard").then((r) => r.data);
export const getAssets = (params?: Record<string, string>) =>
  http.get<CryptoAsset[]>("/assets", { params }).then((r) => r.data);
export const updateAssetStatus = (id: string, status: AssetStatus) =>
  http.patch<CryptoAsset>(`/assets/${id}/status`, { status }).then((r) => r.data);
export const getCompliance = () => http.get<ComplianceReport[]>("/compliance").then((r) => r.data);

export async function downloadComplianceJson(framework: string) {
  const res = await http.get(`/compliance/${framework}/export.json`, { responseType: "blob" });
  const url = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${framework}-compliance.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function openCompliancePdf(framework: string) {
  const res = await http.get(`/compliance/${framework}/export.html`, { responseType: "text" });
  const w = window.open("", "_blank");
  if (!w) throw new Error("Popup blocked — allow popups to print the report.");
  w.document.open();
  w.document.write(res.data as string);
  w.document.close();
  setTimeout(() => w.print(), 400);
}
export const getScans = () => http.get<ScanJob[]>("/scans").then((r) => r.data);
export const runScan = (target: string) =>
  http.post<{ job: ScanJob; assetCount: number }>("/scans", { target }).then((r) => r.data);
export const runGitScan = (url: string, token?: string) =>
  http
    .post<{ job: ScanJob; assetCount: number; repo: string }>("/scans/git", { url, token })
    .then((r) => r.data);
