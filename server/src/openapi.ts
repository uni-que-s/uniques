import { patternCount } from "./discovery/patterns.js";

/**
 * Hand-authored OpenAPI 3.1 description of the QuantumVault API. Served at
 * GET /api/openapi.json for integrators, SDK generation, and API gateways.
 * Paths are relative to the `/api` server base, matching how the dashboard
 * consumes the API. Reads are open on the demo org; mutating endpoints require
 * a bearer session token.
 */
export function openApiDocument(): Record<string, unknown> {
  const bearer = [{ bearerAuth: [] }];
  const ok = { description: "Success" };
  const idParam = {
    name: "id",
    in: "path",
    required: true,
    schema: { type: "string" },
  };
  const frameworkParam = {
    name: "framework",
    in: "path",
    required: true,
    schema: { type: "string", enum: ["FISMA", "CISA", "FedRAMP", "SOC2", "PCI-DSS"] },
  };

  return {
    openapi: "3.1.0",
    info: {
      title: "QuantumVault API",
      version: "0.1.0",
      description:
        "Quantum-safe cryptography platform: cryptographic asset discovery, risk scoring, " +
        "remediation tracking, compliance reporting, and CBOM/SARIF export. " +
        `The discovery engine ships ${patternCount()} detection patterns.`,
      license: { name: "MIT" },
    },
    servers: [{ url: "/api", description: "API base path (proxied by the web tier)" }],
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", description: "Session token from /auth/login or /auth/signup" },
      },
    },
    tags: [
      { name: "auth" },
      { name: "scans" },
      { name: "assets" },
      { name: "compliance" },
      { name: "export" },
      { name: "meta" },
    ],
    paths: {
      "/health": {
        get: { tags: ["meta"], summary: "Service health and pattern count", responses: { "200": ok } },
      },
      "/openapi.json": {
        get: { tags: ["meta"], summary: "This OpenAPI document", responses: { "200": ok } },
      },
      "/auth/signup": {
        post: {
          tags: ["auth"],
          summary: "Create an organization and account; returns a session token",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email", "password"],
                  properties: { email: { type: "string" }, password: { type: "string", minLength: 8 }, orgName: { type: "string" } },
                },
              },
            },
          },
          responses: { "201": ok, "400": { description: "Validation error" }, "429": { description: "Rate limited" } },
        },
      },
      "/auth/login": {
        post: {
          tags: ["auth"],
          summary: "Log in; returns a session token",
          responses: { "200": ok, "401": { description: "Invalid credentials" }, "429": { description: "Rate limited" } },
        },
      },
      "/auth/logout": { post: { tags: ["auth"], summary: "Invalidate the current session", responses: { "200": ok } } },
      "/auth/me": {
        get: { tags: ["auth"], summary: "Current user/org", security: bearer, responses: { "200": ok, "401": { description: "Not authenticated" } } },
      },
      "/dashboard": {
        get: { tags: ["meta"], summary: "Posture summary and migration progress for the latest scan", responses: { "200": ok } },
      },
      "/risk/config": {
        get: { tags: ["meta"], summary: "Active risk-scoring weights and factor descriptions", responses: { "200": ok } },
      },
      "/assets": {
        get: {
          tags: ["assets"],
          summary: "List discovered assets for the latest scan",
          parameters: [
            { name: "family", in: "query", schema: { type: "string" } },
            { name: "priority", in: "query", schema: { type: "string", enum: ["critical", "high", "medium", "low"] } },
            { name: "q", in: "query", schema: { type: "string" } },
          ],
          responses: { "200": ok },
        },
      },
      "/assets/{id}": {
        get: { tags: ["assets"], summary: "Single asset with risk breakdown", parameters: [idParam], responses: { "200": ok, "404": { description: "Not found" } } },
      },
      "/assets/{id}/status": {
        patch: {
          tags: ["assets"],
          summary: "Set an asset's remediation status",
          security: bearer,
          parameters: [idParam],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { type: "object", required: ["status"], properties: { status: { type: "string", enum: ["open", "in_progress", "migrated", "accepted"] } } },
              },
            },
          },
          responses: { "200": ok, "400": { description: "Invalid status" }, "401": { description: "Auth required" }, "404": { description: "Not found" } },
        },
      },
      "/assets/export.csv": { get: { tags: ["export"], summary: "Asset inventory as CSV (honors list filters)", responses: { "200": ok } } },
      "/cbom.json": { get: { tags: ["export"], summary: "CycloneDX 1.6 Cryptography Bill of Materials", responses: { "200": ok } } },
      "/sarif.json": { get: { tags: ["export"], summary: "SARIF 2.1.0 log (GitHub code-scanning)", responses: { "200": ok } } },
      "/scans": {
        get: { tags: ["scans"], summary: "Scan history", responses: { "200": ok } },
        post: {
          tags: ["scans"],
          summary: "Scan a local filesystem path",
          security: bearer,
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["target"], properties: { target: { type: "string" } } } } },
          },
          responses: { "201": ok, "400": { description: "Invalid path" }, "401": { description: "Auth required" }, "429": { description: "Rate limited" } },
        },
      },
      "/scans/git": {
        post: {
          tags: ["scans"],
          summary: "Clone and scan a public or private Git repo",
          security: bearer,
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { type: "object", required: ["url"], properties: { url: { type: "string" }, token: { type: "string", description: "Optional access token for private repos" } } },
              },
            },
          },
          responses: { "201": ok, "400": { description: "Invalid/unsupported repo" }, "401": { description: "Auth required" }, "429": { description: "Rate limited" } },
        },
      },
      "/compliance": { get: { tags: ["compliance"], summary: "Reports for all frameworks", responses: { "200": ok } } },
      "/compliance/{framework}": {
        get: { tags: ["compliance"], summary: "One framework report", parameters: [frameworkParam], responses: { "200": ok, "404": { description: "Not found" } } },
      },
      "/compliance/{framework}/export.json": {
        get: { tags: ["export"], summary: "Framework report as JSON", parameters: [frameworkParam], responses: { "200": ok, "404": { description: "Not found" } } },
      },
      "/compliance/{framework}/export.html": {
        get: { tags: ["export"], summary: "Framework report as print-to-PDF HTML", parameters: [frameworkParam], responses: { "200": ok, "404": { description: "Not found" } } },
      },
    },
  };
}
