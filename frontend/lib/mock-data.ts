/**
 * Demo/placeholder data.
 *
 * This file exists ONLY so the dashboard is visually complete and
 * reviewable before Phase 1-8's FastAPI backend is wired in via
 * `lib/api.ts`. Nothing here is a stand-in for real logic — every page
 * that imports from this file is a clearly temporary data source, and
 * should switch to the corresponding `api.*` call once the backend is
 * live. Grep for "mock-data" to find every call site that still needs
 * that swap.
 */
import type { Assessment, Asset, Finding, PipelineStage, ToolRun } from "./types";

export const mockAssessments: Assessment[] = [
  {
    id: "a1b2c3",
    target: "example.com",
    assessmentType: "Bug Bounty",
    state: "running",
    scope: {
      allowedDomains: ["*.example.com"],
      allowedCidrs: [],
      excludedDomains: ["admin.example.com"],
      excludedCidrs: ["10.0.0.0/8"],
      rateLimitPerSecond: 5,
      concurrency: 10,
      authorizationConfirmed: true,
    },
    createdAt: "2026-10-09T09:12:00Z",
    startedAt: "2026-10-09T09:13:00Z",
    completedAt: null,
    findingsCount: { critical: 0, high: 2, medium: 4, low: 6, info: 3 },
  },
  {
    id: "d4e5f6",
    target: "juice-shop.local",
    assessmentType: "Lab",
    state: "completed",
    scope: {
      allowedDomains: ["juice-shop.local"],
      allowedCidrs: [],
      excludedDomains: [],
      excludedCidrs: [],
      rateLimitPerSecond: 10,
      concurrency: 20,
      authorizationConfirmed: true,
    },
    createdAt: "2026-10-08T14:00:00Z",
    startedAt: "2026-10-08T14:01:00Z",
    completedAt: "2026-10-08T15:22:00Z",
    findingsCount: { critical: 1, high: 3, medium: 5, low: 2, info: 1 },
  },
];

export const mockPipelineStages: PipelineStage[] = [
  { name: "recon", label: "Recon", status: "done", progressPercent: null },
  { name: "dns", label: "DNS", status: "done", progressPercent: null },
  { name: "http_discovery", label: "HTTP Discovery", status: "done", progressPercent: null },
  { name: "port_discovery", label: "Port Discovery", status: "done", progressPercent: null },
  { name: "crawler", label: "Crawler", status: "running", progressPercent: 68 },
  { name: "directory_scan", label: "Directory Scan", status: "pending", progressPercent: null },
  { name: "nuclei", label: "Nuclei", status: "pending", progressPercent: null },
  { name: "ai_analysis", label: "AI Analysis", status: "pending", progressPercent: null },
  { name: "report", label: "Report", status: "pending", progressPercent: null },
];

export const mockFindings: Finding[] = [
  {
    id: "f1",
    title: "Reflected XSS in search parameter",
    category: "xss",
    cwe: "CWE-79",
    owasp: "A03:2021",
    severity: "high",
    confidence: 0.88,
    endpoint: "/search",
    method: "GET",
    parameter: "q",
    evidence: [
      "param 'q' reflected unencoded in HTML context",
      "no CSP header observed on response",
    ],
    affectedAssets: ["example.com"],
    recommendation: "Context-aware output encoding on the `q` parameter; add a restrictive CSP.",
    references: ["https://owasp.org/www-community/attacks/xss/"],
    consensusStatus: "CONFIRMED",
    agreementScore: 0.94,
    modelCount: 3,
    createdAt: "2026-10-09T09:40:00Z",
  },
  {
    id: "f2",
    title: "Possible IDOR on /api/orders/{id}",
    category: "idor",
    cwe: "CWE-639",
    owasp: "A01:2021",
    severity: "critical",
    confidence: 0.63,
    endpoint: "/api/orders/{id}",
    method: "GET",
    parameter: "id",
    evidence: ["swapped id returned a different user's order under the same session"],
    affectedAssets: ["api.example.com"],
    recommendation: "Enforce per-object authorization checks server-side before returning order data.",
    references: [],
    consensusStatus: "REQUIRES_MANUAL_REVIEW",
    agreementScore: 0.41,
    modelCount: 3,
    createdAt: "2026-10-09T09:52:00Z",
  },
  {
    id: "f3",
    title: "Verbose server error on malformed JSON body",
    category: "misconfiguration",
    cwe: "CWE-209",
    owasp: "A05:2021",
    severity: "low",
    confidence: 0.77,
    endpoint: "/api/login",
    method: "POST",
    parameter: null,
    evidence: ["stack trace returned in 500 response body"],
    affectedAssets: ["api.example.com"],
    recommendation: "Return generic error messages in production; log stack traces server-side only.",
    references: [],
    consensusStatus: "CONFIRMED",
    agreementScore: 1.0,
    modelCount: 2,
    createdAt: "2026-10-09T10:05:00Z",
  },
];

export const mockAssets: Asset[] = [
  {
    id: "as1",
    hostname: "example.com",
    ipAddresses: ["93.184.216.34"],
    technologies: ["nginx", "React"],
    openPorts: [80, 443],
    httpStatus: 200,
    discoveredAt: "2026-10-09T09:14:00Z",
  },
  {
    id: "as2",
    hostname: "api.example.com",
    ipAddresses: ["93.184.216.35"],
    technologies: ["FastAPI", "PostgreSQL"],
    openPorts: [443],
    httpStatus: 200,
    discoveredAt: "2026-10-09T09:16:00Z",
  },
  {
    id: "as3",
    hostname: "dev.example.com",
    ipAddresses: ["93.184.216.36"],
    technologies: ["Express"],
    openPorts: [80, 443, 8080],
    httpStatus: 403,
    discoveredAt: "2026-10-09T09:19:00Z",
  },
];

export const mockToolRuns: ToolRun[] = [
  { id: "t1", toolName: "subfinder", target: "example.com", status: "completed", startedAt: "2026-10-09T09:13:05Z", finishedAt: "2026-10-09T09:13:40Z", resultCount: 12 },
  { id: "t2", toolName: "httpx", target: "example.com", status: "completed", startedAt: "2026-10-09T09:13:45Z", finishedAt: "2026-10-09T09:14:02Z", resultCount: 9 },
  { id: "t3", toolName: "katana", target: "example.com", status: "running", startedAt: "2026-10-09T09:16:00Z", finishedAt: null, resultCount: null },
  { id: "t4", toolName: "nuclei", target: "example.com", status: "queued", startedAt: "2026-10-09T09:16:00Z", finishedAt: null, resultCount: null },
];
