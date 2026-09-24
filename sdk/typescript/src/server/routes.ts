import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { ValidateFunction } from "ajv";
import { FindingsError } from "./errors.js";
import { dashboardQuery, serveDashboard } from "./dashboard.js";
import type { FindingsService } from "./findings-service.js";
import {
  ScanRequestError,
  validateScanSubmission,
  type ScanRunner,
} from "./scans.js";
import {
  findingSearchScope,
  pagination,
  validateDedupeGroups,
  type FindingsRequest,
} from "./validation.js";

export interface ScanRouteOptions {
  runner: ScanRunner;
  /** Required bearer token for every /v1/scans route. */
  apiToken: string;
}

export async function handleFindingsRequest(
  request: IncomingMessage,
  response: ServerResponse,
  service: FindingsService,
  validate: ValidateFunction<FindingsRequest>,
  scans?: ScanRouteOptions,
): Promise<void> {
  try {
    const url = new URL(request.url ?? "/", "http://localhost");
    const route = `${request.method} ${url.pathname}`;
    if (url.pathname === "/v1/scans" || url.pathname.startsWith("/v1/scans/")) {
      await handleScanRequest(request, response, url, route, scans);
      return;
    }
    if (
      request.method === "GET" &&
      (await serveDashboard(url.pathname, response))
    )
      return;
    if (route === "GET /v1/dashboard") {
      response.setHeader("Cache-Control", "no-store");
      json(
        response,
        200,
        await service.dashboard(dashboardQuery(url.searchParams)),
      );
      return;
    }
    if (route === "GET /v1/findings") {
      console.log(route);
      json(response, 200, await service.list(pagination(url.searchParams)));
      return;
    }
    const candidates = /^\/v1\/finding\/([^/]+)\/potential-duplicates$/.exec(
      url.pathname,
    );
    if (request.method === "GET" && candidates) {
      console.log("GET /v1/finding/:id/potential-duplicates");
      json(
        response,
        200,
        await service.potentialDuplicates(
          candidates[1]!,
          findingSearchScope(url.searchParams),
        ),
      );
      return;
    }
    const dedupeGroups = /^\/v1\/finding\/([^/]+)\/dedupe-groups$/.exec(
      url.pathname,
    );
    if (request.method === "GET" && dedupeGroups) {
      console.log("GET /v1/finding/:id/dedupe-groups");
      json(response, 200, await service.listDedupeGroups(dedupeGroups[1]!));
      return;
    }
    if (route === "POST /v1/dedupe-groups") {
      console.log(route);
      const input = await readJson(request);
      if (!validateDedupeGroups(input)) {
        throw new FindingsError(
          "invalid_request",
          "Expected {groups: [[findingId, ...], ...]} with at least two distinct finding IDs per group.",
        );
      }
      json(response, 201, await service.storeDedupeGroups(input.groups));
      return;
    }
    if (route === "POST /v1/bulk/findings") {
      console.log(route);
      const input = await readJson(request);
      if (!validate(input)) {
        throw new FindingsError(
          "invalid_request",
          "Expected {findings: [...]} with an optional nonempty repositoryId, using the existing Finding schema.",
        );
      }
      json(
        response,
        201,
        await service.insert(input.findings, input.repositoryId),
      );
      return;
    }
    request.resume();
    json(response, 404, { error: "not_found" });
  } catch (error) {
    if (error instanceof FindingsError) {
      const status = {
        invalid_request: 400,
        finding_conflict: 409,
        embedding_unavailable: 503,
        embedding_failed: 502,
        finding_not_indexed: 404,
      }[error.code];
      json(response, status, { error: error.code, message: error.message });
    } else {
      console.error(error);
      json(response, 500, { error: "internal_error" });
    }
  }
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new FindingsError(
      "invalid_request",
      "Request body must be valid JSON.",
    );
  }
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

async function handleScanRequest(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
  route: string,
  scans: ScanRouteOptions | undefined,
): Promise<void> {
  if (scans === undefined) {
    request.resume();
    json(response, 404, { error: "not_found" });
    return;
  }
  if (!authorized(request, scans.apiToken)) {
    request.resume();
    json(response, 401, { error: "unauthorized" });
    return;
  }
  try {
    if (route === "GET /v1/scans") {
      json(response, 200, { scans: scans.runner.list() });
      return;
    }
    if (route === "POST /v1/scans") {
      console.log(route);
      const input = await readJson(request);
      if (!validateScanSubmission(input)) {
        json(response, 400, {
          error: "invalid_request",
          message:
            "Expected {repository: https git URL, revision?: full 40-character commit SHA}.",
        });
        return;
      }
      json(response, 202, await scans.runner.submit(input));
      return;
    }
    const parts = url.pathname.split("/").slice(3);
    const job = parts[0] === undefined ? undefined : scans.runner.get(parts[0]);
    if (job === undefined) {
      request.resume();
      json(response, 404, { error: "not_found" });
      return;
    }
    if (request.method === "GET" && parts.length === 1) {
      json(response, 200, job);
      return;
    }
    if (request.method === "GET" && parts[1] === "log" && parts.length === 2) {
      await scans.runner.streamLog(job.id, response);
      return;
    }
    if (
      request.method === "GET" &&
      parts[1] === "files" &&
      parts.length === 2
    ) {
      json(response, 200, { files: await scans.runner.listFiles(job.id) });
      return;
    }
    if (request.method === "GET" && parts[1] === "files") {
      const served = await scans.runner.streamFile(
        job.id,
        decodeURIComponent(parts.slice(2).join("/")),
        response,
      );
      if (!served) json(response, 404, { error: "not_found" });
      return;
    }
    request.resume();
    json(response, 404, { error: "not_found" });
  } catch (error) {
    if (error instanceof ScanRequestError) {
      json(response, 400, { error: "invalid_request", message: error.message });
    } else if (
      (error as NodeJS.ErrnoException).code === "ENOENT" ||
      (error as NodeJS.ErrnoException).code === "EISDIR"
    ) {
      json(response, 404, { error: "not_found" });
    } else {
      console.error(error);
      json(response, 500, { error: "internal_error" });
    }
  }
}

function authorized(request: IncomingMessage, apiToken: string): boolean {
  const header = request.headers.authorization ?? "";
  const presented = Buffer.from(header.replace(/^Bearer\s+/i, ""));
  const expected = Buffer.from(apiToken);
  return (
    presented.length === expected.length &&
    timingSafeEqual(presented, expected)
  );
}
