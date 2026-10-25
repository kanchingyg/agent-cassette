import { createServer, type IncomingMessage, type Server } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import { resolveCassettePath } from "./cassette-path.js";
import { sealEntry, stripSensitiveHeaders, verifyEntryIntegrity } from "./cassette-integrity.js";
import { hashPrompt, redactSecrets } from "./prompt-hasher.js";
import { assertAllowedUpstreamTarget } from "./ssrf.js";
import { parseSseBody, type SseEvent } from "./sse-replayer.js";

export const CASSETTE_VERSION = 1;

export type CassetteEntry = {
  method: string;
  url: string;
  requestHash: string;
  requestBody: string;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseBody?: string;
  sseEvents?: SseEvent[];
  isEmbedding?: boolean;
  entrySha256?: string;
};

export type Cassette = { version: number; recordedAt?: string; entries: CassetteEntry[] };

export type LoadCassetteOptions = { strictIntegrity?: boolean; cwd?: string };

export function loadCassette(path: string, opts?: LoadCassetteOptions): Cassette {
  const resolved = resolveCassettePath(path, opts?.cwd);
  if (!existsSync(resolved)) return { version: CASSETTE_VERSION, entries: [] };
  const cassette = JSON.parse(readFileSync(resolved, "utf8")) as Cassette;
  if (opts?.strictIntegrity) {
    for (const entry of cassette.entries) {
      verifyEntryIntegrity(entry, true);
    }
  }
  return redactCassetteSecrets(cassette);
}

function redactCassetteSecrets(cassette: Cassette): Cassette {
  return {
    ...cassette,
    entries: cassette.entries.map((e) => ({
      ...e,
      requestBody: redactSecrets(e.requestBody),
      responseBody: e.responseBody ? redactSecrets(e.responseBody) : e.responseBody,
      responseHeaders: stripSensitiveHeaders(e.responseHeaders),
    })),
  };
}

export function saveCassette(path: string, cassette: Cassette, cwd = process.cwd()): void {
  const resolved = resolveCassettePath(path, cwd);
  const sealed: Cassette = {
    ...cassette,
    entries: cassette.entries.map((e) => sealEntry(redactEntryForStorage(e))),
  };
  writeFileSync(resolved, redactSecrets(JSON.stringify(sealed, null, 2)));
}

function redactEntryForStorage(entry: CassetteEntry): CassetteEntry {
  return {
    ...entry,
    requestBody: redactSecrets(entry.requestBody),
    responseBody: entry.responseBody ? redactSecrets(entry.responseBody) : entry.responseBody,
    responseHeaders: stripSensitiveHeaders(entry.responseHeaders),
  };
}

export type ProxyOptions = {
  mode: "record" | "replay";
  cassettePath: string;
  strict?: boolean;
  allowWrite?: boolean;
  cwd?: string;
};

const LLM_PATH_RE =
  /\/(v1\/chat\/completions|v1\/completions|v1\/embeddings|api\/embed|api\/embeddings|v1\/messages)/;

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function upstreamRequest(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: Buffer,
): Promise<{ status: number; headers: Record<string, string>; body: Buffer; sse: boolean }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const fn = u.protocol === "https:" ? httpsRequest : httpRequest;
    const req = fn(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: u.pathname + u.search,
        method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () => {
          const h: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") h[k.toLowerCase()] = v;
          }
          resolve({
            status: res.statusCode ?? 500,
            headers: h,
            body: Buffer.concat(chunks),
            sse: (h["content-type"] ?? "").includes("text/event-stream"),
          });
        });
      },
    );
    req.on("error", reject);
    if (body.length) req.write(body);
    req.end();
  });
}

function findEntry(cassette: Cassette, method: string, url: string, body: string): CassetteEntry | undefined {
  let parsed: unknown = {};
  try {
    parsed = JSON.parse(body || "{}");
  } catch {
    parsed = body;
  }
  const h = hashPrompt(parsed);
  return cassette.entries.find((e) => e.method === method && e.url === url && e.requestHash === h);
}

export function createVcrProxy(opts: ProxyOptions): Server {
  const cassettePath = resolveCassettePath(opts.cassettePath, opts.cwd);
  let cassette = loadCassette(cassettePath, { strictIntegrity: opts.strict, cwd: opts.cwd });
  return createServer(async (req, res) => {
    const url = req.url ?? "/";
    if (!LLM_PATH_RE.test(url) && url !== "/") {
      res.writeHead(404);
      res.end("not an LLM route");
      return;
    }
    const method = req.method ?? "GET";
    const rawBody = await readBody(req);
    const bodyStr = rawBody.toString("utf8");
    const targetUrl = req.headers["x-cassette-target"] as string | undefined;
    if (!targetUrl && opts.mode === "record") {
      res.writeHead(400);
      res.end("missing X-Cassette-Target");
      return;
    }
    if (opts.mode === "replay") {
      const entry = findEntry(cassette, method, url, bodyStr);
      if (!entry) {
        res.writeHead(opts.strict ? 503 : 404);
        res.end(opts.strict ? "replay miss (strict: no network)" : "cassette miss");
        return;
      }
      try {
        verifyEntryIntegrity(entry, Boolean(opts.strict));
      } catch (e) {
        res.writeHead(503);
        res.end(String(e));
        return;
      }
      for (const [k, v] of Object.entries(entry.responseHeaders)) res.setHeader(k, v);
      res.writeHead(entry.responseStatus);
      if (entry.sseEvents?.length) {
        for (const ev of entry.sseEvents) {
          res.write(`data: ${ev.data.split("\n").join("\ndata: ")}\n\n`);
        }
        res.end();
      } else res.end(entry.responseBody ?? "");
      return;
    }
    if (!opts.allowWrite && existsSync(cassettePath) && cassette.entries.length > 0) {
      res.writeHead(403);
      res.end("Read-only: pass --allow-write to overwrite cassette");
      return;
    }
    try {
      assertAllowedUpstreamTarget(targetUrl!);
    } catch (e) {
      res.writeHead(403);
      res.end(String(e));
      return;
    }
    const fullUrl = targetUrl + (url.startsWith("/") ? url : `/${url}`);
    const fwdHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lower = k.toLowerCase();
      if (lower === "host" || lower === "x-cassette-target") continue;
      if (typeof v === "string") fwdHeaders[k] = v;
    }
    const safeFwd = stripSensitiveHeaders(fwdHeaders);
    try {
      const up = await upstreamRequest(fullUrl, method, safeFwd, rawBody);
      let parsed: unknown = {};
      try {
        parsed = JSON.parse(bodyStr || "{}");
      } catch {
        parsed = bodyStr;
      }
      const entry: CassetteEntry = {
        method,
        url,
        requestHash: hashPrompt(parsed),
        requestBody: redactSecrets(bodyStr),
        responseStatus: up.status,
        responseHeaders: stripSensitiveHeaders(up.headers),
        isEmbedding: /embed/.test(url),
      };
      if (up.sse) {
        entry.sseEvents = parseSseBody(up.body.toString("utf8"));
        entry.responseHeaders["content-type"] = "text/event-stream";
      } else entry.responseBody = redactSecrets(up.body.toString("utf8"));
      cassette.entries.push(sealEntry(entry));
      cassette.recordedAt = new Date().toISOString();
      saveCassette(cassettePath, cassette, opts.cwd);
      for (const [k, v] of Object.entries(up.headers)) res.setHeader(k, v);
      res.writeHead(up.status);
      res.end(up.body);
    } catch (e) {
      res.writeHead(502);
      res.end(String(e));
    }
  });
}

export async function startProxyServer(opts: ProxyOptions): Promise<{ port: number; close: () => void }> {
  const server = createVcrProxy(opts);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return { port, close: () => server.close() };
}

export type RunResult = { exitCode: number | null; signal: NodeJS.Signals | null };

export function buildAgentChildEnv(mode: "record" | "replay", proxyBase: string): Record<string, string> {
  return {
    AGENT_CASSETTE_MODE: mode,
    AGENT_CASSETTE_PROXY: proxyBase,
    OPENAI_BASE_URL: proxyBase,
    OPENAI_API_BASE: proxyBase,
    OLLAMA_HOST: proxyBase,
    ANTHROPIC_BASE_URL: proxyBase,
  };
}

export async function runChild(cmd: string, args: string[], env: Record<string, string>): Promise<RunResult> {
  const { spawn } = await import("node:child_process");
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      env: { ...process.env, ...env },
      shell: false,
      stdio: "inherit",
    });
    child.on("close", (code, signal) => resolve({ exitCode: code, signal }));
  });
}

export async function recordAgentRun(
  cmd: string,
  args: string[],
  cassettePath: string,
  allowWrite = false,
  cwd = process.cwd(),
): Promise<RunResult> {
  const resolved = resolveCassettePath(cassettePath, cwd);
  const { port, close } = await startProxyServer({ mode: "record", cassettePath: resolved, allowWrite, cwd });
  const proxyBase = `http://127.0.0.1:${port}`;
  const result = await runChild(cmd, args, buildAgentChildEnv("record", proxyBase));
  close();
  return result;
}

export async function replayAgentRun(
  cmd: string,
  args: string[],
  cassettePath: string,
  cwd = process.cwd(),
): Promise<RunResult> {
  const resolved = resolveCassettePath(cassettePath, cwd);
  const { port, close } = await startProxyServer({
    mode: "replay",
    cassettePath: resolved,
    strict: true,
    cwd,
  });
  const proxyBase = `http://127.0.0.1:${port}`;
  const result = await runChild(cmd, args, buildAgentChildEnv("replay", proxyBase));
  close();
  return result;
}

export async function proxyFetch(
  proxyPort: number,
  targetBase: string,
  path: string,
  init: { method?: string; body?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: string; ms: number }> {
  const start = performance.now();
  const res = await fetch(`http://127.0.0.1:${proxyPort}${path}`, {
    method: init.method ?? "POST",
    headers: { ...init.headers, "Content-Type": "application/json", "X-Cassette-Target": targetBase },
    body: init.body,
  });
  return { status: res.status, body: await res.text(), ms: performance.now() - start };
}
