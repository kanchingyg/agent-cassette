import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

import {
  hijackStdoutForMcp,
  jsonRpcFrameLog,
  dispatchMcpMessage,
  setGuards,
  resetLoopBreaker,
  checkLoopBreaker,
  guardMutatingTool,
  windowsToWsl,
  wslToWindows,
  normalizeEmbedBatch,
  floatArrayToBase64,
  base64ToFloatArray,
  mrlSlice,
  assertDimensionFingerprint,
  applyReasoningContentPolicy,
  createReasoningState,
  sanitizeRequestBody,
  normalizeToolChoice,
  detectProvider,
  parseDirtyToolCall,
} from "../src/bridge.js";
import { hashPrompt, diffSemantic, headTailTruncate, anchorToolsAtTail, redactSecrets } from "../src/prompt-hasher.js";
import { parseSseBody, replaySseChunks, serializeSseStream } from "../src/sse-replayer.js";
import {
  loadCassette,
  saveCassette,
  startProxyServer,
  proxyFetch,
  buildAgentChildEnv,
} from "../src/http-vcr-proxy.js";
import { assertAllowedUpstreamTarget } from "../src/ssrf.js";
import { resolveCassettePath } from "../src/cassette-path.js";
import { computeEntrySha256, verifyEntryIntegrity } from "../src/cassette-integrity.js";

describe("prompt hasher", () => {
  it("ignores ephemeral keys and key order", () => {
    const a = { messages: [{ role: "user", content: "hi" }], id: "1", temperature: 0 };
    const b = { temperature: 0, messages: [{ role: "user", content: "hi" }], timestamp: 99 };
    expect(hashPrompt(a)).toBe(hashPrompt(b));
  });
  it("redacts secrets", () => {
    expect(redactSecrets("Bearer sk-abcdefghijklmnopqrstuvwxyz123456")).toContain("[REDACTED]");
  });
  it("diff with head+tail truncation", () => {
    expect(diffSemantic({ text: "x".repeat(5000) }, { text: "y".repeat(5000) }, 512)[0].before).toContain("TRUNCATED");
  });
  it("anchors tools before ASSISTANT marker", () => {
    const out = anchorToolsAtTail("SYS\nASSISTANT:", "[TOOLS]");
    expect(out.indexOf("[TOOLS]")).toBeLessThan(out.lastIndexOf("ASSISTANT:"));
  });
});

describe("SSE replayer", () => {
  it("roundtrips SSE chunks", () => {
    const raw = 'data: {"delta":"hello"}\n\n' + 'data: {"tool_calls":[{"name":"t"}]}\n\n' + "data: [DONE]\n\n";
    expect(parseSseBody(raw).length).toBe(3);
    expect(serializeSseStream(parseSseBody(raw))).toContain("tool_calls");
  });
  it("replays in under 10ms", async () => {
    const ms = await replaySseChunks(parseSseBody('data: {"x":1}\n\n'), () => {});
    expect(ms).toBeLessThan(10);
  });
});

describe("HTTP VCR record + replay", () => {
  let mock: Server;
  let mockPort = 0;
  let tmpDir: string;
  const cassetteRel = "tape.json";
  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "cassette-"));
    mock = createServer((req, res) => {
      if (req.url === "/v1/chat/completions" && req.method === "POST") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.write('data: {"choices":[{"delta":{"content":"Hi"}}]}\n\n');
        res.write('data: {"choices":[{"delta":{"tool_calls":[{"name":"run"}]}}]}\n\n');
        res.write("data: [DONE]\n\n");
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => mock.listen(0, "127.0.0.1", () => r()));
    mockPort = (mock.address() as { port: number }).port;
  });
  afterEach(() => {
    mock.close();
    rmSync(tmpDir, { recursive: true });
  });
  it("blocks SSRF upstream targets on record", async () => {
    const rec = await startProxyServer({ mode: "record", cassettePath: cassetteRel, allowWrite: true, cwd: tmpDir });
    const blocked = await proxyFetch(rec.port, "http://10.0.0.1:80", "/v1/chat/completions", {
      body: "{}",
    });
    expect(blocked.status).toBe(403);
    expect(blocked.body).toMatch(/SSRF/);
    rec.close();
  });
  it("records SSE then replays without mock", async () => {
    const target = `http://127.0.0.1:${mockPort}`;
    const body = JSON.stringify({ model: "test", messages: [{ role: "user", content: "ping" }] });
    const rec = await startProxyServer({ mode: "record", cassettePath: cassetteRel, allowWrite: true, cwd: tmpDir });
    expect((await proxyFetch(rec.port, target, "/v1/chat/completions", { body })).body).toContain("tool_calls");
    rec.close();
    mock.close();
    const rep = await startProxyServer({ mode: "replay", cassettePath: cassetteRel, strict: true, cwd: tmpDir });
    const start = performance.now();
    const replayed = await proxyFetch(rep.port, target, "/v1/chat/completions", { body });
    expect(performance.now() - start).toBeLessThan(50);
    expect(replayed.body).toContain("[DONE]");
    rep.close();
  });
});

describe("SSRF and child env", () => {
  it("rejects metadata and non-allowlisted private targets", () => {
    expect(() => assertAllowedUpstreamTarget("http://169.254.169.254/latest/meta-data/")).toThrow(/SSRF/);
    expect(() => assertAllowedUpstreamTarget("http://10.0.0.1/v1")).toThrow(/SSRF/);
    expect(() => assertAllowedUpstreamTarget("http://192.168.1.1/v1")).toThrow(/SSRF/);
    expect(() => assertAllowedUpstreamTarget("http://evil.example/v1")).toThrow(/allowlist/);
  });
  it("allows allowlisted localhost for local LLM mocks", () => {
    expect(() => assertAllowedUpstreamTarget("http://127.0.0.1:9/v1")).not.toThrow();
  });
  it("does not set HTTP_PROXY in LLM-scoped child env", () => {
    const env = buildAgentChildEnv("record", "http://127.0.0.1:1234");
    expect(env.HTTP_PROXY).toBeUndefined();
    expect(env.OPENAI_BASE_URL).toBe("http://127.0.0.1:1234");
    expect(env.OLLAMA_HOST).toBe("http://127.0.0.1:1234");
  });
});

describe("cassette path and integrity", () => {
  it("contains cassette paths under cwd", () => {
    const cwd = mkdtempSync(join(tmpdir(), "cassette-root-"));
    const inside = resolveCassettePath("tape.json", cwd);
    expect(inside.startsWith(cwd)).toBe(true);
    expect(() => resolveCassettePath(join("..", "escape.json"), cwd)).toThrow(/stay under/);
    rmSync(cwd, { recursive: true });
  });
  it("fails closed on integrity mismatch in strict mode", () => {
    const entry = {
      method: "POST",
      url: "/v1/chat/completions",
      requestHash: "abc",
      requestBody: "{}",
      responseStatus: 200,
      responseHeaders: {},
      responseBody: "ok",
      entrySha256: "deadbeef",
    };
    expect(() => verifyEntryIntegrity(entry, true)).toThrow(/mismatch/);
    const sealed = { ...entry, entrySha256: computeEntrySha256(entry) };
    expect(() => verifyEntryIntegrity(sealed, true)).not.toThrow();
  });
});

describe("MCP argv (no shell split)", () => {
  beforeEach(() => {
    resetLoopBreaker();
    jsonRpcFrameLog.length = 0;
    hijackStdoutForMcp();
  });
  it("record_agent_run requires argv array", async () => {
    setGuards({ allowWrite: true, dryRun: false });
    dispatchMcpMessage({
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: "record_agent_run", arguments: { cmd: "node -e 1", cassettePath: "x.json" } },
    });
    await new Promise((r) => setTimeout(r, 80));
    const last = JSON.parse(jsonRpcFrameLog.at(-1)!.trim());
    expect(last.result.isError).toBe(true);
    expect(last.result.content[0].text).toMatch(/argv array required/);
  });
  it("accepts argv array in dry-run", () => {
    setGuards({ allowWrite: true, dryRun: true });
    dispatchMcpMessage({
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: {
        name: "record_agent_run",
        arguments: { argv: ["node", "-e", "0"], cassettePath: "tape.json" },
      },
    });
    const last = JSON.parse(jsonRpcFrameLog.at(-1)!.trim());
    expect(last.result.content[0].text).toContain("[dry-run]");
  });
});

describe("MCP + blindajes", () => {
  beforeEach(() => {
    resetLoopBreaker();
    setGuards({ allowWrite: false, dryRun: false });
    jsonRpcFrameLog.length = 0;
    hijackStdoutForMcp();
  });
  it("handshake", () => {
    dispatchMcpMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    dispatchMcpMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    const frames = jsonRpcFrameLog.map((l) => JSON.parse(l.trim()));
    expect(frames[0].result.serverInfo.name).toBe("agent-cassette");
  });
  it("loop breaker and guards", () => {
    expect(guardMutatingTool({ mutates: true }).blocked).toBe(true);
    expect(guardMutatingTool({ annotations: { destructiveHint: true } }).blocked).toBe(true);
    expect(checkLoopBreaker("t", { a: 1 })).toBeNull();
    expect(checkLoopBreaker("t", { a: 1 })).toBeNull();
    expect(checkLoopBreaker("t", { a: 1 })).toMatch(/LOOP_BREAKER/);
  });
  it("paths reasoning tools embed", () => {
    expect(windowsToWsl("D:\\proj\\foo.ts")).toBe("/mnt/d/proj/foo.ts");
    let state = createReasoningState();
    const r1 = applyReasoningContentPolicy(
      [{ role: "user", content: "hi" }, { role: "assistant", content: "ok", reasoning_content: "think", tool_calls: [{}] }],
      state,
    );
    expect(r1.messages[1].reasoning_content).toBe("think");
    state = r1.state;
    const r2 = applyReasoningContentPolicy(
      [...r1.messages, { role: "user", content: "next" }, { role: "assistant", content: "done", reasoning_content: "old" }],
      state,
    );
    expect(r2.messages[1].reasoning_content).toBeUndefined();
    expect(parseDirtyToolCall('<tool_call>{"name":"run","arguments":{"x":1}}</tool_call>')?.name).toBe("run");
    expect(sanitizeRequestBody({ temperature: 0.2, model: "deepseek-reasoner" }, "deepseek-reasoner").temperature).toBeUndefined();
    expect(normalizeToolChoice("required", detectProvider("https://dashscope.aliyuncs.com"))).toBe("auto");
    const norm = Math.hypot(...mrlSlice([3, 4, 0], 2));
    expect(norm).toBeCloseTo(1);
    expect(() => assertDimensionFingerprint({ dimension: 1024 }, 768)).toThrow(/fingerprint/);
  });
});
