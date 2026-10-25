import { createHash } from "node:crypto";
import { canonicalizeJson, diffSemantic } from "./prompt-hasher.js";
import { loadCassette, recordAgentRun, replayAgentRun } from "./http-vcr-proxy.js";
export { canonicalizeJson, headTailTruncate, diffSemantic, anchorToolsAtTail, hashPrompt, redactSecrets, } from "./prompt-hasher.js";
import { headTailTruncate, redactSecrets } from "./prompt-hasher.js";
export const DEFAULT_N_CTX = 4096;
export const KNOWN_DIMENSIONS = [384, 768, 1024, 1536, 2560, 3072, 4096];

export function toolOutputBudgetChars(nCtx: number, charsPerToken = 4): number {
    return Math.floor(nCtx * charsPerToken * 0.3);
}
export function truncateToolOutput(text: string, nCtx?: number): string {
    return headTailTruncate(String(text), toolOutputBudgetChars(nCtx ?? DEFAULT_N_CTX));
}
export function finalizeMcpToolText(text: string, opts?: { nCtx?: number; toWsl?: boolean }): string {
    const nCtx = opts?.nCtx ?? DEFAULT_N_CTX;
    const toWsl = opts?.toWsl ?? false;
    return String(normalizePathsDeep(redactSecrets(truncateToolOutput(String(text), nCtx)), !toWsl));
}
export function l2Normalize(vec: number[]): number[] {
    let sum = 0;
    for (const v of vec)
        sum += v * v;
    const norm = Math.sqrt(sum) || 1;
    return vec.map((v) => v / norm);
}
export function mrlSlice(vec: number[], dimensions: number): number[] {
    return l2Normalize(vec.slice(0, dimensions));
}
export function floatArrayToBase64(vec: number[]): string {
    const buf = Buffer.alloc(vec.length * 4);
    for (let i = 0; i < vec.length; i++)
        buf.writeFloatLE(vec[i], i * 4);
    return buf.toString("base64");
}
export function base64ToFloatArray(b64: string): number[] {
    const buf = Buffer.from(b64, "base64");
    const out = [];
    for (let i = 0; i < buf.length; i += 4)
        out.push(buf.readFloatLE(i));
    return out;
}
export function assertDimensionFingerprint(lock: { dimension: number } | null | undefined, dim: number): void {
    if (!lock)
        return;
    if (lock.dimension !== dim) {
        throw new Error(`Dimension fingerprint mismatch: lock expects ${lock.dimension}, got ${dim}`);
    }
}
function chunkArray<T>(arr: T[], size: number): T[][] {
    const out = [];
    for (let i = 0; i < arr.length; i += size)
        out.push(arr.slice(i, i + size));
    return out;
}
export type EmbedUpstream = {
    maxBatch: number;
    embed: (texts: string[], model: string, dimensions?: number) => Promise<number[][]>;
};

export async function normalizeEmbedBatch(
    inputs: string[],
    options: {
        dimensions?: number;
        model: string;
        upstream: EmbedUpstream;
        lock?: { dimension: number } | null;
    },
): Promise<{ embeddings: number[][]; indices: number[] }> {
    const dimensions = options.dimensions;
    const indexed = inputs.map((text, i) => ({ text, i }));
    const nonEmpty = indexed.filter((x) => x.text.trim().length > 0);
    const batches = chunkArray(nonEmpty, options.upstream.maxBatch);
    const vectors = new Map();
    for (const batch of batches) {
        const texts = batch.map((b) => b.text);
        const got = await options.upstream.embed(texts, options.model, dimensions);
        for (let j = 0; j < batch.length; j++) {
            let vec = got[j] ?? [];
            if (dimensions && vec.length > dimensions)
                vec = mrlSlice(vec, dimensions);
            else if (dimensions && vec.length === dimensions)
                vec = l2Normalize(vec);
            if (dimensions)
                assertDimensionFingerprint(options.lock ?? null, vec.length);
            vectors.set(batch[j].i, vec);
        }
    }
    const dim = dimensions ?? (vectors.values().next().value?.length ?? 0);
    const embeddings = [];
    const indices = [];
    for (let i = 0; i < inputs.length; i++) {
        indices.push(i);
        embeddings.push(vectors.get(i) ?? new Array(dim).fill(0));
    }
    return { embeddings, indices };
}
let allowWrite = false;
let dryRun = false;
export function setGuards(opts: { allowWrite?: boolean; dryRun?: boolean }): void {
    allowWrite = Boolean(opts.allowWrite);
    dryRun = Boolean(opts.dryRun);
}
export function loopBreakerHash(toolName: string, args: unknown): string {
    return createHash("sha256").update(`${toolName}:${canonicalizeJson(args)}`).digest("hex");
}
const loopState = { lastHash: "", repeatCount: 0 };
export function resetLoopBreaker() {
    loopState.lastHash = "";
    loopState.repeatCount = 0;
}
export function checkLoopBreaker(toolName: string, args: unknown): string | null {
    const h = loopBreakerHash(toolName, args);
    if (h === loopState.lastHash)
        loopState.repeatCount++;
    else {
        loopState.lastHash = h;
        loopState.repeatCount = 1;
    }
    if (loopState.repeatCount >= 3) {
        return "LOOP_BREAKER: Identical tool call repeated 2 times consecutively. Stop calling tools and return your final synthesis.";
    }
    return null;
}
export type McpToolDef = {
    name: string;
    description?: string;
    inputSchema?: Record<string, unknown>;
    mutates?: boolean;
    annotations?: { destructiveHint?: boolean };
};

export function guardMutatingTool(tool?: McpToolDef): { blocked: boolean; reason?: string } {
    if (!(tool?.mutates || tool?.annotations?.destructiveHint))
        return { blocked: false };
    if (dryRun)
        return { blocked: false };
    if (!allowWrite) {
        return { blocked: true, reason: "Read-only mode: pass --allow-write to enable mutating tools." };
    }
    return { blocked: false };
}
const WIN_DRIVE_RE = /^([A-Za-z]):\\(.*)$/;
const WSL_RE = /^\/mnt\/([a-z])\/(.*)$/i;
export function windowsToWsl(p: string): string {
    const m = p.match(WIN_DRIVE_RE);
    if (!m)
        return p;
    return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}`;
}
export function wslToWindows(p: string): string {
    const m = p.match(WSL_RE);
    if (!m)
        return p;
    return `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, "\\")}`;
}
export function normalizePathsDeep(value: unknown, toWsl: boolean): unknown {
    if (typeof value === "string") {
        if (toWsl && WIN_DRIVE_RE.test(value))
            return windowsToWsl(value);
        if (!toWsl && WSL_RE.test(value))
            return wslToWindows(value);
        return value;
    }
    if (Array.isArray(value))
        return value.map((v) => normalizePathsDeep(v, toWsl));
    if (value && typeof value === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>))
            out[k] = normalizePathsDeep(v, toWsl);
        return out;
    }
    return value;
}
let jsonRpcWrite: ((line: string) => void) | null = null;
let stdoutHijacked = false;
export function hijackStdoutForMcp() {
    if (stdoutHijacked)
        return;
    stdoutHijacked = true;
    const native = process.stdout.write.bind(process.stdout);
    jsonRpcWrite = (line) => native(line);
    const hijackedWrite: typeof process.stdout.write = (...args) => {
        const chunk = args[0];
        const str = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString();
        if (str.trim().startsWith("{") && str.includes('"jsonrpc"')) {
            return Reflect.apply(native, process.stdout, args);
        }
        process.stderr.write(str);
        return true;
    };
    process.stdout.write = hijackedWrite;
}
export const jsonRpcFrameLog: string[] = [];
export function writeJsonRpcFrame(obj: Record<string, unknown>): void {
    const line = JSON.stringify(obj) + "\n";
    jsonRpcFrameLog.push(line);
    if (jsonRpcWrite)
        jsonRpcWrite(line);
    else
        process.stdout.write(line);
}
export type JsonRpcMessage = {
    jsonrpc?: string;
    id?: string | number | null;
    method?: string;
    params?: { name?: string; arguments?: Record<string, unknown> };
};

export type McpServerOpts = {
    tools?: McpToolDef[];
    handlers?: Record<string, (args: Record<string, unknown>) => Promise<unknown>>;
    pathToWsl?: boolean;
};

export function dispatchMcpMessage(msg: JsonRpcMessage, opts: McpServerOpts = {}): void {
    const tools = opts.tools ?? defaultTools();
    const handlers = opts.handlers ?? {};
    const toWsl = opts.pathToWsl ?? false;
    handleMessage(msg, tools, handlers, toWsl);
}
function defaultTools(): McpToolDef[] {
    return [
        {
            name: "record_agent_run",
            description: "Record HTTP/SSE from an agent command into a cassette.",
            inputSchema: {
                type: "object",
                properties: {
                    argv: { type: "array", items: { type: "string" } },
                    cassettePath: { type: "string" },
                },
                required: ["argv", "cassettePath"],
            },
            mutates: true,
        },
        {
            name: "replay_agent_run",
            description: "Replay a cassette with zero network (strict).",
            inputSchema: {
                type: "object",
                properties: {
                    argv: { type: "array", items: { type: "string" } },
                    cassettePath: { type: "string" },
                },
                required: ["argv", "cassettePath"],
            },
        },
        {
            name: "diff_cassette_drift",
            description: "Show semantic prompt drift vs stored cassette hashes.",
            inputSchema: {
                type: "object",
                properties: { cassettePath: { type: "string" }, liveBody: { type: "object" } },
                required: ["cassettePath"],
            },
        },
    ];
}
function handleMessage(
    msg: JsonRpcMessage,
    tools: McpToolDef[],
    handlers: Record<string, (args: Record<string, unknown>) => Promise<unknown>>,
    toWsl: boolean,
): void {
    const { id, method, params } = msg;
    if (method === "initialize") {
        writeJsonRpcFrame({
            jsonrpc: "2.0",
            id,
            result: {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {} },
                serverInfo: { name: "agent-cassette", version: "0.1.0" },
            },
        });
        return;
    }
    if (method === "notifications/initialized")
        return;
    if (method === "tools/list") {
        writeJsonRpcFrame({
            jsonrpc: "2.0",
            id,
            result: {
                tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
            },
        });
        return;
    }
    if (method === "tools/call") {
        const name = params?.name;
        const args = normalizePathsDeep(params?.arguments ?? {}, toWsl) as Record<string, unknown>;
        const tool = tools.find((t) => t.name === name);
        const loopErr = checkLoopBreaker(name ?? "", args);
        if (loopErr) {
            writeJsonRpcFrame({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: loopErr }], isError: true } });
            return;
        }
        const guard = guardMutatingTool(tool);
        if (guard.blocked) {
            writeJsonRpcFrame({
                jsonrpc: "2.0",
                id,
                result: { content: [{ type: "text", text: guard.reason ?? "blocked" }], isError: true },
            });
            return;
        }
        if (dryRun) {
            writeJsonRpcFrame({
                jsonrpc: "2.0",
                id,
                result: { content: [{ type: "text", text: `[dry-run] Would call ${name}` }] },
            });
            return;
        }
        const handler = handlers[name ?? ""] ?? builtInHandler(name ?? "");
        void (async () => {
            try {
                const result = await handler(args);
                const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
                writeJsonRpcFrame({
                    jsonrpc: "2.0",
                    id,
                    result: {
                        content: [{ type: "text", text: finalizeMcpToolText(text, { nCtx: DEFAULT_N_CTX, toWsl }) }],
                    },
                });
            }
            catch (e) {
                writeJsonRpcFrame({
                    jsonrpc: "2.0",
                    id,
                    result: {
                        content: [{ type: "text", text: finalizeMcpToolText(String(e), { nCtx: DEFAULT_N_CTX, toWsl }) }],
                        isError: true,
                    },
                });
            }
        })();
        return;
    }
    if (id !== undefined) {
        writeJsonRpcFrame({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
}
function argvFromMcpArgs(args: Record<string, unknown>): { bin: string; rest: string[] } {
    if (!Array.isArray(args.argv)) {
        throw new Error("argv array required (shell:false, no whitespace split)");
    }
    const argv = args.argv.map((v) => String(v));
    if (argv.length < 1) throw new Error("argv must include the command");
    const [bin, ...rest] = argv;
    return { bin, rest };
}

function builtInHandler(name: string): (args: Record<string, unknown>) => Promise<unknown> {
    if (name === "record_agent_run") {
        return async (args) => {
            const { bin, rest } = argvFromMcpArgs(args);
            const r = await recordAgentRun(bin, rest, String(args.cassettePath), allowWrite);
            return { ok: true, exitCode: r.exitCode };
        };
    }
    if (name === "replay_agent_run") {
        return async (args) => {
            const { bin, rest } = argvFromMcpArgs(args);
            const r = await replayAgentRun(bin, rest, String(args.cassettePath));
            return { ok: true, exitCode: r.exitCode };
        };
    }
    if (name === "diff_cassette_drift") {
        return async (args) => {
            const cassette = loadCassette(String(args.cassettePath));
            const live = args.liveBody ?? {};
            const drifts: { url: string; lines: ReturnType<typeof diffSemantic> }[] = [];
            for (const entry of cassette.entries) {
                let stored: unknown = {};
                try {
                    stored = JSON.parse(entry.requestBody);
                }
                catch {
                    stored = entry.requestBody;
                }
                const lines = diffSemantic(stored, live, 4096);
                if (lines.length)
                    drifts.push({ url: entry.url, lines });
            }
            return { drifts };
        };
    }
    return async () => ({ ok: false });
}
export function startMcpServer(opts: McpServerOpts = {}): void {
    hijackStdoutForMcp();
    const stdin = process.stdin;
    stdin.setEncoding("utf8");
    let buffer = "";
    stdin.on("data", (chunk) => {
        buffer += chunk;
        let idx;
        while ((idx = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, idx).trim();
            buffer = buffer.slice(idx + 1);
            if (!line)
                continue;
            try {
                dispatchMcpMessage(JSON.parse(line), opts);
            }
            catch {
                /* skip */
            }
        }
    });
}
export type ChatMessage = {
    role: string;
    content?: string;
    reasoning_content?: string;
    tool_calls?: unknown[];
};

export type ReasoningState = { inToolLoop: boolean };

export function createReasoningState(): ReasoningState {
    return { inToolLoop: false };
}
export function applyReasoningContentPolicy(
    messages: ChatMessage[],
    state: ReasoningState,
): { messages: ChatMessage[]; state: ReasoningState } {
    const out = messages.map((m) => ({ ...m }));
    const userIndices = out.map((m, i) => (m.role === "user" ? i : -1)).filter((i) => i >= 0);
    const lastUser = userIndices[userIndices.length - 1];
    for (const m of out) {
        if (m.role === "assistant" && m.tool_calls)
            state.inToolLoop = true;
    }
    if (userIndices.length > 1) {
        for (let i = 0; i < lastUser; i++) {
            if (out[i].role === "assistant" && out[i].reasoning_content) {
                delete out[i].reasoning_content;
            }
        }
        state.inToolLoop = false;
    }
    return { messages: out, state };
}
export function stripRedactedThinking(text: string): string {
    return text.replace(/<think>[\s\S]*?<\/redacted_thinking>/g, "").trim();
}
export function parseDirtyToolCall(raw: string): { name: string; arguments: Record<string, unknown> } | null {
    const cleaned = stripRedactedThinking(raw);
    const hermes = cleaned.match(/<tool_call>\s*(\{[\s\S]*?\})\s*<\/tool_call>/);
    if (hermes) {
        try {
            const j = JSON.parse(hermes[1]);
            return { name: j.name, arguments: j.arguments ?? {} };
        }
        catch {
            /* continue */
        }
    }
    const qwen = cleaned.match(/✿FUNCTION✿:\s*(\S+)[\s\S]*?✿ARGS✿:\s*(\{[\s\S]*?\})/);
    if (qwen) {
        try {
            return { name: qwen[1], arguments: JSON.parse(qwen[2].replace(/'/g, '"')) };
        }
        catch {
            /* continue */
        }
    }
    const kimi = cleaned.match(/functions\.([^:<]+)/);
    const kimiArgs = cleaned.match(/\{[\s\S]*\}/);
    if (kimi && kimiArgs) {
        try {
            return { name: kimi[1], arguments: JSON.parse(kimiArgs[0].replace(/'/g, '"')) };
        }
        catch {
            /* continue */
        }
    }
    try {
        const j = JSON.parse(cleaned.replace(/'/g, '"'));
        if (j.cmd)
            return { name: "tool", arguments: j };
    }
    catch {
        /* */
    }
    return null;
}
export function sanitizeRequestBody(body: Record<string, unknown>, model: string): Record<string, unknown> {
    const out = { ...body };
    if (String(model).includes("reasoner") || String(model).includes("r1")) {
        delete out.temperature;
        delete out.top_p;
    }
    return out;
}
export function detectProvider(baseUrl: string): string {
    if (baseUrl.includes("dashscope"))
        return "dashscope";
    if (baseUrl.includes("deepseek"))
        return "deepseek";
    return "openai";
}
export function normalizeToolChoice(choice: string, provider: string): string {
    if (provider === "dashscope" && choice === "required")
        return "auto";
    return choice;
}