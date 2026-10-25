import { createHash } from "node:crypto";

export const EPHEMERAL_KEYS = new Set([
  "id",
  "created",
  "created_at",
  "timestamp",
  "request_id",
  "x-request-id",
  "seed",
  "system_fingerprint",
]);

const SECRET_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/g,
  /Bearer\s+[a-zA-Z0-9._-]+/gi,
  /api[_-]?key["\s:=]+["']?[a-zA-Z0-9._-]{8,}/gi,
];

export function redactSecrets(text: string): string {
  let out = text;
  for (const re of SECRET_PATTERNS) out = out.replace(re, "[REDACTED]");
  return out;
}

export function canonicalizeJson(value: unknown, stripEphemeral = true): string {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalizeJson(v, stripEphemeral)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => !stripEphemeral || !EPHEMERAL_KEYS.has(k))
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k], stripEphemeral)}`).join(",")}}`;
}

export function hashPrompt(body: unknown): string {
  return createHash("sha256").update(canonicalizeJson(body, true)).digest("hex");
}

export const TRUNC_MARKER = "[...TRUNCATED BY AGENT-CASSETTE...]";

export function headTailTruncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const headLen = Math.floor(maxChars * 0.6);
  const tailLen = Math.floor(maxChars * 0.4) - TRUNC_MARKER.length;
  return text.slice(0, headLen) + TRUNC_MARKER + text.slice(-tailLen);
}

export type DriftLine = { path: string; before: string; after: string };

export function diffSemantic(before: unknown, after: unknown, nCtx = 4096): DriftLine[] {
  const maxChars = Math.max(200, Math.floor(nCtx * 0.5));
  const b = canonicalizeJson(before, true);
  const a = canonicalizeJson(after, true);
  if (b === a) return [];
  if (b.length > maxChars || a.length > maxChars) {
    return [{ path: "$", before: headTailTruncate(b, maxChars), after: headTailTruncate(a, maxChars) }];
  }
  return [{ path: "$", before: b, after: a }];
}

export function anchorToolsAtTail(prompt: string, toolSig: string): string {
  const marker = "ASSISTANT:";
  const idx = prompt.lastIndexOf(marker);
  if (idx < 0) return `${prompt}\n${toolSig}`;
  return prompt.slice(0, idx) + toolSig + "\n" + prompt.slice(idx);
}
