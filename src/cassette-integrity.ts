import { createHash } from "node:crypto";
import { canonicalizeJson } from "./prompt-hasher.js";
import type { SseEvent } from "./sse-replayer.js";

export type CassetteEntryCore = {
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

export type SealedCassetteEntry = CassetteEntryCore & { entrySha256: string };

const SENSITIVE_HEADER_KEYS = new Set(["authorization", "proxy-authorization", "x-api-key", "api-key"]);

export function stripSensitiveHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!SENSITIVE_HEADER_KEYS.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function entryCanonicalPayload(entry: CassetteEntryCore): string {
  const payload = {
    method: entry.method,
    url: entry.url,
    requestHash: entry.requestHash,
    requestBody: entry.requestBody,
    responseStatus: entry.responseStatus,
    responseHeaders: stripSensitiveHeaders(entry.responseHeaders),
    responseBody: entry.responseBody,
    sseEvents: entry.sseEvents,
    isEmbedding: entry.isEmbedding ?? false,
  };
  return canonicalizeJson(payload, false);
}

export function computeEntrySha256(entry: CassetteEntryCore): string {
  return createHash("sha256").update(entryCanonicalPayload(entry)).digest("hex");
}

export function sealEntry(entry: CassetteEntryCore): SealedCassetteEntry {
  const entrySha256 = computeEntrySha256(entry);
  return { ...entry, entrySha256 };
}

export function verifyEntryIntegrity(entry: CassetteEntryCore, strict = true): void {
  if (!entry.entrySha256) {
    if (strict) throw new Error("Cassette entry missing entrySha256 (strict integrity)");
    return;
  }
  const expected = computeEntrySha256(entry);
  if (expected !== entry.entrySha256) {
    throw new Error("Cassette entry integrity mismatch (strict)");
  }
}
