#!/usr/bin/env node
import { recordAgentRun, replayAgentRun } from "./http-vcr-proxy.js";
import { setGuards, startMcpServer } from "./bridge.js";

function parseArgv(argv: string[]) {
  let mode: "record" | "replay" | "mcp" | "help" = "help";
  let allowWrite = false;
  let dryRun = false;
  const rest: string[] = [];
  let afterDash = false;
  for (const a of argv) {
    if (a === "--") {
      afterDash = true;
      continue;
    }
    if (!afterDash) {
      if (a === "record") mode = "record";
      else if (a === "replay") mode = "replay";
      else if (a === "--mcp") mode = "mcp";
      else if (a === "--allow-write") allowWrite = true;
      else if (a === "--dry-run") dryRun = true;
      else if (a === "--help" || a === "-h") mode = "help";
      else rest.push(a);
    } else rest.push(a);
  }
  return { mode, allowWrite, dryRun, cmd: rest };
}

function printHelp(): void {
  process.stderr.write(
    "agent-cassette — VCR for LLM HTTP/SSE and MCP stdio\n\n" +
      "  npx agent-cassette record -- <cmd...>\n" +
      "  npx agent-cassette replay -- <cmd...>\n" +
      "  npx agent-cassette --mcp\n",
  );
}

async function main(): Promise<void> {
  const { mode, allowWrite, dryRun, cmd } = parseArgv(process.argv.slice(2));
  if (mode === "help") {
    printHelp();
    process.exit(cmd.length ? 2 : 0);
  }
  if (mode === "mcp") {
    setGuards({ allowWrite, dryRun });
    startMcpServer();
    return;
  }
  const cassettePath = process.env.AGENT_CASSETTE_PATH ?? "cassette.json";
  if (cmd.length < 1) {
    printHelp();
    process.exit(2);
  }
  const [bin, ...args] = cmd;
  if (mode === "record") process.exit((await recordAgentRun(bin, args, cassettePath, allowWrite)).exitCode ?? 1);
  if (mode === "replay") process.exit((await replayAgentRun(bin, args, cassettePath)).exitCode ?? 1);
}

const isMain = process.argv[1]?.includes("cli") || process.argv[1]?.endsWith("agent-cassette");
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });

export type { DriftLine } from "./prompt-hasher.js";
