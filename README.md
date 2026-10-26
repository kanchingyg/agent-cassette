# agent-cassette

[![ci](https://github.com/kanchingyg/agent-cassette/actions/workflows/ci.yml/badge.svg)](https://github.com/kanchingyg/agent-cassette/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40kanchingyg%2Fagent-cassette/latest?label=npm)](https://www.npmjs.com/package/@kanchingyg/agent-cassette)
[![JSR](https://jsr.io/badges/@kanchingyg/agent-cassette)](https://jsr.io/@kanchingyg/agent-cassette)
[![JSR Score](https://jsr.io/badges/@kanchingyg/agent-cassette/score)](https://jsr.io/@kanchingyg/agent-cassette/score)
[![Runtime](https://img.shields.io/badge/runtime-Node_%7C_Bun_%7C_Deno-f9f1e1)](https://github.com/kanchingyg/agent-cassette)
[![license](https://img.shields.io/github/license/kanchingyg/agent-cassette)](https://github.com/kanchingyg/agent-cassette/blob/HEAD/LICENSE)
[![npm](https://img.shields.io/npm/v/agent-cassette)](https://www.npmjs.com/package/@kanchingyg/agent-cassette)
[![JSR](https://jsr.io/badges/@kanchingyg/agent-cassette)](https://jsr.io/@kanchingyg/agent-cassette)
[![Bun](https://img.shields.io/badge/runtime-Node_%7C_Bun-f9f1e1)](https://github.com/kanchingyg/agent-cassette)
[![license](https://img.shields.io/github/license/kanchingyg/agent-cassette)](https://github.com/kanchingyg/agent-cassette/blob/HEAD/LICENSE)

Deterministic VCR cassette recorder and offline replay proxy for LLM HTTP/SSE streams and MCP stdio runs. Replay multi-turn agent tests in ~0ms in CI without GPUs or live API keys.

## Install

[Bun](https://bun.sh) / [npm](https://www.npmjs.com/package/@kanchingyg/agent-cassette):

```bash
bunx @kanchingyg/agent-cassette record -- npm test
npx @kanchingyg/agent-cassette record -- npm test

# or install in your project / globally
bun add -d @kanchingyg/agent-cassette
npm i -D @kanchingyg/agent-cassette
```

[JSR](https://jsr.io/@kanchingyg/agent-cassette):

```bash
bunx jsr add @kanchingyg/agent-cassette
npx jsr add @kanchingyg/agent-cassette
```

## Quick start

```bash
# Record live LLM HTTP/SSE and MCP interactions into a deterministic cassette
npx @kanchingyg/agent-cassette record -- npm test
bunx @kanchingyg/agent-cassette record -- bun test

# Replay offline in CI in ~0ms with zero network calls or API keys
npx @kanchingyg/agent-cassette replay -- npm test

# Run as an MCP server over stdio
npx @kanchingyg/agent-cassette --mcp
```

## Features

- **HTTP & SSE stream recording**: Captures chunked token streams from OpenAI, Anthropic, Ollama, and OpenAI-compatible endpoints and replays them deterministically.
- **Prompt & tool-call hashing**: Normalizes volatile headers and timestamps while matching prompt and tool-call signatures.
- **Automatic secret scrubbing**: Strips `Authorization`, `x-api-key`, and bearer tokens before writing cassette files to disk.
- **SSRF & path containment**: Blocks private-network target redirection and enforces workspace path containment on cassette reads/writes.

## MCP setup

```json
{
  "mcpServers": {
    "agent-cassette": {
      "command": "npx",
      "args": ["-y", "@kanchingyg/agent-cassette", "--mcp"]
    }
  }
}
```

## MCP Tools Reference

| Tool | Mutates | Description |
| --- | --- | --- |
| `inspect_cassette` | `false` | Inspect recorded HTTP, SSE, and MCP interactions inside a cassette JSON file with secret scrubbing. |
| `diff_cassette_runs` | `false` | Compute semantic prompt and tool-call drift between two recorded agent cassettes. |
| `prune_cassette` | `true` | Remove stale entries from a cassette file on disk (requires `--allow-write`). |

## Editor and Agent Integration

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "agent-cassette": {
      "command": "npx",
      "args": ["-y", "@kanchingyg/agent-cassette", "--mcp"]
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add agent-cassette -- npx -y @kanchingyg/agent-cassette --mcp
```

### Programmatic Usage (JSR / TypeScript)

```ts
import * as bridge from "jsr:@kanchingyg/agent-cassette/bridge";
```

## Runtime Safety and Guardrails

- **Stdio frame isolation**: When `--mcp` is active, `hijackStdoutForMcp()` redirects accidental `console.log` calls to `stderr` so JSON-RPC 2.0 frames on `stdout` never corrupt.
- **Read-only by default**: Mutating tools (`mutates: true`) are blocked in `--dry-run` mode and require explicit `--allow-write` authorization.
- **Loop breaker**: Repeated identical `(toolName, args)` invocations are hashed with SHA-256 and halted after 3 consecutive repeats to prevent runaway agent loops.
- **Context budget truncation**: Tool outputs are middle-truncated (`60%` head / `40%` tail) scaled to the probed local model `n_ctx` (Ollama `/api/show`, llama.cpp `/props`, vLLM `/v1/models`).
- **Secret redaction and path normalization**: AWS keys (`AKIA*`, `ASIA*`), bearer tokens, and `sk-*` keys are scrubbed before returning tool output, and Windows drive paths (`C:\...`) translate cleanly to `/mnt/c/...` when WSL mode is enabled.

## License

[MIT](./LICENSE)
