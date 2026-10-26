---
name: agent-cassette
description: Record and replay LLM HTTP/SSE and MCP traffic as deterministic cassettes for 0ms CI.
---

# agent-cassette

- `npx @kanchingyg/agent-cassette record -- <cmd>` / `replay -- <cmd>` / `--mcp`
- MCP tools: `record_agent_run`, `replay_agent_run`, `diff_cassette_drift`
- Mutating tools need `--allow-write`
