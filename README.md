# agent-cassette

Deterministic VCR for LLM HTTP/SSE and MCP stdio — replay agent tests in ~0ms with no GPU or API keys in CI.

```bash
npx agent-cassette record -- npm test
npx agent-cassette replay -- npm test
npx agent-cassette --mcp
```

See `SKILL.md` for MCP tool names and Cursor registration.

MIT
