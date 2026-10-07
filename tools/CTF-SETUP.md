# Project CTF tooling

Installed on 2026-10-02 for this repository. Codex loads 18 skills from
`.agents/skills/`, including 11 `ljagiello/ctf-skills` skills, six Ponytail
skills, and Token Optimizer's skill. The CTF collection is also available to
Claude in the existing `.claude/skills/` directory. The project MCP files are
`.codex/config.toml` and `.mcp.json`; the existing `graft` entry remains.

Sources are in `.tools/ctf/`:

| Source | Revision | State |
| --- | --- | --- |
| `DietrichGebert/ponytail` | `e3ba2aa6f1e6f0bc4d69eb09c9f0d0a93af56156` | Skills installed |
| `ljagiello/ctf-skills` | `c332c7be1b27cb64639a20124ac55ba916adef92` | Skills installed |
| `ooples/token-optimizer-mcp` | `011904cadab253fc4a4762a7b05af522acaf67d3` | Local dependencies and MCP build installed; `node tools/check-ctf-tools.mjs` verifies it |
| `ZeroDayEvil/ai-security-tool` | `b14b28b357c78f46cb5a4f7ccd92c98c8aaf44f9` | Source retained, not runnable: `main.js` imports missing `services/*`, and `scripts/one-line-web.sh` contains only `bbvb` |

The Token Optimizer source has three small local path changes so its database,
configuration, and session files live under `.tools/ctf/state/`. Its graph cache
is `.token-optimizer/`. The source and runtime caches are ignored by Git.
Restart Codex or Claude to load added skills
and MCP servers. Use `node tools/check-ctf-tools.mjs` to verify the MCP handshake.
