# Project skills and tools

For CTF work, read `.agents/skills/solve-challenge/SKILL.md` when the category
is unclear, or the relevant `.agents/skills/ctf-*/SKILL.md` when it is known.
Load only the references needed for the current challenge. Use `ctf-writeup`
when documenting a solution. Install category prerequisites on demand; the
upstream tool installer is `.tools/ctf/ctf-skills/scripts/install_ctf_tools.sh`.

Apply `.agents/skills/ponytail/SKILL.md` to coding work: reuse existing helpers,
prefer the standard library, and keep changes small without cutting validation.

For large or repeated file operations, read
`.agents/skills/token-optimization/SKILL.md`. Use Token Optimizer only when its
tools are actually registered; otherwise use bounded native reads and searches.
The project MCP configuration is `.codex/config.toml` for Codex and `.mcp.json`
for Claude-compatible clients. Keep caches in `.tools/ctf/state` or
`.token-optimizer`.

Tool sources are project-local under `.tools/ctf/`. See `tools/CTF-SETUP.md`
for installed versions, verification, and the AI Security Tool installation gap.
