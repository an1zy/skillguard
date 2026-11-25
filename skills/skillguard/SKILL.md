---
name: skillguard
description: Security scanner and pre-install audit gate for AI Agent Skills (SKILL.md), rules files, and MCP servers.
---

# SkillGuard Agent Skill

Audit third-party skills, MCP configs, or local rule files before installing or executing them.

## Usage

```bash
uvx skillguard scan owner/repo
uvx skillguard install owner/repo
uvx skillguard audit-local
```

## Security Checks

- `unicode-smuggling`: invisible Unicode Tag blocks (`U+E0000..U+E007F`), bidi controls, zero-width clusters.
- `hidden-prompt-comment`: hidden markdown HTML comments containing imperative commands.
- `prompt-injection`: instructions attempting to hide actions from the user or hijack tool calls.
- `credential-harvest`: unauthorized access to host SSH keys, cloud credentials, `.env` dumps, browser cookie stores, or messaging session vaults.
- `exfiltration-sink` / `obfuscated-exec` / `unsafe-mcp-config`: capture webhooks, `curl | sh`, unpinned `npx -y`, plaintext keys.
