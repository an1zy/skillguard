<div align="center">

# skillguard.
### *Сканер безопасности и шлюз перед установкой для AI Agent Skills (`SKILL.md`), `.cursorrules` и MCP-серверов*

[![CI](https://github.com/an1zy/skillguard/actions/workflows/ci.yml/badge.svg?style=for-the-badge)](https://github.com/an1zy/skillguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-18181b.svg?style=for-the-badge)](https://www.python.org/downloads/)
[![Agent Skill](https://img.shields.io/badge/agent_skill-skillguard-18181b.svg?style=for-the-badge)](skills/skillguard/SKILL.md)
[![SkillGuard: VERIFIED](https://img.shields.io/badge/skillguard-VERIFIED_0%25-18181b.svg?style=for-the-badge)](assets/trust-card.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-18181b.svg?style=for-the-badge)](LICENSE)

[English](README.md) · **Русский**

<br/>

<img src="assets/demo.svg" alt="SkillGuard блокирует небезопасный skill" width="840" />

</div>

---

Сторонние `SKILL.md`, `.cursorrules` и пакеты через `npx @scope/mcp-server` запускаются внутри агентов с доступом к shell, `~/.ssh`, `.env` и профилям браузера. **SkillGuard** прогоняет статический аудит до установки или мержа.

## Что проверяет

- **`unicode-smuggling`** (`CRITICAL`): невидимые Unicode-теги (`U+E0000..U+E007F`), bidi-перевороты и скрытые zero-width символы (кроме валидного ZWNJ).
- **`prompt-injection`** (`CRITICAL`): инструкции на перехват поведения и сокрытие действий от пользователя.
- **`credential-harvest`** (`CRITICAL`): обращения к `~/.ssh`, `~/.aws`, `~/.kube`, кукам браузера, локальным токенам Discord, `os.environ` и Telegram `tdata`.
- **`hidden-prompt-comment`** (`HIGH`): скрытые HTML-комментарии `<!-- ... -->` в Markdown с императивными командами.
- **`obfuscated-exec`** (`HIGH`): скачивание и запуск через shell-пайпы, закодированные PowerShell-команды и base64 `eval`/`exec` загрузчики.
- **`exfiltration-sink`** (`HIGH`): вебхуки Discord/Telegram, одноразовые приёмники трафика и публичные raw IPv4-адреса.
- **`unsafe-mcp-config`** (`MEDIUM/HIGH`): незакреплённый `npx -y` без версии, пайпы в `args` и зашитые токены в `.mcp.json`.

## Быстрый старт

```bash
pip install -e .

# Проверить внешний репозиторий перед npx skills add
skillguard install owner/repo --max-risk 20

# Прямой аудит папки или GitHub-репозитория
skillguard scan owner/repo

# Аудит локальных конфигов агентов (~/.claude, ~/.cursor, ~/.gemini, .mcp.json)
skillguard audit-local

# SVG-карточка и JSON-отчёт
skillguard scan . --svg assets/trust-card.svg --title "owner/repo"
skillguard scan . --json
```

## Аудит 27 публичных MCP и Skill-репозиториев (10,849 файлов)

<p align="center">
  <img src="assets/benchmark.svg" alt="Аудит 27 публичных репозиториев" width="840" />
</p>

- **20 / 27 (74.1%) получили `0% VERIFIED`** (`modelcontextprotocol/servers`, `microsoft/playwright-mcp`, `ChromeDevTools/chrome-devtools-mcp`, `anthropics/skills`, `vercel-labs/skills`, `apify/apify-mcp-server`, `an1zy/vram-fit`, `an1zy/slopcheck` и др.).
- **В 7 / 27 сработали статические эвристики риска** (`82` `obfuscated-exec`, `15` `prompt-injection`, `8` `hidden-prompt-comment`, `7` `credential-harvest`, `4` `unicode-smuggling`, `2` `unsafe-mcp-config` — это сигналы по паттернам вроде curl-установщиков и security-скиллов, не обвинение авторов).

## Лицензия

MIT © 2026 [an1zy](https://github.com/an1zy)
