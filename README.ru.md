<div align="center">

# SkillGuard

**Сканер безопасности, шлюз перед установкой и GitHub Action для AI Agent Skills (`SKILL.md`), `.cursorrules` и MCP-серверов.**

[![CI](https://github.com/an1zy/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/an1zy/skillguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![Agent Skill](https://img.shields.io/badge/agent_skill-skillguard-purple.svg?style=flat-square)](skills/skillguard/SKILL.md)
[![SkillGuard: VERIFIED](https://img.shields.io/badge/skillguard-VERIFIED_0%25-brightgreen.svg?style=flat-square)](assets/trust-card.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)

[English](README.md) · **Русский**

<br/>

<img src="assets/demo.svg" alt="SkillGuard блокирует вредоносный skill" width="840" />

</div>

---

## Зачем нужен SkillGuard?

Разработчики вслепую запускают `npx skills add <user/repo>`, `npx @random/mcp-server` и вставляют сторонние `SKILL.md` / `.cursorrules` в агентов с доступом к терминалу, `~/.ssh`, `.env` ключам, кукам браузера и сессиям мессенджеров.

**SkillGuard** проверяет Agent Skills и MCP-репозитории **до** установки и запуска:

- **`unicode-smuggling`** (`CRITICAL`): невидимые Unicode-теги (`U+E0000..U+E007F`), bidi-перевороты и скрытые zero-width символы.
- **`prompt-injection`** (`CRITICAL`): попытки скрыть действия от пользователя или перехватить вызовы инструментов.
- **`credential-harvest`** (`CRITICAL`): обращения к `~/.ssh`, `~/.aws`, `~/.kube`, кукам браузера, локальным токенам Discord, дампам `os.environ` и Telegram `tdata`.
- **`hidden-prompt-comment`** (`HIGH`): скрытые HTML-комментарии `<!-- ... -->` в Markdown с инструкциями на кражу данных.
- **`obfuscated-exec`** (`HIGH`): скачивание и запуск скриптов через shell-пайпы, закодированные PowerShell-команды и base64-декодируемые `eval`/`exec` загрузчики.
- **`exfiltration-sink`** (`HIGH`): вебхуки Discord/Telegram, одноразовые туннели (`webhook.site`, `ngrok`) и публичные raw IP-эндпоинты (localhost/private исключены).
- **`unsafe-mcp-config`** (`MEDIUM/HIGH`): незакреплённый `npx -y` без версии, shell-пайпы и зашитые API-ключи в `.mcp.json`.

---

## Быстрый старт

```bash
pip install -e .

# Проверить чужой репо перед установкой через npx skills add
skillguard install owner/repo --max-risk 20

# Прямой аудит локальной папки или GitHub-репозитория
skillguard scan owner/repo

# Аудит всех локальных скиллов и MCP-конфигов на компьютере
skillguard audit-local

# Генерация SVG-карточки доверия и JSON-отчёта
skillguard scan . --svg assets/trust-card.svg --title "owner/repo"
skillguard scan . --json
```

---

## Аудит 27 публичных MCP и Skill-репозиториев (10,849 файлов)

<p align="center">
  <img src="assets/benchmark.svg" alt="Аудит 27 публичных MCP/Skill-репозиториев" width="840" />
</p>

- **20 из 27 репозиториев (74.1%) получили `0% VERIFIED`** — включая `modelcontextprotocol/servers`, `microsoft/playwright-mcp`, `ChromeDevTools/chrome-devtools-mcp`, `anthropics/skills`, `vercel-labs/skills`, `apify/apify-mcp-server`, `cloudflare/mcp-server-cloudflare` и `an1zy/vram-fit`.
- **7 из 27 репозиториев** содержали срабатывания на потенциально рискованные паттерны (установщики `curl | bash`, незакреплённые `npx -y` в конфигах, промпты/тесты в security-скиллах).

---

## Лицензия

MIT © 2026 [an1zy](https://github.com/an1zy)
