# Truthgate — M0 scaffold

Автономный ИИ-оператор наступательной безопасности с детерминированным
**proof gate**: LLM-агент выдвигает гипотезы, детерминированный код решает,
уязвимость это или галлюцинация. Этот срез — **M0**: монорепа, каркас
оркестратора, контракты типов, CI, pre-commit. Валидаторы / proof_gate / TGB
подключаются вехами M1–M6.

## Тезис

> ИИ находит — детерминированный код решает.
> LLM-агент предлагает гипотезы; **находкой** результат становится, только если
> его подтвердил детерминированный верификатор по машинному артефакту
> (не по тексту LLM).

## Структура

```
truthgate/
├── orchestrator/          рой воркеров + LLM-мозг + pipeline
│   ├── types.py           Verdict, ValidatorContext, Candidate, Finding
│   ├── registry.py        реестр валидаторов по bug_class
│   ├── worker.py          worker-контракт (LLM/tool/validator)
│   ├── brain.py           LLM-мозг (Anthropic/OpenAI/stub)
│   ├── scope.py           scope-checker: hard-gate на out-of-scope
│   ├── ratelimit.py       per-host + global RPS
│   ├── oob.py             OOB-адаптер (interactsh-compatible)
│   ├── pipeline.py        recon → candidate → validate → consensus → gate
│   ├── config.py          env + yaml settings
│   └── cli.py             `truthgate run`, `truthgate classes`, `truthgate version`
├── tools/
│   ├── validators/        (M1–M2) 15 детекторов, zero-deps
│   └── proof_gate.py      (M3) судья v1 для сравнения
├── phase1/
│   └── proof_gate_v2.py   (M3) судья по артефакту, тиры live/code_static/none
├── benchmarks/            (M6) 32 CTF-задачи + раннер (TGB — Truthgate Bench)
├── tests/                 юнит-тесты каркаса
├── pyproject.toml         uv + ruff + mypy + pytest
├── .pre-commit-config.yaml
├── .github/workflows/ci.yml
└── Makefile
```

## Быстрый старт

```bash
# 1. установка
curl -LsSf https://astral.sh/uv/install.sh | sh   # или winget install astral-sh.uv
uv sync --all-extras

# 2. pre-commit
uv run pre-commit install

# 3. проверки
make ci      # lint + type + test

# 4. CLI
uv run truthgate --help
uv run truthgate run --target https://example.com --dry-run
```

## Этика

Инструмент — **только для авторизованного контура** (in-scope bug-bounty
программ, собственные стенды). Режим по умолчанию — `TRUTHGATE_DRY_RUN=true`
(reachability + canary, без деструктивных примитивов). `scope-checker` —
hard-gate: любой out-of-scope запрос агента блокируется до сетевого вызова.

## Дорожная карта (M0 → M9)

| Веха | Содержимое | Статус |
|------|------------|--------|
| M0   | Монорепа, каркас, типы, CI, pre-commit | **✅ этот срез** |
| M1   | 6 базовых валидаторов (sqli, ssrf, idor, ssti, lfi, xss) + anti-FP | ⏭ |
| M2   | Ещё 9 валидаторов + LLM-специфика | ⏭ |
| M3   | `phase1/proof_gate_v2.py` — судья по артефакту | ⏭ |
| M4   | Consensus + sellable-gate + журналирование | ⏭ |
| M5   | LLM-мозг, рой воркеров, MCP-адаптер | ⏭ |
| M6   | TGB — 32 задачи, docker + local backend | ⏭ |
| M7   | HackerOne/Bugcrowd/Intigriti API, репорт-шаблоны | ⏭ |
| M8   | Свой OAST, KMS, аудит-лог | ⏭ |
| M9   | Полировка, бенчмарк-прогоны до/после | ⏭ |

Полная методология — [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Лицензия

MIT.
