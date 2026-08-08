# Архитектура Truthgate (M0)

Документ фиксирует три инженерных решения, вокруг которых собирается проект.
На M0 реализованы контракты типов и pipeline-skeleton; валидаторы и судья
подключаются вехами M1–M4 без изменения этих контрактов.

## 1. Судья по артефакту (`phase1/proof_gate_v2.py`) — M3

Принимает **структурированный артефакт** (`Verdict.artifacts`), проверяет
согласованность полей. Никакого `re.search` по прозе. Три тира:
- `live` — есть машинный артефакт + one-time токен из реестра + differential.
- `code_static` — file:line существует в ФС и содержит паттерн.
- `none` — ни артефакта, ни file:line → NOT PROVEN.

## 2. Детерминированные валидаторы (`tools/validators/`) — M1–M2

Контракт: `validate(finding, ctx) -> Verdict`. `is_real` — строго по правилу
класса; `confidence` — воспроизводимость (replays). Обязательный инвариант:
PASS на уязвимой цели ∧ FAIL на безопасной той же семантики.

Плановое покрытие MVP (15): sqli, ssrf, idor/bola, ssti, jwt, lfi, nosqli,
command_injection, mass_assignment, open_redirect, xxe, xss, bfla,
prompt_injection, excessive_agency.

Расширение к M7 (реальная bug-bounty экономика): ssrf→cloud-metadata,
deserialization RCE, request-smuggling, race-conditions, OAuth/SSO,
GraphQL-specific, cache-poisoning, subdomain-takeover.

## 3. Маховик развития (`benchmarks/`) — M6

32 CTF-задачи, бинарный флаг-критерий. Методология «до → после → дельта»:
любое изменение агента/валидаторов прогоняется до и после, регресс роняет CI.

## Pipeline

```
Worker.propose() → Candidate
  → scope.assert_in_scope() (hard-gate)
  → dedup by (target, path, param, class)
  → validator.validate() → Verdict
  → [M4] consensus (severity-quorum)
  → [M3] proof_gate_v2 → tier
  → sellable? → Finding : needs_proof
```

## Инварианты

- Worker никогда не ставит `is_real`. Только валидатор.
- Валидатор никогда не решает `sellable`. Это делает `consensus + proof_gate`.
- Любой сетевой примитив проходит через `scope.assert_in_scope()` до вызова.
- Дефолт `TRUTHGATE_DRY_RUN=true` — только reachability + canary.
