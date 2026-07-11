# SOC-bench data generator — план реализации v2 (ревизия по рецензии)

**Заменяет** `IMPLEMENTATION_PLAN_EVIDENCEFORGE.md`. Основа прежняя: **форк
`Cisco-Talos/EvidenceForge` (MIT)** + пакет-расширение `socbench/`. В этой версии
учтены обоснованные замечания рецензии (только те, что касаются инструмента):

| # | Замечание | Куда вошло |
|---|---|---|
| Б | Не инвазировать ядро EF (coupling, merge-конфликты) | Шаг 1 переписан на неинвазивное расширение |
| Г | Граф Tiger: жёсткий per-edge матч несправедлив | Шаг 3d: verifiable-цепочки + мягкая метрика |
| 3 | Текстовые источники: хрупкий маппинг на evidence_id | Шаг 4: скрытые `__grader_metadata` + детерминизм текста |
| А | Panda как статик ломает feedback loop | Шаг 5/6: архитектурный шов под опц. интерактивный режим |
| В | Синтетический PCAP из Zeek → артефакты генератора | Шаг 7: Zeek-canonical, scapy-PCAP убран |
| 4 | Робастность + защита от контаминации | Новый раздел «Сквозные модули» |

**Осознанные отклонения от текста статьи** (решать авторам явно, см. финал):
сеть как Zeek/flow вместо raw .pcap; граф Tiger оценивается мягкой метрикой;
интерактивный Panda — опциональный режим сверх статичной спецификации §9.4.

---

## 0. Раскладка форка (неизменно)

```
EvidenceForge/                      # форк, ветка socbench
  src/evidenceforge/                # ядро НЕ трогаем (см. Шаг 1)
  scenarios/colonial-pipeline/scenario.yaml
  src/socbench/
    capture/canonical_events.py     # НЕинвазивный перехват потока EF (шаг 1)
    sources/  vss.py helpdesk.py cti.py hostmetrics.py siem.py   (шаг 4)
    truth/    fox.py goat.py mouse.py tiger.py panda.py common.py (шаг 3)
    stage/    world_state.py bucketize.py                         (шаг 5)
    export_dataset.py                                             (шаг 6)
    mutate/   augment.py            # робастность (сквозной модуль)
    integrity/ signatures.py        # contamination guard (сквозной модуль)
    raw/      evtx.py journal.py    # шаг 7 (pcap исключён)
  tests/socbench/
```

Инвариант: `truth/*` и `sources/*` читают только `capture/canonical_events`
(не друг друга — DP2). `export_dataset` не импортирует `truth/*` при сборке
`agent/` (DP2-гейт).

---

## Шаг 1 — Захват канонических событий (НЕинвазивно)  🔶 [замечание Б]

Цель прежняя: структурный поток `SecurityEvent` со стабильными `evidence_id`.
**Изменение:** не патчим `EventDispatcher` в ядре. Порядок выбора механизма:

1. **Проверить штатную точку расширения.** В EF эмиттеры регистрируются в
   диспатчере (ARCHITECTURE.md). Если есть **поддерживаемая регистрация
   эмиттера/плагина** — реализовать `CanonicalEventEmitter` как *внешний*
   эмиттер в `socbench/capture/`, подключаемый через публичный API. Это даёт
   внутри-движковую точность улик БЕЗ правки core.
2. **Если API-регистрации нет — перехват выходного потока.** Собирать
   canonical events пост-фактум из `OBSERVATION_MANIFEST.json` + storyline YAML
   + записей `data/`, обогащая `evidence_id` детерминированно **до** нарезки на
   стадии. Хрупче по chain-of-custody, но не трогает ядро.
3. **Крайний случай — тонкий middleware-шов.** Один узкий адаптер поверх
   публичного интерфейса генерации, изолированный в `socbench/`, чтобы вся
   логика `evidence_id` жила в расширении, а не размазывалась в ядре.

Вне зависимости от механизма — `evidence_id` детерминирован из
`(scenario_seed, порядковый)`; `observed_by` берётся из решения о видимости
сенсоров EF (это же — механизм DP4/DP2).

Формат строки (`grader/canonical_events.ndjson`):
```json
{"evidence_id":"EVID-000123","ts":"...","phase":"lateral_movement",
 "attack":["T1021.002"],"host":"FS-01","actor":"attacker","kind":"process",
 "pid":4821,"ppid":3310,"fields":{...},
 "observed_by":["windows_event_security","ecar","siem"],
 "output_refs":{"windows_event_security":"FS-01.../win.xml#<rec>"}}
```

### DoD
- Механизм выбран по приоритету 1→2→3; **ядро EF не изменено** (или изменение
  сведено к использованию публичного API расширения).
- Каждая атак-строка резолвится в записи `data/` через `output_refs`.
- Детерминизм: тот же seed → идентичный NDJSON (хеш).
- При обновлении апстрима расширение не конфликтует с core (тест: rebase на свежий
  main EF, `capture/` собирается).

### Отчёт о реализации (2026-07-11) ✅

**Статус:** шаг 1 выполнен на ветке `socbench`. Ядро `src/evidenceforge/` не
изменялось.

#### Выбранный механизм

Приоритет **2 — post-generation** (`CaptureMechanism.POST_GENERATION`):
после `eforge generate` canonical events собираются из артефактов бандла:

| Источник | Назначение |
|---|---|
| `GROUND_TRUTH.json` | атак-события (по record), поля, phase, host |
| scenario YAML | ATT&CK-техники, storyline metadata, per-step visibility |
| `OBSERVATION_MANIFEST.json` | per-source visibility (если профиль ≠ `complete`) |
| `data/` | резолв `output_refs` по полям события |

Штатной регистрации внешнего эмиттера в публичном API EF нет — middleware-шов
(приоритет 3) не потребовался.

#### Реализованные модули

```
src/socbench/
  __main__.py              # CLI: socbench capture
  capture/
    canonical_events.py    # build / write / finalize_observation
    output_refs.py         # field-confirmed resolver → data/
    scenario_index.py      # storyline → phase / techniques
    models.py              # CanonicalEvent (Pydantic)
    hashing.py             # evidence_id + локальный stable_seed
    errors.py              # SocbenchCaptureError
tests/socbench/test_canonical_events.py   # 17 тестов
scripts/audit_canonical_events.py         # integrity audit (dev)
```

Команда:

```bash
uv run socbench capture --bundle <bundle-dir> --scenario <scenario.yaml> --seed 42
```

Выход: `<bundle>/grader/canonical_events.ndjson` + SHA-256 digest в stdout.

#### Формат записи (фактический)

```json
{
  "evidence_id": "EVID-547345ca",
  "ts": "2024-01-15T15:29:39Z",
  "phase": "initial_access",
  "attack": ["T1190"],
  "host": "MUSIC-SRV-01",
  "actor": "attacker",
  "kind": "connection",
  "fields": {"dst_ip": "10.10.30.50", "dst_port": 21, "uid": "..."},
  "observed_by": ["zeek_conn"],
  "output_refs": {"zeek_conn": "data/core-switch-tap/conn.json#L53267"},
  "observation_status": "observed",
  "unresolved_sources": [],
  "record_id": "evt-001#0",
  "storyline_id": "evt-001"
}
```

Отличия от черновика в начале раздела:

- `evidence_id` = `EVID-` + 8 hex от `sha256(f"{seed}:{ordinal}")[:8]` (seed
  влияет на id, порядок строк в NDJSON — только по `(ts, record_id)`).
- `observation_status`: `observed` | `partial` | `unobserved` — явный маркер
  неполной видимости (DP4).
- `unresolved_sources` — кандидаты, не подтверждённые resolver'ом (диагностика).
- Инвариант: **`set(observed_by) == set(output_refs.keys())`** после
  `finalize_observation()`.

#### Ключевые решения (post-audit)

| Проблема аудита | Решение |
|---|---|
| `observed_by` на уровне storyline | `candidate_formats_for_record()`: kind ∩ visibility per GT record; multi-record steps — отдельный `observed_by` на record |
| Слабые refs (`#L1`, substring `id` / port `22`) | Resolver пишет ref только при совпадении полей; host-scoped форматы не ищут глобально по `data/` |
| `observed_by` ≠ `output_refs` | Симметрия через подтверждённые refs; неподтверждённое → `partial` + `unresolved_sources` |
| Seed игнорировался в `evidence_id` | Локальный `hashing.py` (без импорта `_stable_seed` из EF) |
| Тихий сбой при дрейфе `GROUND_TRUTH.json` | `SocbenchCaptureError` с `ValidationError` в cause |
| `observation_profile=="complete"` → manifest `None` | Штатный режим EF; задокументировано в коде |

Поддерживаемые форматы resolver'а: `zeek_conn`, `zeek_dns`, `windows_event_*`,
`ecar`, `syslog`, `bash_history`, `web_access`, `proxy_access`, `cisco_asa`,
`snort_alert`.

#### Коммиты

| Коммит | Содержание |
|---|---|
| `341c5a18` | baseline: capture + 8 исходных тестов |
| `6038b3b1` | P0-1: per-record `observed_by` |
| `10855b77` | P0-2: resolver без `#L1`, sorted `rglob`, web/proxy |
| `023c155f` | P0-3: симметрия + `observation_status` |
| `587ab9db` | P0-4: seed-mixed `evidence_id` |
| `2a69d71c` | P1: явная ошибка при дрейфе GT |
| `ed8ce252` | ужесточение substring-матчей |
| `20d4fafd` | host-scoped search (без PID-коллизий между хостами) |

#### Верификация

**Тесты:** `uv run pytest tests/socbench -v --no-cov` — **17/17 passed**.

**Audit** (`scripts/audit_canonical_events.py`) на сгенерированных бандлах:

| Bundle | events | obs_mismatch | ref_issues | unobservable_flag_missing |
|---|---|---|---|---|
| `output/branch-office-test` | 10 | 0 | 0 | 0 |
| `output/retail-test` | 22 | 0 | 0 | 0 |

**Детерминизм (retail, seed=42):**
`bc33eac57fca994ac2d2fe9892858e5fd758d25fa535ed273879f69967b59d57` (два прогона
совпали); seed=99 → другой digest.

**Retail `observation_status` (seed=42):** observed=1, partial=0, unobserved=21.
Единственное observed — `evt-001#0` (FTP RCE, Zeek на tap). 21 unobserved —
**ограничение бандла**, не resolver'а: в `data/` нет директории `MUSIC-SRV-01`,
сценарий генерирует только `windows` + `zeek` (`output.logs`); для Linux process-
событий физически отсутствуют `syslog`, `bash_history`, `ecar`. Исправление —
расширить `output.logs` в Colonial Pipeline (шаг 2) и перегенерировать.

#### DoD — чеклист

- [x] Механизм 2 (post-generation); ядро EF не изменено
- [x] `output_refs` только при field-confirmed match (без слабого fallback)
- [x] Детерминизм NDJSON по seed; порядок событий не зависит от seed
- [x] Расширение изолировано в `src/socbench/`; upstream merge-safe
- [~] «Каждая атак-строка резолвится в `data/`» — **частично**: все строки
  присутствуют в NDJSON, но unobserved события без endpoint-логов на хосте
  остаются без refs (явно помечены `observation_status=unobserved`)

---

## Шаг 2 — Сценарий Colonial Pipeline  🔶

`scenarios/colonial-pipeline/scenario.yaml`. Шаблон —
`tests/fixtures/scenarios/retail-store-ftp-attack.yaml` (20+ юзеров, FTP-RCE,
полная топология — ближайший готовый пример, уже проверенный на retail-бандле
в шаге 1).

### Топология и сенсоры (размещение сенсоров = рычаг DP4)

- **environment.network.segments**: `remote_access`, `corporate_it`, `server`,
  `OT`. Сегментация намеренно неполная → частичная латералка.
- **sensors**: SPAN на `corporate_it`, TAP на периметре, firewall-сенсор
  (Cisco ASA), IDS-сенсор (Snort). Размещение сенсоров — рычаг **DP4**: что
  видно и что нет. Оно же задаёт `observation_status` из шага 1
  (`observed | partial | unobserved`) и профиль в `OBSERVATION_MANIFEST.json`
  (профиль ≠ `complete`, иначе manifest → `None`).
- **systems**: VPN-gw (linux), mail (win), FTP (linux), AD (win),
  2×file-server (win, FS-01/FS-02), OT-device, N workstations. Роли:
  `file_server`; опц. `forward_proxy`; `web_server` — нет.
- **time_window**: start + duration ≥ 3ч → ≥ 6 стадий по 30 мин.

### Storyline — 30-мин раскладка (DarkSide-подобно)

| # | Смещение | Шаг | ATT&CK | Ожидаемая телеметрия |
|---|---|---|---|---|
| 1 | +0:03 | VPN auth скомпрометированным аккаунтом | T1078, T1133 | ASA auth, `zeek_conn` |
| 2 | +0:18 | recon (nltest / net view) | T1018, T1087 | `windows_event_*`, `zeek` |
| 3 | +0:34 | LSASS-дамп | T1003.001 | Sysmon 10 / eCAR PROCESS.OPEN |
| 4 | +0:46 | service install PsExec | T1569.002 | 4697 / eCAR SERVICE.CREATE |
| 5 | +0:52 | SMB admin-auth burst на серверы | T1021.002 | 4624 type3 / 4648 |
| 6 | +1:10 / +1:18 | bulk-архив шар → копия на FTP | T1560, T1005 | eCAR, `windows_event_sysmon`, SMB |
| 7 | +1:36 | эксфильтрация FTP + HTTPS на внешний IP | T1048, T1567 | ASA teardown bytes, `zeek_conn`, 733100 |
| 8 | +2:00 | vssadmin delete shadows | T1490 | process-события (см. шаг 4 VSS) |
| 9 | +2:06 / +2:11 | шифрование FS-01 / FS-02 | T1486 | массовые FILE.WRITE/rename, `hostmetrics` всплеск |
| 10 | +2:30+ | helpdesk-тикеты | — (не атак-улика) | `helpdesk` (late, гейтинг ≥ N/2) |

helpdesk-тикеты — не положительная улика (`forbidden_evidence_ids`, шаг 3),
появляются только во 2-й половине окна (гейтинг — шаг 5).

### DoD

- `eforge validate` проходит; `eforge generate` даёт данные без ошибок.
- `eforge eval` проходит hard-gates: Causal Ordering ≥ 90, Event Presence ≥ 85.
- В `data/` видны все атакующие фазы в ожидаемых форматах.
- **Дополнительно к retail** (закрывает ограничение шага 1): в `output.logs`
  включены Linux/endpoint-логи (`syslog`, `bash_history`, `ecar`) для хостов
  storyline, чтобы process-события не оставались поголовно `unobserved`.
  Проверка тем же audit-скриптом: каждая атак-запись GROUND_TRUTH либо
  резолвится, либо помечена `unobserved` осознанно, а не из-за пропуска сенсора.

### Отчёт о реализации (2026-07-11) ✅

**Статус:** шаг 2 выполнен на ветке `socbench`. Сценарий Colonial Pipeline
сгенерирован и прошёл `eforge eval`; follow-up resolver-доработка (шаг 1
`output_refs`) закрыла основной долг capture coverage на colonial-бандле.

#### Артефакты

```
scenarios/colonial-pipeline/
  scenario.yaml          # 22 users, 15 systems, 13 storyline steps, 4 segments, 4 sensors
  data/                  # сгенерированный бандл (eforge generate --force)
  GROUND_TRUTH.json
  OBSERVATION_MANIFEST.json
  grader/canonical_events.ndjson   # socbench capture --seed 42
```

#### Топология (фактическая)

| Сегмент | CIDR | Системы |
|---|---|---|
| `remote_access` | 10.60.10.0/24 | VPN-GW-01 (Linux) |
| `corporate_it` | 10.60.20.0/24 | WKS-01..06, WKS-OPS-01/02 |
| `server` | 10.60.30.0/24 | DC-01, MAIL-01, FS-01, FS-02, FTP-01 |
| `OT` | 10.60.40.0/24 | OT-HMI-01 |

Сенсоры: SPAN `corp-core-span` (только `corporate_it`), TAP `perimeter-tap`
(`remote_access` + `server`), IDS `perimeter-ids`, ASA `perimeter-fw` (все сегменты).
`observation_profile: enterprise_standard`.

`output.logs`: `windows`, `zeek`, `ecar`, `syslog`, `bash_history`, `snort_alert`,
`cisco_asa` — закрывает ограничение retail (Linux/endpoint-логи на VPN-GW и FTP-01).

#### Storyline (13 шагов, 4ч окно, +3m … +2h11m)

| # | ID | Смещение | ATT&CK | Хост |
|---|---|---|---|---|
| 1 | evt-001 | +3m | T1078, T1133 | VPN-GW-01 |
| 2 | evt-002 | +18m | T1018, T1087 | WKS-OPS-01 |
| 3 | evt-003 | +34m | T1003.001 | WKS-OPS-01 |
| 4 | evt-004/004b | +46/+47m | T1569.002 | WKS-OPS-01 → FS-01 |
| 5 | evt-005/005b | +52/+54m | T1021.002 | FS-01, FS-02 |
| 6 | evt-006a/006b | +1h10/+1h18m | T1560, T1005 | FS-01 → FTP-01 |
| 7 | evt-007 | +1h36m | T1048, T1567 | FTP-01 |
| 8 | evt-008 | +2h | T1490 | FS-01 |
| 9 | evt-009a/009b | +2h6/+2h11m | T1486 | FS-01, FS-02 |

Helpdesk-тикеты (шаг 10 плана) — **шаг 4** (`socbench/sources/helpdesk.py`).

#### Верификация генерации

| Проверка | Результат |
|---|---|
| `eforge validate` | PASS (9 warnings, non-blocking) |
| `eforge generate --force` | PASS, 112K+ records / 16 sources |
| `eforge eval` | **PASS** — Overall 96/100; Causal Ordering **100** (≥90); Event Presence **100** (≥85) |
| Linux endpoint logs | `VPN-GW-01`, `FTP-01`: `syslog.log`, `ecar.json`, `bash_history` |

#### Capture + resolver (seed=42, post follow-up)

Команда:

```bash
uv run socbench capture --bundle scenarios/colonial-pipeline \
  --scenario scenarios/colonial-pipeline/scenario.yaml --seed 42
```

Digest NDJSON: `d0dce7c9a774fca4f72ebbadd236c88531ea255a83e8168361cede6815dab1c0`.

| Метрика | До resolver follow-up | После |
|---|---|---|
| canonical events | 21 | 21 |
| `observed` | 11 | **16** |
| `partial` | 5 | **5** |
| `unobserved` | 5 | **0** |

**Добавленные kind-specific matchers** (`src/socbench/capture/output_refs.py`):

| Приоритет | kind | Источники | Ключевые поля |
|---|---|---|---|
| P0-A | `logon` | Security 4624, eCAR LOGIN | `TargetLogonId`, `IpAddress`, `LogonType` |
| P0-B | `service_installed` | Security 4697, eCAR SERVICE.CREATE | `ServiceName`, `ServiceFileName` |
| P1-A | `explicit_credentials` | Security 4648 | `TargetUserName` + domain |
| P1-B | `create_remote_thread` | Sysmon 8, eCAR THREAD.REMOTE_CREATE | `TargetImage` / `target` |
| P2-A | `connection`, `ssh_session` | eCAR FLOW, syslog Accepted | `dst_ip`/`dst_port`, tuple |
| P2-B | `connection` (exfil) | ASA teardown/built | `dst_ip` + `dst_port` (+ Zeek uid fallback) |
| P2 | `rdp_session` | Security 4624 Type 10, eCAR FLOW :3389 | Zeek uid ↔ `IpAddress` correlation |

`KIND_CANDIDATE_FORMATS` расширен для `service_installed`, `explicit_credentials`,
`create_remote_thread` (`canonical_events.py`). Тесты: `tests/socbench/test_output_refs_resolver.py`
(12 parametric + colonial integration). Полный suite: **29/29 passed**.

**Ключевой выигрыш:** `EVID-cdf56f97` (`evt-002#0`, `rdp_session`) перешёл
`partial → observed` (Security `#rec46`, eCAR `#L68`, Zeek `#L450`, ASA `#L14003`).

#### Оставшиеся partial (5) — классификация

| evidence_id | kind | unresolved | Вердикт |
|---|---|---|---|
| `EVID-547345ca` | `connection` | `cisco_asa` | ASA :1194 VPN teardown отсутствует; Zeek резолвится |
| `EVID-57bc5431` | `create_remote_thread` | `ecar` | **EXPECTED-A** — boot-time lsass без eCAR PROCESS lifecycle |
| `EVID-79379b3d` | `process` | `ecar` | **EXPECTED-A** — eCAR dropped по `OBSERVATION_MANIFEST` (DP4) |
| `EVID-6bdaf0d3` | `connection` | `zeek_conn` | **EXPECTED-A** — Zeek filtered/dropped по manifest (DP4) |
| `EVID-5cbc8381` | `connection` | `ecar` | **EF local bug** — GT :443/ssl, data :80/http (`evt-007#1`) |

Аудит-скрипт (`scripts/audit_canonical_events.py`) выводит `known_partial_notes`
с явными причинами. Документация EXPECTED-A: `docs/KNOWN_LIMITATIONS.md`;
репродукция бага `evt-007#1`: `docs/worklog/2026-07-11-evt-007-ssl-port-mismatch.md`.

**Аудит портов connection (scope `5cbc8381`):** colonial `evt-001#0` (`ssl:1194`)
и `evt-007#0` (`ftp:21`) совпадают с Zeek; только `evt-007#1` ломает GT↔data.
retail-test / branch-office-test не содержат ssl/443 storyline-событий → баг
**локален к эксфильтрации FTP-01**, не системный «EF не умеет ssl».

#### Коммиты (шаг 2 + resolver follow-up)

| Коммит | Содержание |
|---|---|
| *(scenario baseline, ранее на ветке)* | `scenarios/colonial-pipeline/scenario.yaml`, generate/eval |
| `73afe171` | P0: logon + service_installed matchers + тесты |
| `fd0114ff` | P1: explicit_credentials + create_remote_thread matchers + тесты |
| `f1af6eb9` | P2: connection/ASA/ssh/rdp_session matchers, audit script, KNOWN_LIMITATIONS |

#### DoD — чеклист

- [x] `eforge validate` проходит
- [x] `eforge generate` без ошибок
- [x] `eforge eval` hard-gates: Causal Ordering ≥ 90, Event Presence ≥ 85
- [x] Атак-фазы видны в `data/` (Zeek, ASA, Windows, eCAR, syslog)
- [x] `output.logs` включает `syslog`, `bash_history`, `ecar` для Linux/endpoint хостов
- [x] Colonial capture: **0 unobserved**; 16/21 observed с field-confirmed `output_refs`
- [~] 5 partial осознанно классифицированы (3 EXPECTED-A, 1 EF-bug, 1 ASA gap);
  полное 21/21 observed — после upstream EF fix `evt-007#1` и/или расширения ASA coverage

---

## Шаг 3 — Truth-проекторы 5 задач  ✅ (главный вклад)

`socbench/truth/` читает `canonical_events.ndjson` (шаг 1), пишет
scoreboard-манифесты по схемам 5 задач. `common.py`: загрузка ndjson, staging
(`stage_of(ts)`), резолвер `evidence_id`, множества ATT&CK-маркеров.
Инвариант: ни один truth-модуль не импортирует другой — все читают только
canonical (DP2). **Panda** — исключение по входу: читает срез `WorldState`,
не сырой список событий (в static v1 `WorldState` = обёртка над canonical).

### 3a. fox.py — o1_scale / o2_type / o3 (кумулятивно по стадиям)
- `o1_scale`: `scale_label` по **графу verifiable-взаимодействий** затронутых хостов
  (`isolated` | `localized` | `campaign_scale`), не по счётчику хостов; auth-burst
  как явный паттерн `campaign_scale`.
- `o2_type`: `type_label` по **observable** precursor-маркерам (`kind`/`fields`),
  не по grader-полю `attack` (DP2-safe).
- `o3`: два «первых» (первый затронутый хост / первое ransomware-событие),
  кумулятивно по мере накопления стадий.
Источник — cumulative slice canonical по `stage_of(ts)` (30 мин).

### 3b. goat.py — O1..O4 + пороги (ring-скоринг)
- O1 `encrypted_paths`: T1486-события (несут затронутые шары) разворачиваются в
  path-уровень; `encrypted` / `not-yet-encrypted` по времени стадии.
- O2 `impact_by_host_share`: агрегаты encrypted/total bytes из объёмов шар.
- O3 `vss_events`: из vssadmin-процессов (шаг 4 VSS) →
  `{host, event_type, time, evidence_id}`.
- O4 `attribution`: encryptor-процесс из eCAR PROCESS / Sysmon
  (pid / ppid / cmdline).
- `manifest_thresholds` (byte/time tolerance, dir-fraction) — только грейдеру.

### 3c. mouse.py — O1..O5 + tolerances
O1 Yes/No; O2 start-time (±5 мин); O3 volume GB (±10); O4 involved_hosts
(±3, эксфил + стейджинг); O5 protocols (primary = макс. объём). Детекция exfil/
staging — по **observable** `kind`/`fields` (внешний `dst_ip`, `orig_bytes`, …),
**без** фильтра по `observation_status` или grader `phase`/`attack`. Ветка
`exfil_happens=False` → O1=No, остальное N/A.

### 3d. tiger.py — threat graph, verifiable-цепочки + мягкая метрика  [замечание Г]

Граф угрозы строится не жёстко из `caused_by`, а с разделением рёбер по
проверяемости. **Правила verifiable (ревизия 2026-07-11 после Colonial
forensics):**

| rule_id | Verifiable когда | Не verifiable / только contextual |
|---|---|---|
| `process_parent_child` | same host, child `ppid` == parent `pid` (observable) | sibling tools из одного shell (procdump → PsExec: общий ppid=PowerShell) |
| `psexec_remote_service` | launcher cmd: `psexec` + `\\TARGET`; target: `PSEXESVC` service_installed ≤ window | требование byte-identical image (PsExec.exe ≠ PSEXESVC.exe — штатно) |
| `auth_session_action` | same **host**, same `logon_id`, последующее действие на том же хосте | cross-host lateral SMB (FS-01 vs FS-02 — разные LogonID корректны) |
| `file_artifact_continuity` | normalized filename/path match между process-событиями | same PID для compress → upload (multi-step by design) |
| `file_to_network` | process ссылается на файл F + connection/upload с F в window | — |
| `host_interaction` | Fox verifiable host edges (source_ip, dst_ip, remote hostname) | — |

**Capture:** `ppid`/`pid` backfill из Sysmon Event ID 1 и eCAR `PROCESS CREATE`
реализован в `output_refs.py` (technical debt SOC-bench закрыт; не EF bug).

- **verifiable** — только по таблице выше; каждое ребро несёт `rule` +
  `evidence_ids` + `source_attribution` из `observed_by`.
- **contextual** — shared actor/logon_id без same-host action, shared source_ip
  cross-host lateral, temporal tool sequence без ppid (LSASS dump → PsExec).
  Помечаются `edge_class: contextual`.

Forensics: `docs/worklog/2026-07-11-tiger-verifiable-rules-colonial.md`.

Манифест несёт классификацию на каждое ребро:
```json
{"edges":[{"id":"E1","parent":"N1","child":"N2","interaction":"psexec_remote_service",
           "edge_class":"verifiable","rule":"psexec_remote_service",
           "source_attribution":["windows_event_security","ecar"],
           "evidence_ids":["EVID-...","EVID-..."]}]}
```

**Скоринг** (грейдер, `tiger_ged_spec.json` рядом с манифестом): verifiable-рёбра —
жёсткий матч; граф целиком — мягкая метрика **Graph Edit Distance** с весами
(verifiable-рёбра дороже contextual). Веса в конфиге: missing verifiable **5.0**
vs contextual **1.0** (ratio **5×**); extra verifiable **4.0** vs contextual
**0.5** (ratio **8×**). Функция `score_graph_edit_distance()` + тест
`test_tiger_verifiable_core_survives_high_contextual_noise` подтверждают, что
GED штрафует потерю verifiable-core сильнее, чем шум contextual-рёбер.
Colonial seed=42: verifiable-остов **не пуст** (6 рёбер), но разрежен; правило
`process_parent_child` валидно, но **0 эмпирических инстансов** в этом сценарии
(sibling-tools, не process-tree).

Остальные объективы Tiger:
- `o1_relevant_sources`: источники, реально несшие атак-улики (из `observed_by`).
- `o3_initial_entrypoint`: первое observable initial-access событие (external
  `source_ip` → internal host / VPN connection), **без** фильтра по grader `phase`.
- `forbidden_evidence_ids`: helpdesk / user-report (когда появятся в canonical).

### 3e. panda.py — per-stage BLUF ground truth  ✅ [шов под замечание А]
Основной режим — **статический**, строго по §9.4 (per-stage BLUF против ground
truth реального инцидента). Truth-проектор работает не с фиксированным
`canonical_events`, а со **срезом от `WorldState`** (шаг 5), чтобы в опц.
интерактивном режиме ground truth пересчитывался на пропатченном хвосте; в
статик-режиме `WorldState` = тождественный срез.

Логика ground truth per stage: для каждой стадии — правильное containment «на
этот момент» по накопленным уликам (латералка → изолировать AD/FS + блок SMB;
эксфил → блок исходящего FTP/HTTPS; ранние стадии → возможно `no_action`).
`action_targets` — из host/subnet событий стадии. Trap: преждевременное
containment на ранних стадиях штрафуется.

### DoD (весь шаг 3)
- `socbench truth build --events canonical_events.ndjson --out grader/` пишет
  5 json-манифестов.
- Tiger: verifiable-рёбра восстановимы из `data/` по заявленным правилам;
  contextual помечены; спека GED-скоринга приложена отдельным файлом рядом с
  манифестом.
- Panda читает срез `WorldState` (в статике — тождественный), не сырой canonical.
- Консистентность: все `evidence_id` резолвятся; helpdesk не в положительных
  уликах; ни один truth-модуль не импортирует другой.

### Отчёт о реализации (2026-07-11) — ✅ все 5 truth-проекторов

**Статус:** реализованы **Fox, Goat, Mouse, Tiger, Panda** + общий слой
`common.py`, capture backfill (`output_refs.py`), минимальный `WorldState`
(`socbench/stage/world_state.py`) для Panda. Шаг 3 DoD выполнен для static v1.

#### Реализованные модули

```
src/socbench/truth/
  common.py       # staging, host-graph, precursor markers, exfil/staging heuristics
  fox.py          # grader/fox.json (o1_scale / o2_type / o3 per stage)
  goat.py         # grader/goat.json (O1..O4 + manifest_thresholds)
  mouse.py        # grader/mouse.json (O1..O5 + tolerances)
  tiger.py        # grader/tiger.json + score_graph_edit_distance()
  panda.py        # grader/panda.json (per-stage BLUF via WorldState slice)
  errors.py
src/socbench/stage/
  world_state.py  # StaticWorldState (apply/replan = no-op in v1)
src/socbench/capture/
  output_refs.py  # backfill: source_ip, logon_id, orig_bytes, pid, ppid, …
tests/socbench/
  test_fox_truth.py
  test_goat_truth.py
  test_mouse_truth.py
  test_tiger_truth.py
  test_panda_truth.py
  test_backfill_output_refs.py
  test_truth_consistency.py   # сквозные DoD-проверки (шаг 3 финализация)
docs/
  OPEN_QUESTIONS.md
  KNOWN_LIMITATIONS.md
  worklog/2026-07-11-evt-002-rdp-source-ip-mismatch.md
  worklog/2026-07-11-tiger-verifiable-rules-colonial.md
  worklog/2026-07-11-declared-vs-observed-colonial.md
scenarios/colonial-pipeline/grader/
  canonical_events.ndjson, fox.json, goat.json, mouse.json,
  tiger.json, tiger_ged_spec.json, panda.json
```

CLI:

```bash
uv run socbench capture -b scenarios/colonial-pipeline \
  -s scenarios/colonial-pipeline/scenario.yaml --seed 42

uv run socbench truth build \
  --events scenarios/colonial-pipeline/grader/canonical_events.ndjson \
  --out scenarios/colonial-pipeline/grader \
  --window-start 2024-06-03T08:00:00Z
```

Без `--task` по умолчанию собираются все 5 задач (`DEFAULT_TRUTH_TASKS`).
Явный список: `--task fox,goat,mouse,tiger,panda`.

#### 3a Fox — ключевые решения

| Объектив | Реализация |
|---|---|
| `o1_scale` | Граф затронутых хостов: verifiable-рёбра (`source_ip`, `dst_ip`, remote-exec `\\HOST`, shared `uid`/`logon_id`). `isolated`=1 вершина; `localized`=2 вершины + ребро; `campaign_scale`=≥3 **или** auth-burst (≥3 auth на ≥2 хостах за 5 мин) **или** 2 хоста без ребра |
| `o2_type` | `RANSOMWARE_PRECURSOR_MARKERS` в `common.py`: T1569.002 / T1021.002 / event_7045; детекция по `kind`+`fields` only (DP2) |
| `o3` | Кумулятивно: `first_affected_host`, `first_ransomware_*` по `encrypt`/`darkside` в process fields |

**Capture backfill (не scenario YAML):** после `resolve_output_refs` поля
(`source_ip`, `logon_id`, `orig_bytes`, …) подмешиваются из Security/eCAR/Zeek
строк, на которые указывают refs. Enrichment из `scenario_index` **удалён**.

**DP2-тесты:** `test_fox_ignores_ground_truth_labels`,
`test_mouse_ignores_ground_truth_labels`, `test_tiger_ignores_ground_truth_labels`,
`test_panda_ignores_ground_truth_labels` — обнуление `phase`/`attack`/`actor` не
меняет выход truth-проекторов.

#### Colonial Fox (seed=42, window 08:00Z)

| Stage | `o1_scale` | `o2_type` | Примечание |
|---|---|---|---|
| 0 | `campaign_scale` | `uncertain` | VPN-GW + WKS-OPS, **0 verifiable-рёбер** (см. evt-002 ниже) |
| 1+ | `campaign_scale` | `ransomware_like` | ≥2 precursor categories (PsExec + service) |

#### Известное ограничение: evt-002 RDP client IP (EF bug)

- **Storyline:** RDP pivot VPN-GW (`10.60.10.10`) → WKS-OPS-01.
- **GT:** нет emitted-записи на WKS-03; WKS-03 — обычная workstation, не jump-host.
- **Telemetry:** Security/eCAR/Zeek показывают client `10.60.20.13` (WKS-03).
- **Вывод:** артефакт генератора (класс дефекта как `evt-007#1`), **не** planned
  pivot. Fox stage-0 `campaign_scale` корректен по observable-правилам, но **не**
  валидирует narrative VPN→OPS. См. `KNOWN_LIMITATIONS.md`, worklog evt-002.

#### 3c Mouse — ключевые решения

| Объектив | Colonial (seed=42) |
|---|---|
| O1 | Yes |
| O2 | `2024-06-03T09:36:18Z` |
| O3 | ~0.758 GB (сумма обоих каналов) |
| O4 | `{FS-01, FTP-01}` (exfil + staging) |
| O5 primary | `ftp` (540M > 272M https); partial `EVID-5cbc8381` **включён** в расчёт |

Агрегаты **не** фильтруют по `observation_status`. DP2-тест:
`test_mouse_ignores_ground_truth_labels`.

Tolerances в манифесте: ±5 мин / ±10 GB / ±3 hosts.

#### 3b Goat — ключевые решения

| Объектив | Реализация |
|---|---|
| O1 `encrypted_paths` | Per-stage path status по T1486 process cmd (`extract_encrypt_paths`) |
| O2 `impact_by_host_share` | Агрегаты encrypted/total bytes (deterministic share volume placeholder) |
| O3 `vss_events` | Из vssadmin delete-shadows process events |
| O4 `attribution` | Encryptor pid/ppid/cmdline из observable process fields |
| thresholds | `byte_tolerance_fraction=0.10`, `time_tolerance_minutes=5`, `dir_fraction=0.10` |

Colonial (seed=42): encrypt paths появляются на stage 4; VSS на stage 3.

#### 3d Tiger — ключевые решения

| Компонент | Реализация |
|---|---|
| Verifiable rules | Таблица §3d; forensics-driven (см. worklog tiger-verifiable-rules) |
| Contextual rules | `sequential_tools_same_host`, `lateral_shared_source_ip` |
| GED spec | `tiger_ged_spec.json` с `weight_ratios` (verifiable ≥5× contextual) |
| Scoring | `score_graph_edit_distance()` — weighted edge/node edit cost |

**Colonial Tiger (seed=42):** 6 verifiable, 8 contextual. Verifiable skeleton:
`psexec_remote_service` (004→004b), `file_artifact_continuity` ×3
(stage-fs01.zip chain), `file_to_network` ×2 (archive/xcopy → FTP conn).
`process_parent_child`: **0 инстансов** (sibling procdump/PsExec под PowerShell
5464; не сломанное правило).

**Capture tail (закрыт):** backfill `pid`/`ppid` из Sysmon + eCAR; тест
`test_backfill_process_ppid_from_sysmon_and_ecar`.

#### 3e Panda — ключевые решения

| Компонент | Реализация |
|---|---|
| Вход | `WorldState.slice_through(stage)` — не прямой canonical list |
| Static v1 | `StaticWorldState.from_events()`; `apply`/`replan_tail` = no-op |
| Фазы | `initial_access` → `lateral_movement` → `staging` → `exfiltration` → `impact` |
| BLUF | Per-stage `recommended_actions`, `action_targets`, `premature_containment_trap` |
| Trap | Stage 0: `no_action` + `monitor`; premature isolation штрафуется |

**Colonial Panda (seed=42, window 08:00Z):** 5 stages; progression
initial → lateral → staging → exfil → impact.

#### Открытый вопрос (не блокирует)

`docs/OPEN_QUESTIONS.md` — когда именно `non_ransom_coordinated` vs `uncertain`
при 1 precursor category (временное правило задокументировано).

#### Финализация шага 3 — сквозные DoD-проверки (2026-07-11) ✅

После реализации всех 5 truth-проекторов выполнена финальная приёмка **не по
модулям**, а сквозными инвариантами.

| # | Проверка | Результат |
|---|---|---|
| 1 | **DP2 Panda** — `test_panda_ignores_ground_truth_labels`: обнуление `phase`/`attack`/`actor` на colonial-events не меняет per-stage containment в `panda.json` | PASS (правок `panda.py` не потребовалось — логика уже DP2-safe по `kind`/`fields`) |
| 2 | **Единый build** — `socbench truth build` без `--task` → ровно 5 task-manifest JSON в `grader/`; повторный прогон → идентичные SHA-256; порядок вызова задач не влияет | PASS |
| 3 | **Кросс-модульная консистентность** (`test_truth_consistency.py`) | PASS |

**`test_truth_consistency.py`:**

| Тест | Назначение |
|---|---|
| `test_all_manifest_evidence_ids_resolve` | Все `EVID-*` из fox/goat/mouse/tiger/panda (включая вложенные: edges, encrypted_paths, vss_events, …) резолвятся в `canonical_events.ndjson` |
| `test_no_truth_module_imports_another` | AST-проверка импортов в `socbench/truth/*.py` (кроме `common.py`, `__init__.py`): запрещены cross-import `socbench.truth.{fox,goat,mouse,tiger,panda}`; разрешены `common`, `errors`, `capture`, `stage` (Panda/WorldState), `evidenceforge.utils` |
| `test_forbidden_evidence_ids_empty_source_safe` | Colonial без helpdesk (шаг 4 ещё не реализован): `tiger.json` → `forbidden_evidence_ids == []`, без exception |
| `test_truth_build_writes_five_manifests_deterministically` | Ровно 5 json-файлов в output; стабильные хеши при двойном build и reverse-order |

**Colonial manifest SHA-256 (seed=42, window 08:00Z, post unified build):**

| Файл | SHA-256 |
|---|---|
| `fox.json` | `74fe0dd05e9d6fb01c841e55ac82679e4f88540e31d2a79575e160b46eac2d41` |
| `goat.json` | `47d0b2efd9408502c91d22addc767ab9018149e3d2ab34482260fa45c937b6a1` |
| `mouse.json` | `892b10c0e49a8d93f5070c8ca0ddb7ae65fe62aa5e50845965c719272dacc519` |
| `tiger.json` | `6bc35eb6c5348a45c1c12d2ff4fcbf7cedc66801e6693ba96632c66fe1a84010` |
| `panda.json` | `fec62e583c35691c7edda031d0e620c5adcb57ff8d94802dd549935ad0309e8a` |

Дополнительно: `tiger_ged_spec.json` (спека GED, не task-manifest).

**CLI-изменение:** `src/socbench/__main__.py` — `DEFAULT_TRUTH_TASKS =
("fox", "goat", "mouse", "tiger", "panda")`; без `--task` собираются все 5.

#### Верификация

`uv run pytest tests/socbench -v --no-cov` — **74/74 passed** (2026-07-11;
было 69, +5: `test_panda_ignores_ground_truth_labels` + 4 в
`test_truth_consistency.py`).

#### DoD шага 3 — чеклист

- [x] `socbench truth build` → все 5 манифестов (`fox`, `goat`, `mouse`, `tiger`, `panda`)
- [x] Fox: graph-based `o1_scale`, observable `o2_type`, cumulative `o3`
- [x] Goat: O1..O4 + manifest_thresholds; per-stage encrypted paths
- [x] Mouse: O1..O5 + tolerances; observation_status-agnostic
- [x] Tiger: verifiable/contextual edges + `tiger_ged_spec.json` + GED scorer
- [x] Panda: per-stage BLUF через `WorldState`-срез (static v1)
- [x] DP2: truth-модули не зависят от `phase`/`attack`/`actor` (тесты Fox/Mouse/Tiger/**Panda**)
- [x] Capture backfill из resolved refs (включая `pid`/`ppid` из Sysmon/eCAR)
- [x] Ни один truth-модуль не импортирует другой (AST-тест `test_no_truth_module_imports_another`)
- [x] Все manifest `evidence_id` резолвятся в canonical (`test_all_manifest_evidence_ids_resolve`)
- [x] `forbidden_evidence_ids` корректно пуст на colonial без helpdesk
- [x] Единый build детерминирован (двойной прогон → идентичные хеши)

---

## Шаг 4 — Недостающие источники + жёсткая привязка улик  🔶 [замечание 3]

`socbench/sources/`. Каждый источник читает canonical, пишет в `data/` (agent),
и — ключевое изменение — **несёт скрытый grader-блок**, невидимый агенту:

```json
{"ticket_id":"HD-9921","ts":"...","user":"jsmith","host":"WKS-01",
 "text":"файлы переименовались и не открываются, на рабочем столе записка",
 "__grader_metadata":{"linked_evidence_ids":["EVID-001044","EVID-001045"],
                      "latency_applied_ms":1800000,"template_id":"ransom_note_v3"}}
```
`__grader_metadata` вырезается при экспорте `agent/` (DP2-гейт, шаг 6) и остаётся
только в grader-копии. Это решает хрупкий маппинг текст→evidence_id.

**Детерминизм текста (устранение противоречия «LLM vs воспроизводимость»):**
- **По умолчанию — шаблоны** с детерминированными слотами (параметры из
  linked-события). EF гордится «no LLM calls, reproducible» — сохраняем это.
- LLM-перефразирование — **опционально** и **кэшируется** по ключу
  `(seed, template_id, linked_evidence_ids)`; повторный прогон берёт кэш →
  бинарная воспроизводимость. Без кэша LLM в data-path запрещён.

Источники: **vss.py** (backup-лог + дублирование в process-телеметрию),
**helpdesk.py** (поздние тикеты, гейтинг во 2-й половине — шаг 5),
**cti.py** (релевантные IOC/TTP + десятки trap-фидов; часть IOC = реальные
артефакты инцидента), **hostmetrics.py** (time-series CPU/mem/IO/net, всплески
при шифровании/эксфиле; DP4: часть хостов без метрик), **siem.py** (тонкий
rule-based слой поверх Windows/Zeek/ASA/Snort: severity, correlated hosts;
DP4-специфика — латентность/FP/FN на уровне правил; XDR-anomaly поверх eCAR).

### DoD
- Каждая атак-запись резолвится в canonical через `__grader_metadata`.
- FP-записи не несут атак-evidence_id.
- Текст детерминирован по seed (шаблоны; LLM только через кэш).

---

## Шаг 5 — WorldState, нарезка на стадии, шов под интерактив  🔶 [замечание А]

`socbench/stage/`. Прежняя нарезка + архитектурный шов под опц. интерактивный
Panda, **без обязательства строить attacker-response модель в v1**.

**Частично реализовано (2026-07-11):** `socbench/stage/world_state.py` —
`StaticWorldState` с `slice_through` / no-op `apply` / `replan_tail`; используется
Panda truth-проектором. `bucketize.py` и interactive apply/replan — в backlog.

### world_state.py — абстракция состояния между стадиями
```python
@dataclass
class Intervention:               # containment-команда агента (интерактив. режим)
    kind: str                     # isolate_host | block_egress | disable_account | segment_change
    targets: list[str]
    at_stage: int

class WorldState:
    def slice_through(self, stage:int) -> list[Event]: ...        # улики ≤ конца стадии
    def apply(self, iv:Intervention) -> "WorldState": ...          # патч мира
    def replan_tail(self, from_stage:int) -> list[Event]: ...      # пересбор хвоста
```
- **Статический режим (v1-функциональность):** `apply` = no-op, `replan_tail` =
  исходный хвост. Всё работает как обычный экспорт. **Это единственный
  обязательный режим для первой публикации.**
- **Интерактивный режим (future / опц.):** после стадии N движок принимает
  `Intervention`, `apply` патчит сценарий (segment/account), `replan_tail`
  перегенерирует хвост через **детерминированный ре-ран EF** с
  пропатченным scenario. Panda-truth пересчитывается на новом хвосте.
  - Известное усложнение: ре-ран меняет `evidence_id` хвоста → нужна политика
    стабильности id (префикс по стадии + пересвязка). Задокументировать; это
    сознательно вынесено в future work, а не в v1.

### bucketize.py — нарезка + инкрементальный гейтинг
- Разложить `data/` и canonical по 30-мин стадиям (`floor(Δt/30m)`).
- `agent/stage_XX/` = записи с `ts ≤ конец XX`; late-источники (helpdesk,
  CTI-user) гейтятся по `stage ≥ N/2` (§8.2).
- Ссылка на улику из будущей стадии = нарушение (для грейдера).

### DoD
- Статический режим: `--stream-by-stage` даёт `agent/stage_00..K/`;
  late-источники пусты в ранних стадиях.
- `WorldState.apply/replan_tail` реализованы как no-op для статики + имеют
  явный интерфейс под интерактив (тест интерфейса, не поведения).

---

## Шаг 6 — Сборка датасета + DP2-гейт  🔶

`socbench/export_dataset.py` + CLI:
```
python -m socbench build --scenario scenarios/colonial-pipeline/scenario.yaml \
  --seed 42 --tasks fox,goat,mouse,tiger,panda --stream-by-stage --out ./dataset/
```
Раскладка `agent/` (стадии + `topology.json`) и `grader/`
(`canonical_events.ndjson`, 5 манифестов, `evidence_registry.json`) — как в v1.

**DP2-гейт (усилен под шаг 4):** `export_agent()` вырезает из всех записей
`phase/attack/actor/evidence_id/observed_by/__grader_metadata`. Тест: в
`agent/**` ни одного из этих полей и ни одного файла из `grader/`. Экспортёр
agent физически не импортирует `socbench/truth`.

### DoD
- `build` из чистого форка → полный `dataset/` одной командой.
- Повтор с тем же seed → идентичные хеши.
- Тест DP2-гейта (включая отсутствие `__grader_metadata` в `agent/`) проходит.

---

## Шаг 7 — Нативные бинарники: Zeek-canonical, без scapy-PCAP  🔶 [замечание В]

**Изменение против v1:** сеть отдаётся как **Zeek/flow NDJSON — базовый и
достаточный** сетевой источник (так её и потребляет современный SOC). Обратный
инжиниринг `.pcap` из conn-метаданных через scapy **исключён** — он порождает
детектируемые артефакты (кривое рукопожатие, шаблонный TLS-hello, синтетические
дельты), на которых агент учится вместо реальных аномалий (нарушение DP1).

Бинарные форматы, которые остаются осмысленными (хостовые, структура уже готова):
1. **.evtx** — из `windows_event_security.xml` EF собрать нативный EVTX
   (Windows-контейнер + `wevtutil`/Event Log API → экспорт).
2. **.journal** — из `syslog.log` (RFC5424) залить в `systemd-journald` через
   `systemd-journal-remote` → нативный `.journal`.

**Если raw .pcap всё же критичен** (см. отклонения): генерить его **только** на
уровне ядра EF реальным запуском сетевых демонов в контейнеризованной топологии,
а не обратным инжинирингом металогов. Это отдельная тяжёлая задача — вне v1.

### DoD
- `.evtx` парсится Chainsaw, поля = `windows_event_security.xml`.
- `.journal` читается `journalctl --file`, поля = `syslog.log`.
- Сетевой домен документирован как Zeek/flow-canonical; scapy-PCAP отсутствует.

---

## Сквозные модули (новое, tool-релевантная часть раздела 4)

### mutate/augment.py — робастность оцениваемых систем  [замечание 4]
Модуль data-augmentation для проверки, не завязаны ли агенты на конкретные
формулировки/индикаторы. Варьирует под управляемым seed: текстовые шаблоны
helpdesk, индикаторы CTI, имена хостов/аккаунтов, размещение сенсоров, тайминг.
Инвариант: мутация **не меняет ground truth-семантику** (те же evidence_id,
те же правильные ответы) — только поверхностную форму. Даёт семейство
семантически-эквивалентных инстансов для robustness-прогонов.

### integrity/signatures.py — защита от контаминации  [замечание 4]
Хеш-сигнатурный логгер: на каждый сгенерированный артефакт (и весь `dataset/`)
пишет стабильный хеш в `MANIFEST.json`. Позволяет будущим исследователям
проверять, не попал ли инстанс в обучающие выборки LLM. Дёшево, ожидаемо при
релизе бенчмарков.

### validate.py — валидатор консистентности
(1) все claim-evidence_id резолвятся; (2) helpdesk не в положительных уликах;
(3) `agent/` без grader-полей и `__grader_metadata`; (4) причинность не нарушает
время; (5) verifiable-рёбра Tiger восстановимы из `data/`.

### Швы под downstream-артефакты статьи (вне генератора, но подготовить)
Генератор должен облегчать то, что рецензенты потребуют, не строя это внутри:
- **Валидация грейдера людьми** — грейдер отделён от генератора и запускается на
  `grader/` манифестах, чтобы можно было сравнить его оценки с ручными отчётами
  L2/L3-аналитиков (Cohen's kappa). Требование к инструменту: манифесты
  самодостаточны и человекочитаемы.
- **Baseline-агенты** — `agent/`-датасет самодостаточен для прогона внешних
  агентов (naive ReAct / SOTA multi-agent / random). Генератор их не содержит,
  но формат входа стабилен и документирован.

---

## Вехи (коммиты)

1. Форк + `eforge generate` на retail-примере (uv sync). ✅
2. Шаг 1: `capture/canonical_events` post-generation (ядро EF не тронуто). ✅
3. Шаг 2: сценарий Colonial Pipeline, `eforge eval` зелёный. ✅
4. Шаг 3: все 5 truth-проекторов (`fox`, `goat`, `mouse`, `tiger`, `panda`) +
   `common.py`, capture backfill (вкл. `pid`/`ppid`), `StaticWorldState` для Panda. ✅
5. Шаг 4: `siem`→`hostmetrics`→`vss`→`helpdesk`→`cti` со скрытыми `__grader_metadata`; текст детерминирован.
6. Шаг 5+6: `world_state` (interactive apply/replan — future) + `bucketize` + `export_dataset` + DP2-гейт + `validate`.
7. Сквозное: `mutate/augment` + `integrity/signatures`.
8. Шаг 7 (опц.): `.evtx` → `.journal`. Raw PCAP — только через контейнерные демоны, вне v1.

---

## Отклонения от спецификации статьи (решить авторам явно)

Три ревизии уводят от буквального текста SOC-bench — это осознанные инженерные
решения, которые нужно проговорить в статье (в Limitations/Design Rationale),
иначе рецензент поймает на непоследовательности:

1. **Сеть = Zeek/flow, а не raw .pcap** (Mouse/Tiger в тексте говорят «агент
   получает оригинальный .pcap»). Обоснование: raw-реконструкция нарушает DP1;
   flow-логи — как реальный SOC потребляет сеть.
2. **Граф Tiger оценивается мягкой метрикой** (Table 3 подразумевает жёсткий
   per-edge штраф). Обоснование: справедливость к логически верным
   реконструкциям; verifiable-остов остаётся жёстким.
3. **Интерактивный Panda — опц. режим сверх §9.4** (статья описывает статичную
   per-stage оценку). Обоснование: полноценный incident-response feedback loop;
   в v1 — только шов, полноценный режим = future work.
