# SOC-bench open questions

Items here need author/paper clarification before we treat the implementation as
final. Until resolved, the codebase uses the documented temporary behavior.

---

## Fox `o2_type`: `uncertain` vs `non_ransom_coordinated`

**Source:** Interpretation guidance for Fox task `type_label` (SOC-bench paper).

**Rule from text (partial):**

- Count **distinct precursor marker categories** cumulatively per stage:
  - `T1569.002` (PsExec-like remote service)
  - `T1021.002` (SMB/Admin Shares lateral movement)
  - Windows EventID `7045` / service creation
- ≥2 distinct categories → `ransomware_like`
- 1 category → `uncertain`, **or** `non_ransom_coordinated` when there is
  correlating activity without a full precursor pattern (exact wording unclear)
- 0 categories → `uncertain` by default (or no label if no attack activity)

**Question for authors:**

When exactly should `non_ransom_coordinated` apply?

1. Only when there is **1** precursor category plus multi-host correlation?
2. When there are **0** precursors but localized/campaign-scale correlation?
3. Some other split (e.g. coordinated non-ransom TTPs without encryption
   precursors)?

**Temporary behavior (2026-07-11):**

| Precursor categories | Scale | `type_label` |
|---|---|---|
| ≥2 | any | `ransomware_like` |
| 1 | `localized` or `campaign_scale` | `non_ransom_coordinated` |
| 1 | `isolated` | `uncertain` |
| 0 | any | `uncertain` |

Detection uses **observable** `kind` / `fields` only (not grader `attack` labels)
so Fox truth remains DP2-safe.

**Files:** `src/socbench/truth/common.py` (`classify_type_label`), `fox.json`
assumptions block.
