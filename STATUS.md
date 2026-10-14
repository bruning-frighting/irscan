# STATUS.md

Updated after every phase. States what was done, what was **verified** (with evidence and the
environment it was verified in), what failed, and what remains.

**Reading rule:** "verified" here always names an environment. Anything not run is called
unverified, never implied to work.

---

## Environment of record

Everything below was executed in this environment unless stated otherwise.

| | |
|---|---|
| Host OS | Microsoft Windows 11 Home Single Language, build 26200 |
| Privilege | `KAIZ3N\thong`, **not elevated** (`IsInRole(Administrator) = False`) |
| Smart App Control | **ON** — `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState = 1` |
| Linux | WSL2 **Kali GNU/Linux Rolling 2026.1**, kernel `6.6.87.2-microsoft-standard-WSL2`, user `kali` (uid 1000, in `sudo` group) |
| Go | `go1.27.2 linux/amd64`, installed at `/home/kali/toolchain/go` **inside WSL2** |
| Python | CPython 3.14.5 (Windows), stdlib only |
| Network | Available at build time; `raw.githubusercontent.com` and `go.dev` reachable |
| git | 2.x, repository initialised at `C:\Users\thong\Downloads\irscan` |

---

## Phase 0 — ATT&CK registry builder — **GATE PASSED**

### What was done

- `build/fetch_stix.py` — fetches the pinned ATT&CK STIX bundle, verifies SHA-256 and size
  against `build/sources.lock.json`, and treats a mismatch as fatal. Records the required MITRE
  attribution. Has `--verify-only` and an explicit `--repin`; on network failure it prints the
  path at which a locally supplied bundle may be placed rather than silently working around the
  block.
- `build/sources.lock.json` — pins ATT&CK Enterprise **v20.0**, URL, size, SHA-256,
  `retrieved_at`, licence and required attribution; also records both Go toolchain archive
  hashes and an intentionally empty runtime-dependency list.
- `build/registry_builder/` — stdlib-only package:
  `stixload.py` (bundle indexing, relationship resolution), `classify.py` (testability rules +
  baseline status), `scope.py` (scope constants, each citing its DECISIONS.md entry),
  `emit.py` (byte-deterministic writers), `build.py` (orchestration + all denominators).
- `build/build_registry.py` — CLI with `--check-determinism` implementing the Phase 0 gate.
- `build/query_registry.py` — reviewer utility so the review pass can recompute and spot-check
  from the built artefact rather than trusting the build log.
- `data/overlay/log_source_taxonomy.json` — maps ATT&CK v20 log-source names to evidence
  categories. Key set enumerated **mechanically** from the bundle (399 distinct names, 146
  prefixes), not invented.
- `data/overlay/technique_families.json` — curated artifact / memory / network family signals,
  keyed by top-level technique ID, each with a stated reason.
- `data/overlay/testability_overrides.json` — 2 reviewed overrides, each with a reason.
- `NOTICE` — MITRE attribution, licence terms, MITRE's own coverage disclaimer, toolchain hashes.

### Generated and bundled (`data/registry/`)

| File | Rows | SHA-256 |
|---|---|---|
| `attack_registry.json` | 867 techniques | `c7be7ff4f8d690ea6cbabbab2eacdbf10680a8c073e6049d9c585ee3b17d4c83` |
| `attack_registry.csv` | 867 + header | `098c56f7599514d4b354f027c87f680a5f206f27f5e0bcc04b9369a3c94cb2c0` |
| `revoked_deprecated.csv` | 161 + header | `4e44cd3f0c068327a65e3c47f5c4b331023fc49f62a967e9abd3798d3b594154` |
| `classification_audit.csv` | 511 + header | `c6cce454cd41d5a340a6318b68ebce4d7a81518eafe224c14a4c0963189fddc9` |
| `registry_meta.json` | — | `99c6a9c5bfbdadb4cfc57772bcc06066259f6ffa121addb5b9a68bd3d945d517` |

`registry_meta.json` records the hashes of the other four outputs; its own hash is listed here
because a file cannot contain its own digest. Row counts independently confirm the
denominators: 867 = `U_bundle`, 161 = inactive, 511 = `U_host`.

### Gate evidence — all four criteria

Command: `python build/build_registry.py --check-determinism` (Windows, CPython 3.14.5).

1. **Two runs on the same input give identical output hashes** — `GATE: PASS - two runs
   byte-identical`. All five outputs matched across two builds into separate temp directories.
   Achieved by: `sort_keys=True`, fixed `\n` line terminators, UTF-8 without BOM, and **no
   wall-clock timestamp anywhere in the outputs** — the only recorded time is the pinned
   source's `retrieved_at`, which is an input.
2. **Counts and denominators documented** — computed in one place (`build._counts`) and written
   to `registry_meta.json`:

   | Universe | Count |
   |---|---|
   | `U_bundle` — all attack-patterns | **867** |
   | `U_active` — minus revoked/deprecated | **706** |
   | `U_host` — active ∧ (Windows ∨ Linux) | **511** (179 top-level, 332 sub) |
   | `U_impl` — `U_host` ∧ 4 scope tactics | **296** (69 top-level, 227 sub) |
   | `U_impl` as (technique, OS) pairs | **436** (windows 269, linux 167) |

   Per-tactic `U_impl` (a technique in two scope tactics counts in both here, but **once** in
   `U_impl`): stealth 141, persistence 91, credential-access 58, defense-impairment 35.
3. **Every in-scope technique has a testability class** — `UNDETERMINED = 0`,
   `U_host_unclassified = 0`. Distribution over `U_host = 511`: MIXED 203 (39.7%),
   HOST_TELEMETRY 304 (59.5%), HOST_ARTIFACT 1 (0.2%), OFF_HOST 3 (0.6%).
4. **Revoked and deprecated reported separately** — 149 revoked + 12 deprecated + 0 both = 161
   rows in `revoked_deprecated.csv`, excluded from every live denominator, retained in the
   registry for traceability with their `revoked_by` target resolved.

Data quality: **0 parse anomalies, 0 unclassified log sources.**

### Defects found and fixed during Phase 0

1. **Classifier over-attribution (serious).** The first build classified **492 of 511 (96.3%)**
   in-scope techniques as `MIXED` — a meaningless result. Cause: `detection_for()` expanded each
   referenced data component's *entire* `x_mitre_log_sources` list, so a component like "File
   Modification" injected dozens of cross-platform log sources into techniques whose analytics
   never cite them. Fix: use only the analytic's own `x_mitre_log_source_references`; keep the
   component *name* for context. Result: MIXED fell to 203 (39.7%) with
   HOST_TELEMETRY at 304. Rationale is recorded in a code comment at the fix site.
2. **False parse anomalies.** 16 sub-techniques were flagged as missing their `subtechnique-of`
   relationship. All 16 are revoked (all 13 `T1562.*`, plus `T1053.001`, `T1070.001/.002`,
   `T1547.011`); ATT&CK deliberately drops that relationship on revocation. Fix: derive the
   parent from the ID as a fallback, record **how** it was resolved in `parent_id_source`, and
   flag an anomaly only for *active* sub-techniques. Anomalies: 16 → 0.
3. **Three unclassified log sources** (`FirmwareLogs:Update` ×116, `network:runtime` ×116,
   `network:auth` ×55) — added `firmwarelogs` and `network` prefixes. Also reclassified the `fs:`
   prefix from `artifact` to `generic_telemetry`: `fs:fileevents`/`fs:fsusage` are file-event
   telemetry, not durable state. Unclassified: 3 → 0.
4. **Two `UNDETERMINED` techniques** — `T1698` / `T1699` (Indirect / Direct Prompt Injection).
   ATT&CK v20.0 ships **no** detection strategy or log source for either, so no rule could fire.
   Resolved with reviewed overrides to `OFF_HOST` (evidence is the LLM application's own
   prompt/tool-call records, not host state), each with a written reason. Both are tactic
   `execution`, so outside implementation scope regardless.

### Verified facts established (cited, not assumed)

- **ATT&CK v20.0 has no "Defense Evasion" tactic.** `TA0005` is **"Stealth"**; `TA0112`
  **"Defense Impairment"** is new. Confirmed in the pinned bundle's `x-mitre-tactic` objects
  *and* independently on <https://attack.mitre.org/tactics/enterprise/> (retrieved 2026-10-14),
  which lists 15 tactics and no "Defense Evasion". Scope consequence recorded as C-001/D-002.
- **`T1562` "Impair Defenses" and all 13 of its sub-techniques are revoked**, each with an
  explicit `revoked-by` target (`T1562` → `T1685` Disable or Modify Tools; `T1562.002` →
  `T1685.001`; `T1562.004` → `T1686`; `T1562.009` → `T1688`; `T1562.010` → `T1689`;
  `T1562.003` → `T1690`; and so on). Read from the bundle's `revoked-by` relationships.
- **ATT&CK v20.0 dropped `x_mitre_detection`, `x_mitre_data_sources`,
  `x_mitre_defense_bypassed` and `x_mitre_permissions_required` from `attack-pattern` objects**
  — measured: 0 of 867 carry any of them. Detection content moved to 705
  `x-mitre-detection-strategy` and 1,770 `x-mitre-analytic` objects. The builder reads either
  representation, so a v19 pin still works.
- 508 of the 511 in-scope techniques have at least one detection strategy.

### What is NOT yet true

- No scanner exists yet. The registry's `baseline_implementation_status` is `PLANNED` for 508
  in-scope techniques and `UNSUPPORTED` for 3. **Nothing is `IMPLEMENTED`** — by construction,
  the registry builder cannot emit `IMPLEMENTED` or `PARTIAL` (D-009); only the Go check
  inventory can, and only through the per-check quality gate.
- Coverage metrics M3–M6 are therefore all `0 / 296` or undefined at this point. Not padded.

---

## Phase 1 — Skeleton and pilot — NOT STARTED

---

## Blockers carried forward

| ID | Blocker | Effect |
|---|---|---|
| **B-001** | Smart App Control ON + not elevated ⇒ no unsigned binary can execute on this host | `irscan.exe` cannot be **run** here. **No Windows check can reach `LAB_VERIFIED` this session.** Not worked around — bypassing a host security control is a hard stop. |
| **B-002** | No real Windows Server, no domain, no elevation | Checks needing elevation or a DC (`T1003.003`, `T1003.006`, `T1556.001`, Security-log reads) cannot be exercised privileged. Their `PERMISSION_DENIED` path *is* genuinely testable here by running unprivileged. |
| **D-001** | Authoritative spec document absent from the session | The "six coverage metrics" are a documented **reconstruction**, flagged in `PLAN.md` §4 and in report headers. |

---

## Hard stops encountered

| What | Decision |
|---|---|
| Disabling Smart App Control to run the Go toolchain / built binary on Windows | **Refused.** Requires elevation I lack, is irreversible on Windows 11, and weakens the user's host security posture. Recorded as B-001; Go moved into WSL2 instead. |
