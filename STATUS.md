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

## Phase 1 — Skeleton and pilot — **GATE PASSED**

### What was built

~9,700 lines of Go (36 files, standard library only) plus ~1,850 lines of build-time Python.

| Package | Lines | Role |
|---|---|---|
| `internal/model` | 604 | Data contracts; **enforces** "missing data is never NOT_DETECTED" |
| `internal/safety` | 199 | Limits, budgets, timeouts, write-confinement guard, network-FS detection |
| `internal/collect` | 2,492 | Collector interfaces, root-relocatable FS, Linux collectors, Windows registry, fakes |
| `internal/check` | 1,011 | Check interface, Env, quality gate, mapping validator, evidence helpers |
| `internal/checks` | 3,087 | The five pilot checks + the gate/invariant test suite |
| `internal/registry` | 210 | Embedded ATT&CK registry loader |
| `internal/coverage` | 414 | The six metrics |
| `internal/report` | 594 | Three separate reports + evidence and scan manifests |
| `internal/module` | 390 | Module interface, attack module, not-implemented malware module |
| `internal/allowlist` | 167 | Scoped, expiring, non-silent suppression |
| `cmd/irscan` | 537 | CLI |

### The five pilot checks

| Check | ATT&CK | OS | Kind | Validation |
|---|---|---|---|---|
| `LNX-PERSIST-SYSTEMD-001` | T1543.002, T1543, T1053.006(partial) | linux | artifact | **LAB_VERIFIED** |
| `LNX-PERSIST-CRON-001` | T1053.003, T1053 | linux | artifact | **LAB_VERIFIED** |
| `LNX-PERSIST-SSHKEY-001` | T1098.004, T1098 | linux | artifact | **LAB_VERIFIED** |
| `LNX-DEFIMP-AUDITD-001` | T1685.004, T1685 | linux | **telemetry** | **LAB_VERIFIED** |
| `WIN-PERSIST-RUNKEY-001` | T1547.001, T1547, T1112(partial) | windows | artifact | FIXTURE_TESTED (capped by B-001) |

### Gate evidence

1. **All pilot checks pass all four test cases.** 5 checks × 4 cases = 20 case assertions, plus
   7 supporting tests. `go test ./...` → `ok irscan/internal/checks`. The gate is
   **machine-verified**: each check supplies its four cases as data and a generic runner
   executes them, so a check cannot self-certify. `check.EvaluateGate` additionally verifies
   overlay completeness, documented privileges and failure modes, escalation criteria,
   false-positive handling and an honest validation status.
2. **The Linux binary runs.** `dist/irscan-linux-amd64` executed against the **live** WSL2
   Kali root filesystem, unprivileged (uid 1000), scan_id
   `irscan-20261014T044834Z-7b0a0cd0`. Result: 441 real systemd units and 89 real cron
   entries inventoried, 0 false positives, outcomes `NOT_DETECTED=1, PARTIAL_DATA=2,
   INSUFFICIENT_DATA=1`.
3. **The Windows binary is built and statically checked only.** `GOOS=windows go build` and
   `GOOS=windows go vet` both pass; `dist/irscan-windows-amd64.exe` is produced.
   **It has never been executed** — Smart App Control blocks unsigned binaries on the only
   Windows host available (B-001). This limit is stated in the README, in `M5`'s note, and
   enforced by `TestWindowsChecksAreNotLabVerified`.
4. **Effort per pilot check** — measured as source size and defects found. Wall-clock
   authoring time was *not* instrumented, so none is claimed.

   | Check | impl. lines | defects found by its own fixtures / lab run |
   |---|---|---|
   | systemd | ~380 (in `persist_lnx.go`, 728 total with cron) | 2 (symlink mode bits; masked units) |
   | cron | ~350 (same file) | 2 (whole-command `/tmp` match; `perl -e` pattern) |
   | sshkey | 349 | 1 (denied-vs-absent in home directories) |
   | auditd | 581 | 1 (criteria evaluated against unread data) |
   | runkey | 530 | 1 (Startup folder is itself under `%ProgramData%`) |

   Shared: `common.go` 315, test suite 584, fixtures 50 files.

### Defects found and fixed in Phase 1

Every one of these was found by a test case or the real-host run, not by inspection.

1. **Windows check silently excluded from the build (most serious).** The check lived in
   `internal/checks/persist_windows.go`; Go treats a `_windows.go` filename suffix as an
   implicit `GOOS` build constraint, so the file was dropped from the Linux build, the check
   was never registered, and the gate suite passed while testing **4 of 5** checks. Nothing
   errored. Fixed by renaming to `persist_win.go`, and locked in by two new tests:
   `TestExpectedChecksAreRegistered` (asserts the inventory by name) and
   `TestNoAccidentalPlatformConstrainedCheckFiles` (rejects the filename pattern).
2. **False positives manufactured from unreadable data.** The auditd check concluded
   "configured but no rules" when the truth was "`/etc/audit` is mode 0750 and this scan is
   unprivileged". Caught by the permission-denied fixture. Fixed by having the collector
   distinguish *read it, found nothing* from *could not read it*
   (`ConfigReadable`, `RuleFilesRead`, `LogStateKnown`, `PermissionError`) and gating every
   criterion on it.
3. **43 false positives on a clean host: symlink permission bits.** A symlink's own mode is
   always `lrwxrwxrwx`, so the world-writable criterion fired on every symlinked unit.
4. **6 false positives on a clean host: masked units.** `/etc/systemd/system/X.service ->
   /dev/null` is systemd's standard way to **disable** a unit — the opposite of persistence —
   and was being reported as vendor shadowing.
5. **1 false positive on a clean host: stock Debian `apt-compat`.** `eval $(apt-config shell
   ...)` matched the encoded-execution pattern. Narrowed to `eval $(curl|wget|fetch ...)`.
6. **Negative-fixture precision bugs, caught before the lab run.** Matching `/tmp` anywhere
   in a command flagged the benign `curl -s -o /tmp/metrics.json` monitoring pattern; and
   `perl -e 'sleep int(rand(43200))'` (the real certbot cron line) matched the interpreter
   clause. Both narrowed to inspect the *executable*, not the whole command string.
7. **Misleading `PARTIAL_DATA` reason.** The report said "truncated by safety limit" when the
   real cause was a permission denial. Split into distinct `Truncated` and `Incomplete`
   source states so the analyst is told the true cause of a visibility gap.
8. **`Exists()` collapsed denied and absent.** An unprivileged scan of root's `0700` home
   reported "no SSH keys" instead of "could not look". Now uses `Stat` and branches on
   `ErrPermission`.

   False positives on the live host: **44 → 0**, with every fixture positive still detecting.

### Observed real-host behaviour (the point of the lab run)

| Check | Outcome | Why — exactly as reported by the tool |
|---|---|---|
| `LNX-PERSIST-SYSTEMD-001` | `NOT_DETECTED` | 441 units read in full; nothing matched |
| `LNX-PERSIST-CRON-001` | `PARTIAL_DATA` | "partially readable: cron tables" — genuine denial on `/var/spool/cron/crontabs` |
| `LNX-PERSIST-SSHKEY-001` | `PARTIAL_DATA` | `/etc/shadow` and `/root/.ssh` unreadable unprivileged |
| `LNX-DEFIMP-AUDITD-001` | `INSUFFICIENT_DATA` | audit subsystem genuinely absent — **real** confirmation of the no-data path |

M6 for that scan: **1/4 = 25.0%** (denominator: checks executed). Three of four checks could
not give a determinate answer on a stock unprivileged host — which is the honest picture of
what retrospective host scanning sees, and precisely what the metric exists to show.

### Coverage at end of Phase 1 (computed by the tool, not by hand)

| Metric | Value |
|---|---|
| M1 registry completeness | 867/867 = 100.0% (U_bundle = 867) |
| M2 classification completeness | 511/511 = 100.0% (U_host = 511) |
| M3 implementation coverage | **10/296 = 3.4%** (U_impl = 296) |
| M4 partial coverage | 2/296 = 0.7% (U_impl = 296) |
| M5 validation coverage (LAB_VERIFIED) | 4/5 = 80.0% — beside it, not added in: FIXTURE_TESTED 1/5, UNTESTED 0/5 |
| M6 runtime data availability | per scan; 1/4 on the run above |

M3 per tactic: persistence 8/91, defense-impairment 2/35, stealth 0/141, credential-access
0/58. These numbers are low and are not padded.

### Built artefacts

`dist/irscan-linux-amd64` and `dist/irscan-windows-amd64.exe`, built reproducibly with
`-trimpath` from Go 1.27.2 in WSL2; hashes in `dist/SHA256SUMS`. The Windows binary is
**unverified at runtime**.

---

## Phase 2a — Persistence (Linux and Windows) — **GATE PASSED**

Six checks added, taking the inventory to **11**. Every one passes the full per-check quality
gate (`check.EvaluateGate` plus its four executed test cases).

| Check | ATT&CK (non-partial) | OS | Validation |
|---|---|---|---|
| `LNX-PERSIST-SHELLRC-001` | T1546.004, T1546 | linux | **LAB_VERIFIED** |
| `LNX-PERSIST-RCSCRIPT-001` | T1037.004, T1037 | linux | **LAB_VERIFIED** |
| `LNX-PERSIST-ACCOUNT-001` | T1136.001, T1136, T1098.007, T1098 (T1078.003 partial) | linux | **LAB_VERIFIED** |
| `WIN-PERSIST-SERVICE-001` | T1543.003, T1543 | windows | FIXTURE_TESTED (B-001) |
| `WIN-PERSIST-SCHTASK-001` | T1053.005, T1053 | windows | FIXTURE_TESTED (B-001) |
| `WIN-PERSIST-REGLOADPOINT-001` | T1547.004, T1547.002, T1547.005, T1547, T1546.010, T1546.012, T1546, T1556.002 | windows | FIXTURE_TESTED (B-001) |

Two reusable collectors were added, both deliberately derived from the registry and
filesystem interfaces rather than from new native APIs — which is what keeps them
fixture-testable under B-001:

- `collect.WindowsServices` reads `HKLM\SYSTEM\CurrentControlSet\Services`, resolves
  `ImagePath` quoting and the `\??\` / `\SystemRoot\` prefixes, and **also reads
  `Parameters\ServiceDll`** — the svchost service-DLL hijack an ImagePath-only review misses.
- `collect.WindowsScheduledTasks` parses Task Scheduler XML, decoding UTF-16LE/BE and UTF-8.

`WIN-PERSIST-REGLOADPOINT-001` covers six sub-techniques in one check because they are one
evidence shape (a named registry value compared against a documented default). Attribution
is **per artifact**: the `Userinit` finding cites T1547.004 only, the `Notification Packages`
finding cites T1556.002 only, the IFEO finding cites T1546.012 only. The positive fixture
asserts all three independently.

### Defects found and fixed in Phase 2a

1. **Microsoft's own scheduled tasks are hidden AND run as SYSTEM.** `TASK-C3` as first
   written fired on `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan` and
   `\Microsoft\Windows\Defrag\ScheduledDefrag` — i.e. on every Windows host. Caught by the
   negative fixture. The criterion now additionally requires the task to be **outside** the
   `\Microsoft\` namespace, and the Limitations section states plainly that this is noise
   reduction, not a boundary: a task planted under `\Microsoft\Windows\` evades it.
2. **A real false positive on the live host: Debian's `postgres` account.** The postgresql
   package creates `postgres` with `/bin/bash`, so `ACCT-C3` fired on every PostgreSQL host.
   Fixed with a documented known-shell-bearing-accounts list that applies **only** when the
   account is not uid 0 and not in a privileged group, so it cannot launder a backdoor named
   after a service; the account still appears in Inventory.
3. **Go's XML decoder rejected real Task Scheduler files.** Task XML declares
   `encoding="UTF-16"`, which `encoding/xml` refuses without a `CharsetReader` even after the
   bytes have been converted. Fixed with a pass-through `CharsetReader`. Without this, every
   real task file would have been reported as a parse error.
4. **Scheduled-task criterion inspected only `<Command>`.** The usual shape is
   `Command=powershell.exe` with the staged payload path in `<Arguments>`, so the
   transient-directory criterion missed it. Now evaluated against the full action, while
   still only descending into arguments for known interpreters so a task that merely *writes*
   to `%TEMP%` does not match (that case is in the negative fixture).
5. **The read-only guard test was too crude.** It banned the substring `lsass`, and so failed
   on documentation prose explaining why LSA registry load points matter. Naming a process in
   a comment is not reading its memory; the guard now bans the actual APIs
   (`OpenProcess`, `ReadProcessMemory`, `MiniDumpWriteDump`, `process_vm_readv`, `ptrace`,
   `/proc/self/mem`).

### Real-host validation (live WSL2 Kali, unprivileged)

`scan_id irscan-20261014T051011Z-46209192`, 7 Linux checks executed, **598 inventory items,
0 findings, 0 false positives**. Outcomes: `NOT_DETECTED=2, PARTIAL_DATA=4,
INSUFFICIENT_DATA=1`; M6 = 2/7 = 28.6%. The four `PARTIAL_DATA` results are genuine and
correctly explained (`/etc/shadow`, `/root/.ssh`, `/var/spool/cron/crontabs` and other users'
dotfiles are unreadable without root).

### Coverage after Phase 2a

| Metric | Phase 1 | Phase 2a |
|---|---|---|
| M3 implementation coverage | 10/296 = 3.4% | **25/296 = 8.4%** |
| M4 partial coverage | 2/296 | 3/296 = 1.0% |
| M5 validation (LAB_VERIFIED) | 4/5 = 80.0% | **7/11 = 63.6%** (FIXTURE_TESTED 4/11 beside it, never added in) |

M3 per tactic: **persistence 23/91**, defense-impairment 2/35, stealth 0/141,
credential-access 0/58. (technique, OS) pairs: linux 15/167, windows 13/269.

M5 *fell* in percentage terms because the three new Windows checks cannot be lab verified
under B-001. That is the honest direction for that metric and it is not adjusted.

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
