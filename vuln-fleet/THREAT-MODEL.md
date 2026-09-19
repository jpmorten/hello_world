# Threat Model

## Purpose and scope

vuln-fleet is a **defensive, decision-support** system. It discovers, correlates, scores, and reports security vulnerabilities across Stibo Software Group's in-scope assets (`scope/assets.yaml`). It does not exploit anything, does not remediate anything, and does not act on any system beyond reading configuration/telemetry (and, for a narrow, explicitly-authorized set of actions, sending read-only network probes). Every output is a report for a human to act on — findings, risk scores, and the remediation board are inputs to a decision, never the decision itself.

**Non-goals**, stated explicitly because a defensive tool that drifts into these is worse than useless:
- No exploit code, payloads, or credential-attack tooling anywhere in this repository (acceptance criterion, checked by review, not by a scanner this repo runs on itself).
- No autonomous remediation. Nothing in this codebase opens a PR, changes a config, rotates a credential, or disables an account.
- No active scanning outside `scope/authorized-active.yaml`'s signed, time-boxed records. A target that's in `scope/assets.yaml` is in scope for *read-only* assessment; it is not thereby authorized for anything that sends traffic to it.

## Actors and trust boundaries

| Actor | Trust level | Notes |
|---|---|---|
| Fleet operator (Security Ops) | Trusted | Can run sweeps, approve active-scan authorizations, edit `scope/*.yaml`, kill a run. |
| Orchestrator / Tier 1 / Tier 2 (`engine/*.py`, `.claude/agents/*.md`) | Trusted code, untrusted inputs | The code path itself is reviewed and version-controlled; everything it *ingests* (adapter responses, scanner output) is untrusted (see below). |
| Adapters (`adapters/*.py`) | Trusted code, untrusted network responses | `adapters/cve_intel.py` and `adapters/osv.py` are real network clients against public feeds (CISA KEV, FIRST.org EPSS, NVD, OSV.dev). Their responses are treated as data, never as instructions (see Prompt/data injection below). |
| Public intelligence feeds (KEV/EPSS/NVD/OSV.dev) | Untrusted, best-effort | Read-only, unauthenticated, third-party. A source being down, wrong, or slow degrades one field on one finding — it never crashes a run and never fabricates a worse or better answer than "unknown" (see `adapters/cve_intel.py`'s graceful-degradation design). |
| SOC / SIEM (log sinks) | Trusted consumer | Receives the hash-chained event stream. Treats it as authoritative once received; this repo is responsible for not lying to it. |
| A live Claude Code session running a Tier 1/Tier 2 agent | Trusted code, untrusted context | The `.claude/agents/*.md` definitions constrain tool access (`Read, Grep, Glob, Bash` — no `Write`/`Edit`) precisely because a subagent's own context can include untrusted adapter output. |

## Assets to protect

- **Scope integrity**: `scope/assets.yaml`, `scope/exclusions.yaml`, `scope/authorized-active.yaml`. If these are wrong, everything downstream is wrong — an excluded target gets touched, or an unauthorized active scan runs.
- **The event log**: `logs/<run_id>.ndjson`. This is the SOC's audit trail. Its hash chain (`engine/logbus.py`) exists so tampering is detectable, not so tampering is impossible — the log files themselves need normal filesystem access control, which is outside this repo's scope.
- **Findings and reports**: `reports/<run_id>/*`. Contain no raw secrets (see Data handling below) but do contain real asset names, owners, and vulnerability detail — reasonable to protect at the same sensitivity as an internal vulnerability report generally.
- **Credentials for real adapters**: none exist yet in this repo (the three real adapters — supply-chain, firmware-hardware, api-surface — are unauthenticated public feeds or unauthenticated spec fetches). When a credentialed adapter (CMDB, Defender, Wiz, Entra) is added, its credential handling is this threat model's responsibility to re-review at that time — nothing here should be read as already covering that case.

## Threats considered

### Prompt / data injection via ingested content
Adapter output, scanner output, and any future ticket/document ingestion is **data**, never instructions. Concretely:
- `adapters/*.py` return plain Python dicts that go straight into `schema/validate.py`'s schema check — there is no path from an adapter's returned string fields into a shell command, an eval, or a prompt that gets re-interpreted as instructions.
- The one place external content reaches an LLM's context at all is a live Tier 1/Tier 2 subagent reading adapter output as part of its own reasoning (once real, credentialed adapters exist and agents run live rather than through `engine/orchestrator.py`). The `.claude/agents/*.md` definitions restrict those agents to `Read, Grep, Glob, Bash` — no `Write`/`Edit` — so even a successful injection attempt in scanned content has no path to modify this repository's own code, scope config, or authorization records.
- **Gap, not yet built**: a dedicated `prompt_injection_suspected` finding type (mentioned in the original design brief) that flags adapter output containing instruction-like content (e.g. "ignore previous instructions", embedded markdown that looks like a system prompt) isn't implemented. Until it is, injection resistance rests entirely on adapters never being interpreted as instructions, not on active detection.

### Scope violation (touching something out of bounds)
Enforced in two independent places, deliberately redundant:
- `engine/scope.py`'s `ScopeModel.assert_in_scope()` / `check_active_authorization()` — called by `engine/orchestrator.py` before every worker's adapter call. This is what a live `engine.orchestrator.Orchestrator.run()` actually goes through.
- `.claude/hooks/scope_guard.py` — a Claude Code `PreToolUse` hook that independently re-checks any Bash call that looks like an adapter invocation (`adapters/*.py --target ... --action ...`), fails closed if it can't extract a target, and logs every decision. This exists specifically so a live agent session that bypasses `engine/orchestrator.py` (e.g. a subagent improvising a Bash command instead of going through the Python API) still can't reach an out-of-scope or unauthorized target.

A target that fails either check is refused and logged as `scope_violation` — it never silently degrades to "best-effort" scanning, and it never halts the whole run (see coverage-gap handling in `engine/orchestrator.py` and the report suite in `engine/reports.py`).

### Runaway / unbounded execution
`engine/spawn.py`'s `SpawnManager` bounds this three ways: a hard depth cap (Tier 2 workers structurally cannot spawn children — the resulting tier would exceed `MAX_TIER`), per-domain concurrency budgets (excess spawns queue, they don't fail or run unbounded), and duplicate-spawn refusal keyed on `(domain, target_ref)`. `heartbeat()`/`check_liveness()` detect a hung agent by heartbeat-age alone and free its slot rather than blocking the run indefinitely.

### Inability to stop a run
`engine/orchestrator.py` checks a per-run kill flag (`reports/<run_id>.kill`, written by `python3 -m engine.cli kill` / the `/kill` slash command) between every target and before every domain. A run killed mid-flight still produces a full report suite, with every un-swept target recorded as a `kill_switch`-reasoned coverage gap — a killed run is a partial, honest report, not a crash or a silent gap (see `engine/tests/test_orchestrator.py`'s kill-switch tests for the exact behavior this guarantees).

### Bad or malicious third-party intelligence data
`adapters/cve_intel.py` and `adapters/osv.py` trust CISA/FIRST.org/NVD/OSV.dev to be correct; this repo does not independently verify their data. The realistic failure mode isn't a malicious payload (responses are parsed as JSON into typed fields, never executed) but *wrong* data — a feed reporting a CVE as not-KEV-listed when it actually is (observed and fixed once already: see the User-Agent/WAF issue in the step 7 commit history) degrades a risk score, it doesn't compromise the fleet. Both adapters fail closed on a source outage (conservative defaults: not KEV-listed, EPSS 0.0, no CVSS) rather than blocking the run or guessing.

### Secret exposure in findings/logs
No adapter returns a raw secret value; `.claude/agents/code-firstparty.md` explicitly instructs that a hardcoded-secret finding's `evidence_ref` points at the finding's *location*, never the secret's value. This is a documented convention enforced by review today, not by a runtime scrubber — a future adapter that handles raw scan output containing secrets (a real SAST tool's output, for instance) needs its own redaction step before anything reaches `schema/validate.py`, and that redaction does not exist yet because no such adapter exists yet.

## Human oversight (the EU AI Act–relevant part)

- **Every active-scan action requires a pre-existing, signed, time-boxed human authorization** (`scope/authorized-active.yaml`) — the system cannot authorize itself, and an expired or missing authorization is refused the same way an out-of-scope target is.
- **No autonomous action beyond read-only assessment.** The remediation board assigns an owner team and an SLA clock; it does not open a ticket, does not page anyone, and does not change anything. A human decides what happens next.
- **The kill switch is a human control**, reachable without needing to understand or modify the fleet's internals (`python3 -m engine.cli kill` / `/kill`).
- **Every decision the fleet makes is logged**, not just its conclusions: `scope_check`/`scope_violation` for every scope decision, `budget_exhausted`/`agent_error`/`kill_switch` for every operational refusal, hash-chained so a human reviewing the log afterward can trust it wasn't edited after the fact.

## Logging and accuracy characteristics

- **Determinism where it matters.** Scope resolution, deduplication, correlation, and risk scoring (`engine/scope.py`, `engine/dedupe.py`, `engine/risk.py`) are plain arithmetic and set operations, unit-tested, with no model judgement involved — the design brief's requirement that "agents reason about context and narrative; matching and scoring are code." A risk score is reproducible from a finding's own fields; it is not an LLM's opinion.
- **Known, documented limitations, not silent gaps:**
  - Correlation (`correlate_findings`) is CVE-keyed only. Two non-CVE findings that merely *look* related (shared wording, no CVE) are never merged — a false correlation would hide a real second issue, which is a worse failure than an extra line in a report.
  - `compliance-view.md` maps findings to regulatory *tags* (NIS2/CRA/ISO27001/GDPR), not to specific ISO 27001 Annex A control numbers — that mapping needs a control taxonomy this fleet doesn't implement, and inventing plausible-looking control IDs would be exactly the unevidenced number this project's own acceptance criteria forbid.
  - Effort estimates on the remediation board are declared per-domain policy defaults (a dependency bump is assumed cheaper than a network change), not a per-finding judgement — real effort can differ from the default, and the report says these are estimates, not facts.
  - Only three of nine domains (`supply-chain`, `firmware-hardware`, `api-surface`) have a real adapter; the other six run against `adapters/mock/*.py` synthetic data. Any report from a full sweep today is a proof of the pipeline, not a real security posture for the other six domains — this is stated in `README.md` and should be stated to any human reading a report from this system until real adapters exist for them.
- **Coverage is always quantified, never implied.** A domain or target that couldn't be assessed appears in `posture.md`/`by-domain.md` with its target and the exact reason (scope violation, budget exhaustion, adapter error, kill switch) — a confident-looking report over partial coverage is treated as a worse outcome than an explicitly incomplete one.

## Residual risks

| Risk | Current mitigation | Not yet done |
|---|---|---|
| A live agent session improvises a Bash command that bypasses `engine/orchestrator.py`'s scope checks | `.claude/hooks/scope_guard.py` independently re-checks Bash calls | Hook coverage depends on the `adapters/*.py --target ... --action ...` calling convention; a command that doesn't match that pattern isn't inspected at all (falls through to allow) |
| A future credentialed adapter (CMDB/Defender/Wiz/Entra) mishandles its credential | N/A — none exist yet | Credential handling review is required before any such adapter is merged |
| Prompt injection via scanned content once real, richer adapters exist | Least-privilege tool grants on Tier 1/Tier 2 agents | No active `prompt_injection_suspected` detection/finding type |
| A finding's secret-value redaction depends on adapter authors following convention | Documented in `.claude/agents/code-firstparty.md`, code-reviewed | No runtime scrubber; a careless future adapter could leak a value before review catches it |
