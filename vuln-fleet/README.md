# vuln-fleet

Hierarchical, orchestrated fleet of AI agents that continuously discovers and
reports security vulnerabilities across Stibo Software Group entities
(Stibo Software Group A/S, Stibo Systems, Stibo DX, and subsidiaries).

This is a **defensive security programme**: read-only by default, no
exploitation, active scanning gated on signed authorization records, and a
hard scope boundary enforced by a pre-tool guard hook. See `THREAT-MODEL.md`
(to come) for the full governance model.

## Status

Build is proceeding per the staged build order. Completed so far:

1. **Schemas locked** — `schema/finding.schema.json` (OCSF Vulnerability
   Finding-aligned) and `schema/event.schema.json` (the common log envelope),
   with `schema/validate.py` and a passing test suite in `schema/tests/`.
2. **Log bus** — `engine/logbus.py`: append-only, hash-chained NDJSON writer
   (`logs/<run_id>.ndjson`) with syslog (RFC 5424 over TLS) and generic
   webhook sinks. Every event is schema-validated before it's written. Sink
   failures spool locally instead of blocking the run; `flush_sinks()`
   replays the spool with backoff, preserving delivery order, and never
   drops a spooled event — one whose retries are exhausted is surfaced as a
   `sink_delivery_failed` event instead. Tests in `engine/tests/`.

3. **Scope model + pre-tool scope guard** — `scope/assets.yaml`,
   `scope/exclusions.yaml`, `scope/authorized-active.yaml` (example data;
   see the comments in each file) plus `engine/scope.py`, the deterministic
   resolver every scope decision goes through: does a target resolve to an
   in-scope asset, is it on the never-touch exclusion list, and — for
   active-scan actions specifically — is there a signed, in-window
   authorization covering it. `.claude/hooks/scope_guard.py` is the
   PreToolUse hook wired in `.claude/settings.json`: it inspects Bash calls
   that invoke an adapter (`adapters/*.py --target ... --action ...`),
   denies anything out of scope, excluded, or missing a target entirely
   (fail closed), and logs every decision — allow or deny — as a
   `scope_check`/`scope_violation` event via the same hash-chained logbus
   from step 2. The `VULN_FLEET_*` environment variables the hook reads
   (`RUN_ID`, `AGENT_ID`, `AGENT_ROLE`, `TIER`, `SPAN_ID`,
   `PARENT_AGENT_ID`, `PARENT_SPAN_ID`, `LOG_DIR`) are the contract
   step 4's spawn engine will set when it launches each agent.

4. **Spawn/budget engine** — `engine/spawn.py`: `SpawnManager` tracks
   lineage (agent_id/span_id/parent chain), enforces the tier-2 depth cap
   (a Tier 2 worker can never become a parent — the resulting tier would
   be 3, over the cap), refuses duplicate `(domain, target_ref)` spawns
   within a run, and gives each Tier 1 domain its own concurrency
   sub-budget (`allocate_sub_budgets` does the proportional, deterministic
   split of a global `max_concurrent` across domain weights). A domain at
   its budget ceiling queues further spawns instead of failing them, and
   `budget_exhausted` is logged once per domain, not once per queued
   request. `heartbeat()`/`check_liveness()` detect a hung agent purely by
   heartbeat age — an agent is reported stalled (once) and its slot freed
   for the next queued worker. `trigger_kill_switch()` is idempotent,
   blocks all further spawns, and returns the agent_ids that were running
   at the moment of the trigger so the caller can terminate/flush them.
   Every decision streams through the step-2 logbus as it happens.

5. **Orchestrator end-to-end (mock adapters)** — `engine/orchestrator.py`:
   `Orchestrator.run()` closes the full spawn → worker → rollup → log →
   report loop for `supply-chain` and `api-surface` (the two domains that
   need no active scanning), against `adapters/mock/*.py` synthetic
   adapters. A domain is a `DomainSpec` entry (targets + adapter_fn), not
   a code change — adding one is exactly the "declarative, extensible"
   shape the design calls for. Each target becomes a Tier 2 worker through
   `SpawnManager`; a target that's out of scope or excluded is refused via
   `engine/scope.py`, logged as a real `scope_violation` event, and
   recorded as a coverage gap on that domain's rollup — the run finishes
   regardless. Findings pass through `schema/validate.py` before they're
   logged or written anywhere. `engine/dedupe.py` (new, minimal by
   design) gives every finding a deterministic `finding_id`
   (CVE-based, falling back to title when there's no CVE) and collapses
   exact re-reports; the richer cross-domain correlation and baseline
   delta (new/resolved/recurring/regressed) are step 8's job. Every run
   writes `reports/<run_id>/findings.json` and a `posture.md` naming its
   coverage gaps by target and reason — the fuller report suite
   (by-domain/remediation-board/compliance-view, baseline-aware posture)
   is step 9's.

6. **Remaining Tier 1 agents and their worker patterns** —
   `engine/domains.py` adds the other seven domains from the design brief
   (`infra-network`, `infra-cloud`, `firmware-hardware`, `code-firstparty`,
   `identity-access`, `endpoint-posture`, `data-exposure`) alongside
   `supply-chain`/`api-surface`, as one `DomainRegistration` entry each:
   a `decompose_fn(scope_model) -> list[target_ref]` (its worker pattern)
   plus a mock `adapter_fn` — exactly the "new agent definition file plus
   a registry entry, nothing more" shape the design calls for.
   `engine.scope.ScopeModel.targets(scheme=..., asset_type=...)` is the
   new primitive every decompose_fn is built from — e.g. `infra-network`
   unions `cidr:` targets (one worker per subnet) with
   `network_device`-typed assets' targets (one worker per firewall
   platform), while `code-firstparty` and `supply-chain` deliberately
   decompose to the *same* repos (SAST and SBOM scanning the same asset is
   correct, and per-domain fingerprinting means it never collides).
   `build_domain_specs()` materializes a full (or subset) sweep from the
   registry against the live scope model. `scope/assets.yaml` grew four
   example assets (one each of type `network_device`, `firmware`,
   `data_store`, `cloud_resource`) so every domain has something concrete
   to decompose into; `location.kind` in `schema/finding.schema.json`
   gained `network_segment` to represent a subnet-level finding, the one
   gap step 1's schema had. `.claude/agents/*.md` adds the nine Tier 1
   subagent definitions (least-privilege tool grants, no Write/Edit) for
   when this runs as a live Claude Code fleet rather than through
   `engine/orchestrator.py` directly — each one points at its own
   `decompose_fn` rather than restating the worker pattern in prose. A
   full 9-domain sweep against the example inventory now runs end-to-end
   with zero coverage gaps.

7. **First real, read-only adapters** — `adapters/cve_intel.py` and
   `adapters/osv.py` are genuinely real, live integrations against public,
   unauthenticated intelligence feeds: CISA's KEV catalog, FIRST.org's
   EPSS API, NVD's CVSS data, and OSV.dev's dependency-vulnerability
   database. Each has exactly one HTTP seam (`_http_get_json` /
   `_http_post_json`) that's a real network call by default and the one
   thing tests monkeypatch with frozen fixture data to stay hermetic —
   the same pattern `SyslogSink`/`WebhookSink` used back in step 2.
   `adapters/supply_chain.py` combines them into the real replacement for
   `adapters/mock/supply_chain.py` in `engine/domains.py`'s registry (the
   mock stays in the repo; it's still what the step-5 test exercises
   directly). What's *not* real yet is the SBOM inventory itself — a
   small local package manifest stands in for a real SBOM-store/CMDB
   adapter — so this step's real value is specifically the vulnerability
   *lookup*, not a fabricated finding count.

   Verified against live data, not just fixtures: `supply_chain.scan()`
   run against `repo:stibo/checkout`'s one example package
   (`lodash@4.17.15`) returns the real current OSV.dev advisories for it
   (6, at time of writing) with real CVE ids, EPSS scores, and CVSS
   scores; `cve_intel.enrich_cve("CVE-2021-44228")` (Log4Shell) correctly
   comes back KEV-listed / `known_exploited` against the live CISA feed.
   That live check caught a real bug before it shipped: CISA's KEV feed's
   WAF 403s a User-Agent containing the phrase "security scanner"
   specifically (confirmed by direct A/B curl testing), which was silently
   swallowed by this module's own by-design graceful degradation (a
   source failure reads as "not KEV-listed," not a crash) — exactly the
   failure mode that's dangerous to get silently wrong. Fixed by using a
   contact-URL-style User-Agent instead, and added a one-retry-with-backoff
   to both HTTP seams so a single transient block or rate limit doesn't
   read as clean.

8. **Dedupe, correlation, risk scoring, baseline delta** —
   `engine/risk.py`: `score_finding()` is a deterministic 0–100 blend of
   CVSS severity (50%), likelihood (30% — EPSS, or forced to 1.0 when
   KEV-listed), and asset criticality (20%), with a KEV multiplier on top
   so a confirmed-exploited finding always outranks an equally-scored
   probable one. It's additive, not multiplicative, on purpose: a CVSS
   9.8 with near-zero EPSS still carries roughly half its weight from
   severity alone, instead of collapsing toward zero the way a pure
   CVSS×EPSS product would. `score_issue()` aggregates a correlated
   group's worst exposure with an exposure-breadth boost (capped
   at +50%) — the same CVE live in five places is worse than live in one.
   `engine/dedupe.py` gained `correlate_findings()`: findings sharing a
   CVE become one issue with multiple exposures (domains/assets/
   finding_ids), deliberately CVE-keyed only — a shared GHSA with no CVE
   alias, or two findings whose titles merely look alike, are *not*
   merged, since a wrong correlation hides a real second issue behind a
   coincidental resemblance. `engine/baseline.py` (new) computes the
   new/recurring/resolved/regressed delta the finding schema's `status`
   field always had a slot for: it diffs the current run's finding_ids
   against the previous run's `findings.json` plus a small persisted
   ledger (`reports/.baseline_ledger.json`) of everything ever resolved,
   so a finding reappearing after being fixed reads as `regressed`, not
   a fresh `new`. `finding.schema.json` gained an optional `risk_score`
   field. `Orchestrator.run()` now takes `previous_run_id`, stamps
   `risk_score` and the real delta-derived `status` onto every finding,
   and writes `reports/<run_id>/issues.json` alongside a `posture.md`
   with a real "top issues by risk" ranking and baseline-delta summary —
   verified manually against the full 9-domain sweep: the one KEV-listed
   firmware finding correctly ranks #1 at the score cap (100.0). The full
   report suite (by-domain/remediation-board/compliance-view) is still
   step 9's.

9. **Full report suite** — `engine/reports.py` (new; report generation
   moved out of `engine/orchestrator.py` so it's unit-testable against
   synthetic data without running a full sweep) writes all five files
   `reports/<run_id>/` was always meant to have:
   - `posture.md`: an executive summary with an overall risk-posture
     label (CLEAN/Low/Medium/High/Critical, from the highest issue's
     risk score), the top 10 issues by business risk, coverage achieved
     vs. scope with every gap named by target and reason, and a real
     delta vs. the previous run — or, on a first run, an explicit "no
     previous run to compare against" rather than presenting delta
     counts against nothing.
   - `by-domain.md`: one section per Tier 1 domain with its own coverage
     gaps and findings, ranked by risk.
   - `remediation-board.md`: every correlated issue ranked by risk, with
     owner team(s) (from the resolved asset, not guessed), a
     declared-policy SLA clock by severity band (Critical 15d / High
     30d / Medium 90d / Low 180d), and a coarse per-domain effort
     estimate (dependency bump vs. network change vs. firmware/vendor
     coordination) — a defensible default, not a per-finding guess.
   - `compliance-view.md`: findings grouped by their real
     `regulatory_tags` under NIS2/CRA/ISO27001/GDPR headings, each shown
     even when empty ("No findings currently tagged X") rather than
     silently omitted, plus any other tags present. Explicitly does
     *not* claim ISO 27001 Annex A control-number mapping — that needs a
     control taxonomy this fleet doesn't have, and a plausible-looking
     control ID would be exactly the unevidenced number the design
     brief says never to report.

   Verified against the full 9-domain sweep: the remediation board
   correctly seats the KEV-listed firmware issue at rank 1 (Critical,
   15-day SLA), and every regulatory section reflects real tagged
   findings from the run, not placeholders.

Not built yet: real adapters for the other 8 domains.

## Running the tests

```bash
cd vuln-fleet
pip install -r requirements.txt
pytest
```

## Layout

See the design note in the originating PR/commit for the full planned
repository layout. Directories present now are placeholders for upcoming
build steps; most are empty until their step is built.
