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

10. **Kill switch, CLI, slash commands, RUNBOOK, THREAT-MODEL** —
    `Orchestrator` now checks a per-run kill flag
    (`reports/<run_id>.kill`) between every target and before every
    domain (`_kill_requested`/`_gap_rollup` in `engine/orchestrator.py`):
    a domain already in flight when killed keeps whatever it completed
    and gaps the rest with reason `kill_switch: ...`; a domain never
    reached gets a full-gap rollup without even a `domain_spawn`
    event, so the log distinguishes "in flight when killed" from "never
    reached." `engine/cli.py` (new) is the real, tested command-line
    entry point behind this and every other operator action —
    `python3 -m engine.cli full-sweep|delta-sweep|target|kill` — and
    `.claude/commands/{full-sweep,delta-sweep,target,kill}.md` are the
    matching slash commands for a live Claude Code session, each one
    instructing Claude to run the CLI and report back rather than
    reimplementing any of this in a subagent's own reasoning.

    The CLI surfaced one real bug during its own testing: `LOG_DIR`/
    `REPORT_DIR` module globals were bound as function-default-argument
    values (`def f(x=LOG_DIR)`), which Python evaluates once at import
    time — so tests that monkeypatched `cli.LOG_DIR` and then called a
    function *without* an explicit argument silently kept operating on
    the original path. Every unit test that passed an explicit argument
    masked this; only the end-to-end `kill` command (which relies on
    the default) exposed it. Fixed by resolving the module global inside
    the function body instead of binding it as a default.

    `THREAT-MODEL.md` and `RUNBOOK.md` (new, both at the repo root) cover
    the rest: threat model covers purpose/non-goals, actors and trust
    boundaries, the threats actually mitigated by what's built (scope
    violation, runaway spawning, inability to stop a run, bad third-party
    intelligence data, secret exposure) versus what's a documented gap
    (no active `prompt_injection_suspected` detection yet, no redaction
    runtime), human-oversight/EU-AI-Act posture, and known accuracy
    limitations (CVE-only correlation, no Annex A control mapping, 6 of
    9 domains still on mock adapters). The runbook covers starting a
    run, approving an active-scan authorization, reading and verifying
    the hash-chained log, responding to a scope violation, killing a
    run, and handing findings to the SOC — every command in it was run
    for real against a live sweep while writing it, including the
    hash-chain verification snippet.

11. **Second real adapter: `firmware-hardware`** —
    `adapters/firmware_hardware.py` uses `adapters/cve_intel.py`'s new
    `search_nvd_by_keyword()` (real NVD keyword search) instead of the
    exact-version OSV.dev match `supply-chain` gets, because a firmware
    image has no package-manager-precision version to check against —
    only a vendor/product name. This is an honestly weaker signal than
    `supply-chain`'s, and the code says so: every finding's description
    states it's an unversioned keyword match, `confidence` is 0.35 (vs.
    supply-chain's 0.9) and `false_positive_likelihood` is 0.45, and the
    remediation string asks the reader to confirm the installed version
    before treating it as live — rather than presenting an NVD keyword
    hit as a confirmed vulnerability the way an exact OSV.dev version
    match can be. Verified live: a real scan of `idrac-mdm-01` returns 5
    real Dell iDRAC CVEs from NVD, none of which happen to be KEV-listed
    (the mock adapter's fabricated "CVE-2022-88888, KEV-listed" finding
    is gone — replaced by what NVD actually reports, not a fabricated
    drama beat).

12. **Third real adapter: `api-surface`** — `adapters/api_surface.py` is
    static security analysis of a *fetched OpenAPI/Swagger spec document*,
    not an active probe of the live API it describes: an operation with no
    security requirement (global or per-operation), an operation still
    defined despite `deprecated: true`, a `servers[]` entry declared over
    plain `http://`, and multiple major API version families (`/v1/`,
    `/v2/`, ...) coexisting in one document. All four are real structural
    facts about the document itself, readable without touching the live
    server. Two of the four things the design brief lists for api-surface
    — undocumented/zombie endpoints (found by diffing the spec against
    real traffic) and broken object-level authorization (found by actually
    calling endpoints with different identities) — are inherently active
    techniques this fleet doesn't build against a target that doesn't
    actually exist, for the same reason firmware-hardware's writeup gives:
    fabricating results against a fictional company's fictional traffic
    would violate the no-fabrication rule, not extend it.

    Verified live against a real, public spec (Swagger's official
    Petstore demo, `https://petstore3.swagger.io/api/v3/openapi.json`):
    the adapter correctly flags 10 of its 19 real operations as having no
    security requirement at all — a genuine finding against a spec this
    project doesn't control, not a fixture. What's still a placeholder:
    `_SPEC_URL_BY_TARGET` (which target maps to which spec URL) is empty,
    because no current `scope/assets.yaml` target has a real, reachable
    OpenAPI spec to point at — so `scan()` honestly returns `[]` for
    `cms-edge` today rather than wiring in a fabricated spec URL just to
    produce a nonzero finding count.

    The other 6 domains (`infra-network`, `infra-cloud`, `identity-access`,
    `endpoint-posture`, `data-exposure`, `code-firstparty`) can't follow
    any of these three patterns: their finding types are inherently
    org-internal telemetry (firewall rules, IAM policy, IdP audit logs,
    EDR consoles, encryption-at-rest status, private source code) with no
    public read-only feed standing in for them the way CISA/EPSS/NVD/
    OSV.dev do for CVE data, and no public document format standing in for
    them the way an OpenAPI spec does for api-surface. Making them real
    needs real credentialed access to real Stibo CMDB/Defender/Wiz/
    Entra-equivalent systems — which, since Stibo Software Group is an
    example company built for this exercise, don't exist to connect to.
    Fabricating "real-looking" data for them would violate the one rule
    this whole project has held to since step 1: never report a number
    you can't evidence.

13. **Blue/red/purple: `red-team-recon`, an external-target adversary-perspective
    front end** — `adapters/dns_recon.py` reconnoiters an arbitrary,
    user-supplied DNS domain the way a red team would: real DNS record
    hygiene, real SPF/DMARC email-spoofing posture, and real subdomain/
    certificate exposure via public Certificate Transparency logs, all
    passive (no traffic to the target itself, no authorization needed —
    the same as visiting the domain's website would require). With an
    explicit `--authorize-active` self-attestation
    (`scope/red-team-active-authorizations.yaml`, a 24-hour-lived twin of
    `scope/authorized-active.yaml` for a target that has no internal
    security-ops lead to sign off on it), it also runs a TLS handshake, a
    single HTTPS GET for security headers, and a HEAD-only check of a
    couple of well-known accidental-exposure paths — every one
    indistinguishable from an ordinary browser visit. None of it exploits
    anything: `check_exposed_paths` never even reads a file's body, only
    its HTTP status, so a real secret it finds exposed can never be
    captured or logged by this scan. It reports the *opportunity*, for a
    defender to close, never a demonstration that it was used.

    This is **not** a bolt-on separate red-team system: a finding from it
    validates against the same `schema/finding.schema.json`
    (`domain: red-team-recon`), runs through the same `engine/risk.py`
    scoring and `engine/reports.py` report suite every internal-asset
    domain's findings do. The blue/purple synthesis this project asked
    for *is* that shared pipeline — schema, scope enforcement, dedup,
    risk scoring, reporting — and `red-team-recon` is the
    adversary-perspective front end that feeds it, exactly like
    `supply-chain`/`firmware-hardware`/`api-surface` are the
    defender-perspective ones. It's deliberately not one of the design
    brief's nine Tier 1 domains (not in `DOMAIN_REGISTRY`): it targets an
    arbitrary external domain, not a Stibo asset, so `engine/cli.py`'s
    `red-team-recon` subcommand invokes it directly, the same way
    `cmd_target` already builds one-off `DomainSpec`s for a single ad hoc
    target. `full-sweep`/`delta-sweep` (`engine/cli.py`'s `_run_sweep`)
    fold it in too, as a tenth domain riding alongside the registry's
    nine: whichever domain was most recently registered via
    `red-team-recon` (the last entry in `scope/red-team-targets.yaml`)
    gets swept in the same run, with the same active-check gating
    (`scope/red-team-active-authorizations.yaml`) as a standalone
    `red-team-recon` invocation -- never assumed authorized just because
    it's riding along. This is the purple-team payoff made concrete: a
    full sweep's findings, and the attack-scenario-analyst pass over
    them, can now span both an internal Stibo asset and an external
    red-team target in the same run, the same report, the same
    correlation pass.

    Two of the four things a real red-team engagement might normally
    include — active exploitation of anything discovered, and
    authenticated/credentialed testing — are explicitly, permanently out
    of scope, not a placeholder: "report every opportunity, exploit none
    of them" was the one hard requirement this capability was built
    against, so it's enforced in the adapter's own design (no payloads,
    no injection, no credential attacks, no port scanning beyond 443
    anywhere in `adapters/dns_recon.py`), not left to operator discipline
    alone.

    Verified live against a real domain during development: IANA's
    `example.com` (reserved by RFC 2606 specifically for documentation
    and examples, so no ownership question applies). The passive run
    found 5 real subdomains and a wildcard certificate via crt.sh's live
    Certificate Transparency data; SPF/DMARC were both correctly
    configured, so — honestly — no email-security findings fired. The
    `--authorize-active` run surfaced one finding worth calling out
    specifically: `check_tls_posture` reported `interception_suspected`
    instead of a normal TLS-posture finding, because this fleet's own
    sandboxed execution environment routes all outbound HTTPS through a
    TLS-terminating egress proxy — a live handshake from here observes
    that proxy's re-issued certificate, not `example.com`'s real one.
    Rather than silently presenting the proxy's certificate as
    `example.com`'s own (which would have been exactly the kind of
    unevidenced, environment-specific-but-uncaught error this whole
    project's discipline exists to prevent), `check_tls_posture`
    independently cross-checks the live handshake's certificate serial
    number against what Certificate Transparency logs actually show for
    the domain — a real, live check catching a real, live accuracy bug
    before it could ever reach a report, the same way the KEV/User-Agent
    issue was caught while building `adapters/cve_intel.py` in step 7.
    The HTTP-layer checks (missing security headers, `Server: cloudflare`
    banner disclosure, no `security.txt`) were unaffected by the TLS
    interception and are genuine. `scope/red-team-targets.yaml` and
    `scope/red-team-active-authorizations.yaml` carry this verification
    run's real entries as the first (and, as of this writing, only)
    records in each file.

14. **Tier 0.5: `attack-scenario-analyst`, a white-hat attention-points
    stage** — `.claude/agents/attack-scenario-analyst.md` defines a new
    kind of agent in this fleet: one that never touches a target, live
    or mock. The fleet orchestrator (`engine/orchestrator.py`'s
    `_run_attack_scenario_analysis`) triggers it exactly once per run,
    after every Tier 1 domain has reported in and findings are
    deduplicated/correlated/risk-scored — never per-domain, never
    per-target, because its whole value is seeing across domains a
    single domain's own worker never would (a `red-team-recon`
    subdomain finding chained with a `code-firstparty` hardcoded
    credential and an `infra-network` permissive firewall rule is a
    larger story than any one of the three alone tells). It reads the
    run's full finding/issue set and predicts plausible attack scenarios
    by chaining findings together — narrative prediction, for the report,
    never anything tested or attempted.

    That last part is enforced structurally, not just by convention.
    `schema/attack_scenario.schema.json` locks every scenario's `status`
    to the single allowed value `predicted` — there is no schema-legal
    way to mark one "confirmed" or "exploited". The agent's own tool
    grants (`Read, Grep, Glob` — no `Bash`, no `Write`/`Edit`) make this
    a structural fact too: it cannot execute code or reach a network
    from this role, so it *can't* attempt what it predicts even if
    asked to. `engine/attack_scenarios.py`'s `finalize_scenarios()` adds
    a second, independent guard: every `chained_finding_id` a scenario
    references is checked against this run's real, deduplicated finding
    set, and any scenario referencing one that doesn't exist is rejected
    (logged, dropped) rather than silently kept — a hallucinated finding
    reference is exactly the kind of unevidenced claim this project's
    whole reporting discipline refuses to let through, whether it comes
    from an adapter or an analyst.

    Findings surface in the report suite as attention points, per the
    request that started this: a new "Attention points: predicted attack
    scenarios" section in `posture.md` (with a fixed, always-present
    disclaimer, not an optional one a future careless edit could drop),
    full detail in the new `reports/<run_id>/attack-scenarios.md`, and
    an `attack_scenario` event type in the hash-chained log
    (`schema/event.schema.json`) alongside `finding` events.

    `analysts/mock/attack_scenario.py` is the CLI/test path's
    placeholder (wired into every CLI-driven run --
    `full-sweep`/`delta-sweep`/`target`/`red-team-recon` -- by default
    via `engine/cli.py`; a directly-constructed `Orchestrator`, as most
    of the test suite uses, leaves it off unless a test opts in), and
    it's a different kind of mock than the
    original nine domains': genuine attack-scenario prediction is
    reasoning about context, not a fact retrievable from an API the way
    `adapters/supply_chain.py` made OSV.dev lookups real, so there's no
    "upgrade this mock to a real adapter" path here the way there was for
    supply-chain/firmware-hardware/api-surface. The mock picks the run's
    two highest-risk issues and produces exactly one clearly-labeled
    `[MOCK ANALYSIS]` illustrative scenario (verified live: a real
    `full-sweep` run correctly chained two real Dell iDRAC CVE findings
    from `firmware-hardware` into one templated example, end to end
    through the log, `posture.md`, and `attack-scenarios.md`) — proving
    the pipeline, never standing in for genuine judgement. A live
    Claude Code session running the real `attack-scenario-analyst` agent
    is the only "real" version of this stage that will ever exist.

15. **Full/delta sweep folds in the last-selected red-team target** —
    `engine/cli.py`'s `_run_sweep` (shared by `full-sweep` and
    `delta-sweep`) now reads `scope/red-team-targets.yaml`'s last entry
    (`_last_red_team_target()`) and, if one exists, sweeps it as a tenth
    domain in the same `Orchestrator.run()` call as the registry's nine —
    one run, one scope resolution, one report, rather than a second
    invocation an operator has to remember and reconcile by hand. Active
    checks join in only when a still-valid self-attested authorization is
    already on file (`scope.check_active_authorization`, cleared and
    re-checked fresh each run — never carried over as an assumption); a
    domain with no active authorization gets swept passive-only, the same
    honest default a bare `red-team-recon <domain>` run has always had.

    This surfaced a real, pre-existing correctness bug worth fixing
    while touching this path: `ScopeModel.resolve()` hardcoded every
    finding's `scope_ref` to `"assets.yaml#<id>"` regardless of which
    scope file an asset actually came from -- harmless while every asset
    really did live in `assets.yaml`, but wrong the moment a report could
    mix Stibo's own assets with `red-team-targets.yaml`'s. Fixed by
    tagging each asset with its real source file at load time
    (`engine/scope.py`); a red-team finding's `scope_ref` now correctly
    reads `red-team-targets.yaml#red-team-<domain>`.

    Verified live: a real `full-sweep` against Stibo's own scope plus the
    already-registered `stibo.com` red-team target produced 23 findings
    (16 from the nine Tier 1 domains + 7 from `red-team-recon`) in one
    report, with the still-valid `stibo.com` active-check authorization
    correctly picked up (`authorization_ref` populated on the TLS/HTTP-tier
    findings, `null` on the passive ones) and every finding's `scope_ref`
    correctly attributing its real source file.

16. **Tier G: governance (Warden, PolicyCop, CostCop, Ethica)** — a new
    tier above every domain agent and above the Tier 0.5 attack-scenario
    analyst, watching the fleet's own conduct and cost rather than a
    target's risk. Four new roles, each with its own
    `.claude/agents/*.md` definition:
    - **PolicyCop** (`engine/policy_checks.py`) — five deterministic
      checks against this fleet's own real repo state, each mapped to
      the EU regulation it's actually about: tool-boundary discipline
      and finding-schema transparency fields (EU AI Act), remediation
      guidance required (CRA), stale-authorization hygiene and no
      hardcoded secrets in tracked config (NIS2/GDPR). These are the
      same four regulations `schema/finding.schema.json`'s
      `regulatory_tags` enum already names.
    - **CostCop** (`engine/token_budget.py`) — real arithmetic over a
      new append-only ledger (`scope/token-usage-ledger.yaml`) against a
      declared budget (`scope/token-budget.yaml`), alerting once
      remaining budget drops below a configured threshold (20% by
      default). A run's real token cost is never estimated or
      fabricated — only a live Claude Code session actually knows its
      own usage, recorded via the new `python3 -m engine.cli
      record-usage <run_id> <tokens>`; an unrecorded run stays honestly
      `measured: false`.
    - **Ethica** (`engine/ethics_checks.py`) — four defense-in-depth
      checks over a completed run's own findings/scenarios/event log
      (no self-exploitation, predictions never validated, refused
      targets produce no findings, red-team never captures response
      content). Ethica's tool grant is `Read, Grep, Glob` only — no
      `Bash` — the same structural non-action guarantee
      `attack-scenario-analyst.md` holds itself to: an ethics watchdog
      that could act on its own findings wouldn't be a watchdog.
    - **Warden** (`engine/governance.py`) — combines all three into one
      `GovernanceReport` (`schema/governance_report.schema.json`) and a
      single verdict (`clear`/`warning`/`critical`), computed
      deterministically from the worst severity PolicyCop/Ethica raised
      plus CostCop's alert flag — not Warden's own judgement call. A
      `critical` verdict is where this tier gets real teeth: the
      orchestrator logs a critical `escalation` event and writes a
      fleet-wide halt flag (`reports/FLEET_HALT.flag`, checked at the
      very start of `Orchestrator.run()`) that refuses every subsequent
      `full-sweep`/`delta-sweep`/`target`/`red-team-recon` invocation
      until a human runs the new `python3 -m engine.cli resume` — this
      halt is deliberately not something any agent, Warden included, can
      clear on its own. This is a genuinely new capability, not a
      per-run kill: the existing `<run_id>.kill` flag (step 10) stops
      one in-flight run; `FLEET_HALT.flag` stops the *next* run from
      starting at all.

    Governance review runs unconditionally, once per run, right after
    the attack-scenario-analyst — unlike that stage, it needs no live
    agent wired in to produce a real result, because PolicyCop/CostCop/
    Ethica's checks are all deterministic, unit-tested code (the same
    governance principle `engine/scope.py` already applies to scope
    decisions). A live Warden/PolicyCop/CostCop/Ethica session adds
    narrative and, for Warden alone, the discretion to escalate a
    concern the fixed rules didn't catch — it never recomputes the
    numbers underneath. `engine/reports.py` gained an eighth report,
    `governance.md`, plus a "Governance: Warden's oversight report"
    section in `posture.md` that renders an impossible-to-miss red
    banner at the top of the whole report when the verdict is critical.

    Verified live: a real `full-sweep` against Stibo's own scope
    produced a `clear` verdict (no policy violations, no ethics flags,
    cost not yet measured) — the honest, expected result for a fleet
    that has never actually violated any of its own guardrails, not a
    fabricated demonstration. A dedicated hermetic test
    (`test_critical_governance_verdict_triggers_kill_switch_and_fleet_halt`)
    forces a critical verdict via a synthetic report to prove the
    kill-switch/halt-flag wiring actually works, without inventing a
    real violation that was never there.

Not built yet: real adapters for the remaining 6 Tier 1 domains — blocked
on real credentialed infrastructure access this exercise doesn't have,
not on more engineering effort. `red-team-recon` is complete for the
scope described above; extending it (more passive signal sources, more
benign active checks) is additional engineering effort, not blocked on
anything this exercise lacks. `attack-scenario-analyst` and the Tier G
governance roles (`warden`, `policy-cop`, `cost-cop`, `ethica`) are
complete as pipelines (schema, integrity checks, orchestrator wiring,
reporting) and as agent definitions; running any of them for real
requires a live Claude Code session (not this repo's own test/CLI path),
same as every other `.claude/agents/*.md` definition in this fleet.

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
