# Runbook

Operational guide for Security Ops. Everything below has a real command behind it — `python3 -m engine.cli ...` — whether you're running it yourself or asking a live Claude Code session to run the matching `/full-sweep`, `/delta-sweep`, `/target`, or `/kill` slash command.

Before your first run: `cd vuln-fleet && pip install -r requirements.txt`.

## Starting a run

**Full sweep** (every registered domain — currently `supply-chain`, `firmware-hardware`, and `api-surface` are real adapters; the other six run against mock data, see `README.md`):

```bash
python3 -m engine.cli full-sweep
```

This picks a timestamped `run_id` automatically (`full-sweep-<UTC timestamp>`), sweeps every domain in `engine/domains.py`'s `DOMAIN_REGISTRY`, and prints a summary: finding/issue counts, the delta vs. nothing (a first run has no baseline, so everything is `new`), any coverage gaps, and the report paths.

**Delta sweep** (same, but diffed against the last completed run):

```bash
python3 -m engine.cli delta-sweep
```

Use this for a routine/scheduled run once you have at least one completed sweep — it auto-selects the most recent `reports/<run_id>/findings.json` as the baseline. Pin an explicit baseline instead with `--previous-run-id <run_id>` if you want to compare against something other than "whatever ran last" (e.g. last week's Monday run, not last night's ad-hoc targeted one).

**Targeted sweep** (one asset, whichever domains claim it):

```bash
python3 -m engine.cli target repo:stibo/checkout
```

The target ref must use a scheme `engine/scope.py` understands (`repo:`, `host:`, `ip:`, `endpoint:`, `cidr:`). This command tells you, and refuses cleanly, if the target isn't in scope (`scope/assets.yaml`), is on the exclusion list (`scope/exclusions.yaml`), or isn't claimed by any domain's current decomposition (`engine/domains.py`) — none of those are errors to work around, they're the scope boundary doing its job.

Live Claude Code session equivalents: `/full-sweep`, `/delta-sweep`, `/target <ref>`.

## Running a red-team recon against an external domain

`red-team-recon` is a separate capability from the sweep above — not one of the nine Tier 1 domains, not swept by `full-sweep`/`delta-sweep` — for reconnoitering an arbitrary, externally-supplied DNS domain the way a red team would, without ever exploiting anything it finds. **Only ever run this against a domain you own or are authorized to assess.**

```bash
python3 -m engine.cli red-team-recon example.com --requested-by "you@example.com"
```

This always runs passive checks — DNS record hygiene, SPF/DMARC email-spoofing posture, subdomain/certificate exposure via public Certificate Transparency logs — none of which touch the target's own infrastructure (they ask a DNS resolver or crt.sh, both routine, publicly-available lookups). The domain is registered (idempotently) in `scope/red-team-targets.yaml` the first time you run it, so it's a durable, auditable record from then on, the same as any other asset in scope.

To also run the active checks (a TLS handshake, one HTTPS GET for security headers, a HEAD-only check of a couple of well-known accidental-exposure paths — every one indistinguishable from an ordinary browser visit, no exploitation attempted):

```bash
python3 -m engine.cli red-team-recon example.com --requested-by "you@example.com" --authorize-active
```

This self-attests a fresh, 24-hour authorization in `scope/red-team-active-authorizations.yaml` (`approved_by` is whatever you passed to `--requested-by`) before anything active runs, gated through the exact same `ScopeModel.check_active_authorization` mechanism as any other active-scan action in this fleet. The attestation expires after 24 hours by design — re-run with `--authorize-active` again for a later scan rather than relying on a stale approval.

Findings land in `reports/<run_id>/` exactly like a normal sweep's — same schema, same risk scoring, same report suite — because a red-team finding is meant to reach the same defenders' desk a blue-team sweep's finding does, not live in a separate system. `domain: red-team-recon`, `location.kind: dns_domain` in the raw finding data.

One real limitation to know about: if you run this from behind a TLS-inspecting network path (a corporate proxy, or this fleet's own sandboxed execution environment during development — see `adapters/dns_recon.py`'s docstring), the TLS-handshake check will report `interception_suspected` instead of the target's real certificate/protocol facts. That's the adapter correctly refusing to attribute an intermediary's TLS session to the target, not a bug — re-run from a network path with no TLS inspection in front of it to get a genuine TLS posture reading.

## Approving an active scan

Nothing in this fleet is authorized to send traffic to a target (a port scan, a live service fingerprint, an authenticated config pull) without a signed, time-boxed record in `scope/authorized-active.yaml`. To approve one:

1. Add an entry to `scope/authorized-active.yaml`:
   ```yaml
   - authorization_ref: "descriptive-id-YYYY-MM"
     scope: ["cidr:x.x.x.x/24"]        # or specific host:/endpoint: targets
     actions: ["port_scan"]             # only the actions you're actually approving
     approved_by: "your-name@stibo.example.com"
     signed_at: "2026-09-18T00:00:00Z"
     valid_from: "2026-09-18T00:00:00Z"
     valid_until: "2026-09-25T00:00:00Z"  # keep windows short; extend deliberately, don't leave them open-ended
     signature: "PLACEHOLDER-UNSIGNED"    # real signing mechanism is a tracked follow-up (see THREAT-MODEL.md)
   ```
2. Commit this change through your normal change-management process — `scope/authorized-active.yaml` is a control document, treat edits to it like any other production security config change (review, not a direct push).
3. `engine.scope.ScopeModel.check_active_authorization()` re-reads this file on every run; there's nothing to restart or reload.
4. When the window in `valid_until` passes, the authorization simply stops matching — no separate revocation step is needed, but remove expired entries during your normal cleanup so the file doesn't accumulate stale history.

No infra-network/infra-cloud/firmware-hardware adapter that performs an active action exists yet (see `README.md`'s status list) — this section describes the mechanism the moment one is added, not a currently-active capability.

## Reading the log

Every run writes `logs/<run_id>.ndjson` — one JSON object per line, append-only, hash-chained (each line's `integrity_hash` covers the previous line's hash plus its own content; see `engine/logbus.py`). To read one:

```bash
# tail live during a run
tail -f logs/<run_id>.ndjson | python3 -m json.tool --json-lines   # or just `tail -f` and eyeball it

# every scope decision this run made
grep -h '"event_type":"scope_' logs/<run_id>.ndjson

# every finding
grep -h '"event_type":"finding"' logs/<run_id>.ndjson

# verify the chain hasn't been tampered with
python3 -c "
import json
from engine.logbus import GENESIS_HASH, compute_integrity_hash
prev = GENESIS_HASH
for line in open('logs/<run_id>.ndjson'):
    event = json.loads(line)
    stored = event.pop('integrity_hash')
    assert compute_integrity_hash(prev, event) == stored, 'chain broken at ' + event['event_type']
    prev = stored
print('chain intact')
"
```

The SIEM/SOC copy (once a real sink is configured — `engine.logbus.SyslogSink`/`WebhookSink` exist and are tested, but no run wires one in by default yet) is the authoritative record for incident response purposes; the local file is authoritative for everything else, including verifying the SIEM copy wasn't dropped or altered in transit.

## Responding to a scope violation

A `scope_violation` event means a target was refused — out of scope, excluded, or (for an active action) unauthorized. This is normal operation, not an incident by itself: check `posture.md` or `by-domain.md` for the domain it came from, and the coverage-gap line names the exact target and reason.

- **Target should be in scope but isn't** → it's missing from `scope/assets.yaml`, or its `type`/`targets` don't match what a domain's `decompose_fn` looks for (`engine/domains.py`). Fix the inventory, not the code.
- **Target is correctly excluded** (shows `excluded: <reason>`) → working as intended; no action.
- **An active-scan action was refused for lacking authorization** → see "Approving an active scan" above if the action should be allowed going forward.
- **A target the fleet has no business touching keeps showing up** (e.g. a customer-owned host that isn't in `scope/exclusions.yaml` yet) → add it to `scope/exclusions.yaml` immediately; treat this as higher priority than a routine inventory fix, since until it's excluded a future decompose_fn change could pick it up again.

`scope_violation` never halts a run — the rest of the sweep continues, and the gap is recorded, not hidden.

## Killing a run

```bash
python3 -m engine.cli kill                      # targets the most recently active run (by logs/*.ndjson mtime)
python3 -m engine.cli kill --run-id <run_id>     # explicit
```

Or `/kill` (optionally with a run_id) in a live Claude Code session.

This writes `reports/<run_id>.kill` — a flag file, not a process signal. The running sweep checks for it between targets and before each new domain (`Orchestrator._kill_requested`, `engine/orchestrator.py`) and stops there; there is no forced/instant termination, and a very short sweep can finish before it's ever checked. Once the run does stop, it still produces the full report suite — every target it hadn't gotten to shows up as a coverage gap with reason `kill_switch: ...`, not a crash and not a silently missing section.

A `.kill` flag is scoped to its own `run_id` (which includes a timestamp), so it never needs manual cleanup before a later run — a new run gets a new run_id and a fresh, absent flag.

## Handing findings to the SOC

1. A completed run's authoritative output is `reports/<run_id>/`: `findings.json` (full deduplicated set), `issues.json` (CVE-correlated groups with an aggregate risk score), `posture.md` (executive summary), `by-domain.md`, `remediation-board.md`, `compliance-view.md`.
2. For SIEM ingestion, the event stream (`logs/<run_id>.ndjson`) is the machine-readable record — every `finding` event's `details` field is the same object that ends up in `findings.json`, so nothing in the report suite is derived from data the SIEM didn't also receive.
3. Hand the SOC `posture.md` for the human-readable summary and `remediation-board.md` for assigned owners/SLAs; point them at `findings.json`/`issues.json` if they need to pull the data into their own tooling.
4. State the coverage caveat every time until it's no longer true: only `supply-chain`, `firmware-hardware`, and `api-surface` run against real adapters today; the other six domains' findings in any `full-sweep`/`delta-sweep` report are from `adapters/mock/*.py` synthetic data, proving the pipeline, not reporting a real posture for those domains yet. `red-team-recon` reports (a separate, opt-in run, never part of a full sweep) are real in full.
