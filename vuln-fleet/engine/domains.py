"""Tier 1 domain registry: every domain in the design brief, declared as
one entry mapping (a) how it plans its own decomposition into Tier 2
workers and (b) which adapter its workers call. Adding a domain is
exactly one entry here plus, for a live Claude Code fleet, a matching
`.claude/agents/<domain>.md` subagent definition — no change to
engine/orchestrator.py's control flow, which stays domain-agnostic.

Every `adapter_fn` here started as a mock (adapters/mock/*.py, per step
5); step 7 replaces these one at a time with real, read-only adapters
behind the exact same `(target_ref, ScopeResolution) -> list[dict]`
signature, so nothing in this file or in orchestrator.py needs to change
when that happens — only the import each entry points at.
`supply-chain` (adapters/supply_chain.py: real OSV.dev + CISA KEV/
FIRST.org EPSS/NVD data), `firmware-hardware` (adapters/
firmware_hardware.py: real NVD keyword search + the same KEV/EPSS/NVD
enrichment, honestly weaker signal since it has no version to match
against), and `api-surface` (adapters/api_surface.py: real static
analysis of a fetched OpenAPI spec document — no active probing) are
real; the rest are still mocks — see README.md for why the other 6
domains can't follow the same pattern (they need credentialed access to
internal systems that don't exist for this example company, not another
public feed).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from adapters import api_surface, firmware_hardware, supply_chain
from adapters.mock import (
    code_firstparty,
    data_exposure,
    endpoint_posture,
    identity_access,
    infra_cloud,
    infra_network,
)
from engine.orchestrator import AdapterFn, DomainSpec
from engine.scope import ScopeModel

DecomposeFn = Callable[[ScopeModel], list[str]]


@dataclass(frozen=True)
class DomainRegistration:
    domain: str
    worker_role: str
    decompose_fn: DecomposeFn
    adapter_fn: AdapterFn


DOMAIN_REGISTRY: dict[str, DomainRegistration] = {
    "supply-chain": DomainRegistration(
        domain="supply-chain",
        worker_role="repo-worker",
        # One worker per repository/SBOM.
        decompose_fn=lambda scope: scope.targets(scheme="repo"),
        adapter_fn=supply_chain.scan,
    ),
    "api-surface": DomainRegistration(
        domain="api-surface",
        worker_role="endpoint-worker",
        # One worker per service/gateway endpoint.
        decompose_fn=lambda scope: scope.targets(scheme="endpoint", asset_type="service"),
        adapter_fn=api_surface.scan,
    ),
    "infra-network": DomainRegistration(
        domain="infra-network",
        worker_role="network-worker",
        # One worker per VLAN/VPC/subnet, plus one per firewall platform.
        decompose_fn=lambda scope: (
            scope.targets(scheme="cidr") + scope.targets(asset_type="network_device")
        ),
        adapter_fn=infra_network.scan,
    ),
    "infra-cloud": DomainRegistration(
        domain="infra-cloud",
        worker_role="cloud-resource-worker",
        # One worker per cloud resource (storage, IAM-bound endpoints, etc).
        decompose_fn=lambda scope: scope.targets(asset_type="cloud_resource"),
        adapter_fn=infra_cloud.scan,
    ),
    "firmware-hardware": DomainRegistration(
        domain="firmware-hardware",
        worker_role="device-worker",
        # One worker per device (grouped by class/vendor once a real CMDB
        # adapter exists to report those fields; for now, one per asset).
        decompose_fn=lambda scope: scope.targets(asset_type="firmware"),
        adapter_fn=firmware_hardware.scan,
    ),
    "code-firstparty": DomainRegistration(
        domain="code-firstparty",
        worker_role="repo-sast-worker",
        # One worker per repository — deliberately the same repos
        # supply-chain covers; SAST and SBOM scanning is the same asset
        # from two domains, not a conflict (see adapters/mock/code_firstparty.py).
        decompose_fn=lambda scope: scope.targets(scheme="repo"),
        adapter_fn=code_firstparty.scan,
    ),
    "identity-access": DomainRegistration(
        domain="identity-access",
        worker_role="identity-worker",
        # One worker per identity provider/directory.
        decompose_fn=lambda scope: scope.targets(scheme="endpoint", asset_type="identity"),
        adapter_fn=identity_access.scan,
    ),
    "endpoint-posture": DomainRegistration(
        domain="endpoint-posture",
        worker_role="endpoint-posture-worker",
        # One worker per managed host/server.
        decompose_fn=lambda scope: scope.targets(scheme="host", asset_type="service"),
        adapter_fn=endpoint_posture.scan,
    ),
    "data-exposure": DomainRegistration(
        domain="data-exposure",
        worker_role="data-store-worker",
        # One worker per data store/repository.
        decompose_fn=lambda scope: scope.targets(asset_type="data_store"),
        adapter_fn=data_exposure.scan,
    ),
}


def build_domain_specs(scope_model: ScopeModel, domains: Optional[list[str]] = None) -> list[DomainSpec]:
    """Materializes a run's DomainSpec list from the registry.

    Each domain's decompose_fn runs against the current scope model right
    now, so a full sweep always reflects the live inventory rather than a
    snapshot baked in ahead of time. `domains=None` means every registered
    domain (a full sweep); passing a subset is how a delta or targeted
    sweep would select domains — deciding *which* subset is the
    orchestrator's job (design brief section 1, item 2), not this
    registry's.
    """
    selected = domains if domains is not None else list(DOMAIN_REGISTRY)
    specs = []
    for domain in selected:
        registration = DOMAIN_REGISTRY[domain]
        specs.append(
            DomainSpec(
                domain=registration.domain,
                worker_role=registration.worker_role,
                targets=registration.decompose_fn(scope_model),
                adapter_fn=registration.adapter_fn,
            )
        )
    return specs
