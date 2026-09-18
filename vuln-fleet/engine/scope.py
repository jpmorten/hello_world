"""Scope model: assets.yaml + exclusions.yaml + authorized-active.yaml.

Plain, deterministic code — no model judgement — per the governance
requirement that scope decisions are unit-tested arithmetic/matching, not
agent discretion. This is what both the pre-tool scope-guard hook
(.claude/hooks/scope_guard.py) and, later, adapters call before touching
a target.

Target refs are strings with an explicit scheme: repo: | host: | ip: |
endpoint: | cidr:. `cidr:` only ever appears as a target *pattern* inside
assets.yaml/authorized-active.yaml; a caller queries with `ip:`, which is
checked for containment.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import yaml

_REQUIRED_ASSET_FIELDS = ("asset_id", "entity", "type", "owner_team", "criticality", "targets")
_VALID_CRITICALITY = ("critical", "high", "medium", "low")
_REQUIRED_AUTH_FIELDS = ("authorization_ref", "scope", "actions", "approved_by", "valid_from", "valid_until")


class ScopeConfigError(Exception):
    """assets.yaml / exclusions.yaml / authorized-active.yaml is malformed."""


class ScopeViolation(Exception):
    """A target is out of scope, excluded, or lacks active-scan authorization."""

    def __init__(self, target_ref: str, reason: str):
        self.target_ref = target_ref
        self.reason = reason
        super().__init__(f"{target_ref}: {reason}")


@dataclass(frozen=True)
class ScopeResolution:
    target_ref: str
    asset_id: str
    entity: str
    asset_type: str
    criticality: str
    owner_team: str
    scope_ref: str


@dataclass(frozen=True)
class ActiveAuthorization:
    authorization_ref: str
    approved_by: str
    valid_from: datetime
    valid_until: datetime


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _read_yaml_mapping(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise ScopeConfigError(f"{path}: expected a YAML mapping at the top level")
    return doc


def _matches_target(target_ref: str, pattern: str) -> bool:
    if target_ref == pattern:
        return True
    if pattern.startswith("cidr:") and target_ref.startswith("ip:"):
        try:
            ip = ipaddress.ip_address(target_ref[len("ip:") :])
            network = ipaddress.ip_network(pattern[len("cidr:") :], strict=False)
        except ValueError:
            return False
        return ip in network
    return False


class ScopeModel:
    def __init__(
        self,
        assets_path: Path | str,
        exclusions_path: Path | str,
        authorized_active_path: Path | str,
        now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._now = now_fn
        self.entities: dict[str, str] = {}
        self.assets: list[dict] = []
        self.exclusions: list[dict] = []
        self.authorizations: list[dict] = []
        self._load(Path(assets_path), Path(exclusions_path), Path(authorized_active_path))

    def _load(self, assets_path: Path, exclusions_path: Path, authorized_active_path: Path) -> None:
        assets_doc = _read_yaml_mapping(assets_path)
        exclusions_doc = _read_yaml_mapping(exclusions_path)
        auth_doc = _read_yaml_mapping(authorized_active_path)

        for entity in assets_doc.get("entities") or []:
            if "id" not in entity or "name" not in entity:
                raise ScopeConfigError(f"entity missing id/name: {entity!r}")
            self.entities[entity["id"]] = entity["name"]

        for asset in assets_doc.get("assets") or []:
            missing = [f for f in _REQUIRED_ASSET_FIELDS if f not in asset]
            if missing:
                raise ScopeConfigError(f"asset {asset.get('asset_id', '?')!r} missing field(s): {missing}")
            if asset["entity"] not in self.entities:
                raise ScopeConfigError(
                    f"asset {asset['asset_id']!r} references unknown entity {asset['entity']!r}"
                )
            if asset["criticality"] not in _VALID_CRITICALITY:
                raise ScopeConfigError(
                    f"asset {asset['asset_id']!r} has invalid criticality {asset['criticality']!r}"
                )
            self.assets.append(asset)

        for exclusion in exclusions_doc.get("exclusions") or []:
            if "pattern" not in exclusion or "reason" not in exclusion:
                raise ScopeConfigError(f"exclusion missing pattern/reason: {exclusion!r}")
            self.exclusions.append(exclusion)

        for auth in auth_doc.get("authorizations") or []:
            missing = [f for f in _REQUIRED_AUTH_FIELDS if f not in auth]
            if missing:
                raise ScopeConfigError(f"authorization {auth.get('authorization_ref', '?')!r} missing field(s): {missing}")
            self.authorizations.append(auth)

    def _excluded_by(self, target_ref: str) -> Optional[dict]:
        for exclusion in self.exclusions:
            if fnmatch.fnmatch(target_ref, exclusion["pattern"]):
                return exclusion
        return None

    def resolve(self, target_ref: str) -> ScopeResolution:
        """Raises ScopeViolation if target_ref matches no asset. Does not
        consult exclusions — use assert_in_scope for the full check."""
        for asset in self.assets:
            if any(_matches_target(target_ref, pattern) for pattern in asset["targets"]):
                return ScopeResolution(
                    target_ref=target_ref,
                    asset_id=asset["asset_id"],
                    entity=self.entities[asset["entity"]],
                    asset_type=asset["type"],
                    criticality=asset["criticality"],
                    owner_team=asset["owner_team"],
                    scope_ref=f"assets.yaml#{asset['asset_id']}",
                )
        raise ScopeViolation(target_ref, "does not resolve to any asset in scope/assets.yaml")

    def assert_in_scope(self, target_ref: str) -> ScopeResolution:
        exclusion = self._excluded_by(target_ref)
        if exclusion is not None:
            raise ScopeViolation(target_ref, f"excluded: {exclusion['reason']}")
        return self.resolve(target_ref)

    def targets(self, *, scheme: Optional[str] = None, asset_type: Optional[str] = None) -> list[str]:
        """Flattened target refs across assets, optionally filtered by the
        asset's declared `type` and/or the target ref's scheme prefix.

        This is how a Tier 1 domain plans its own decomposition into
        workers (engine/domains.py): e.g. infra-network asks for every
        `cidr:` target (one worker per subnet) plus every target on a
        `network_device`-typed asset (one worker per firewall platform).
        It does not consult exclusions — an excluded target still comes
        back here and is refused later, the same way any other target is,
        when the worker's own assert_in_scope call runs. That keeps
        exclusion handling in one place instead of duplicating it into
        every domain's planning step.
        """
        results = []
        for asset in self.assets:
            if asset_type is not None and asset["type"] != asset_type:
                continue
            for target_ref in asset["targets"]:
                if scheme is not None and not target_ref.startswith(f"{scheme}:"):
                    continue
                results.append(target_ref)
        return results

    def check_active_authorization(self, target_ref: str, action: str) -> ActiveAuthorization:
        """Active-scan gate: in scope AND a signed, in-window record covers
        this exact (target, action) pair."""
        self.assert_in_scope(target_ref)
        now = self._now()
        for auth in self.authorizations:
            if action not in auth["actions"]:
                continue
            if not any(_matches_target(target_ref, pattern) for pattern in auth["scope"]):
                continue
            valid_from, valid_until = _parse_dt(auth["valid_from"]), _parse_dt(auth["valid_until"])
            if valid_from <= now <= valid_until:
                return ActiveAuthorization(
                    authorization_ref=auth["authorization_ref"],
                    approved_by=auth["approved_by"],
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
        raise ScopeViolation(
            target_ref, f"no in-window active-scan authorization covers action {action!r}"
        )
