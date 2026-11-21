"""Real red-team-recon adapter: external attack-surface reconnaissance
against a user-supplied DNS domain. Every technique here is read-only and
non-exploitative by construction -- it observes what's already publicly
true about the domain and reports it; it never attempts to log in,
inject, brute-force, deny service, or otherwise act on what it finds.

Two tiers, gated differently:

Passive (always runs, no authorization needed): DNS record hygiene
(resolve_dns_records), SPF/DMARC email-spoofing posture
(analyze_spf/analyze_dmarc), and subdomain/certificate exposure via public
Certificate Transparency logs (enumerate_subdomains_via_ct). None of these
send a single packet to the target's own infrastructure -- they ask a
recursive DNS resolver (the same routine question it answers for anyone,
constantly) or a third-party CT log aggregator (crt.sh), never the target
itself. This mirrors how any public "check my domain's email security"
tool works and needs no more authorization than visiting the domain's
website would.

Active (only runs when the caller has populated
_ACTIVE_AUTHORIZATION_BY_TARGET for this target -- see engine/cli.py's
`red-team-recon` subcommand, which populates it only after
ScopeModel.check_active_authorization succeeds): a TLS handshake
(check_tls_posture), a single HTTPS GET of `/` to read security headers
(check_http_security_headers), and a HEAD request against a short, fixed
list of well-known accidental-exposure paths (check_exposed_paths). Every
one of these is indistinguishable from a normal browser visit -- no
parameter fuzzing, no auth bypass attempts, no payloads -- but they do
touch the live target, so they're gated the same way any other
active-scan action in this fleet is, through scope/authorized-active.yaml
(here, its red-team-specific twin,
scope/red-team-active-authorizations.yaml).

_ACTIVE_AUTHORIZATION_BY_TARGET deliberately deviates from the
"hardcoded per-target config map" pattern in adapters/api_surface.py and
adapters/firmware_hardware.py: those map a target to a permanent fact
(a spec URL, a device's vendor). Authorization isn't a permanent fact --
it expires -- so this is a *runtime* map the CLI populates fresh, right
before each call, from a fresh check_active_authorization() evaluation,
never persisted as a "known good forever" table. adapter_fn's fixed
(target_ref, resolution) -> list[dict] signature has no room for a third
argument, so this is the seam that carries a per-run authorization
decision through it without changing that signature for every other
domain's adapter.

What this explicitly will never do, even with authorization: exploit
anything it finds, attempt credential stuffing/brute force, fuzz
parameters, run injection payloads, port-scan beyond 443, or read the
contents of a file it discovers is exposed (check_exposed_paths reports
only the HTTP status of a HEAD request -- it never issues a GET against a
path that might contain real secrets, so it can never itself capture or
log one). Findings describe an *opportunity* a real attacker could use,
for the defender to close -- never a demonstration that it was used.

Never run this against a domain you don't own or aren't authorized to
assess.

Verified live against a real domain during development: IANA's
example.com (reserved by RFC 2606 specifically for use in documentation
and examples like this one, so no ownership question applies). See
adapters/tests/test_dns_recon.py's live-shaped fixtures for what that run
returned, and README.md for the full write-up including one real,
environment-specific finding this live check surfaced: this fleet's own
sandboxed execution environment routes all outbound HTTPS through a
TLS-terminating egress proxy, which means a live TLS handshake run from
here observes the proxy's certificate, not the target's. check_tls_posture
detects exactly this by cross-checking the live handshake's certificate
serial number against what Certificate Transparency logs actually show
for the domain, and reports interception-suspected instead of silently
presenting the proxy's certificate facts as the target's own -- the same
"never report a number you can't evidence" discipline this fleet already
holds to for every other adapter, applied to a new failure mode this
adapter is the first to be able to observe.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

import dns.exception
import dns.resolver

from engine.scope import ScopeResolution

_USER_AGENT = "vuln-fleet/1.0 (+https://github.com/jpmorten/hello_world)"

# Populated at runtime by engine/cli.py's `red-team-recon` subcommand,
# once per target, only after a fresh ScopeModel.check_active_authorization
# call succeeds for that exact target. See the module docstring for why
# this is a runtime map rather than the hardcoded per-target config map
# other real adapters use.
_ACTIVE_AUTHORIZATION_BY_TARGET: dict[str, str] = {}

_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)
_BANNER_HEADERS = ("Server", "X-Powered-By")
_EXPOSED_PATHS = ("/.git/config", "/.env")
_SECURITY_TXT_PATH = "/.well-known/security.txt"
_CERT_EXPIRY_WARNING_DAYS = 30


def _target_domain(target_ref: str) -> str:
    return target_ref.split("domain:", 1)[1] if target_ref.startswith("domain:") else target_ref


# -- passive: DNS ------------------------------------------------------------


def _resolve(domain: str, record_type: str) -> list[str]:
    """One retry on timeout. NXDOMAIN/NoAnswer/NoNameservers come back as
    an empty list, not an exception -- a domain legitimately having no MX
    or no CAA record is normal and common, not a failure to report."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    last_exc: Exception = dns.exception.DNSException("unreachable")
    for attempt in range(2):
        try:
            answer = resolver.resolve(domain, record_type)
            return [rr.to_text() for rr in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(1.0)
    raise last_exc


def resolve_dns_records(domain: str) -> dict[str, list[str]]:
    """Real DNS resolution -- a routine recursive-resolver query, the same
    kind every mail server and browser makes constantly. Never raises:
    an unreachable resolver degrades to empty results per record type."""
    records = {}
    for record_type in _DNS_RECORD_TYPES:
        try:
            records[record_type] = _resolve(domain, record_type)
        except dns.exception.DNSException:
            records[record_type] = []
    return records


def analyze_spf(txt_records: list[str]) -> dict:
    spf_records = [t for t in txt_records if t.strip('"').lower().startswith("v=spf1")]
    if not spf_records:
        return {"status": "missing"}
    if len(spf_records) > 1:
        return {"status": "multiple", "records": [t.strip('"') for t in spf_records]}
    record = spf_records[0].strip('"')
    if re.search(r"(^|\s)\+all\b", record, re.IGNORECASE):
        return {"status": "permissive", "record": record}
    return {"status": "ok", "record": record}


def analyze_dmarc(domain: str) -> dict:
    try:
        records = _resolve(f"_dmarc.{domain}", "TXT")
    except dns.exception.DNSException:
        records = []
    dmarc_records = [t for t in records if t.strip('"').lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {"status": "missing"}
    record = dmarc_records[0].strip('"')
    policy_match = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
    return {"status": "present", "policy": policy_match.group(1).lower() if policy_match else None, "record": record}


# -- passive: Certificate Transparency ---------------------------------------


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    last_exc: Exception = urllib.error.URLError("unreachable")
    for attempt in range(2):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(1.0)
    raise last_exc


def enumerate_subdomains_via_ct(domain: str) -> dict:
    """Real, passive subdomain/certificate exposure via crt.sh's public
    Certificate Transparency log search -- never touches the target's own
    infrastructure. `serials` (normalized upper-hex, no separators) feeds
    check_tls_posture's interception cross-check."""
    try:
        text = _http_get_text(f"https://crt.sh/?q=%25.{domain}&output=json")
    except (urllib.error.URLError, TimeoutError):
        return {"available": False, "subdomains": set(), "serials": set(), "wildcard": False}
    try:
        entries = json.loads(text)
    except ValueError:
        return {"available": False, "subdomains": set(), "serials": set(), "wildcard": False}
    if not isinstance(entries, list):
        return {"available": False, "subdomains": set(), "serials": set(), "wildcard": False}

    subdomains: set[str] = set()
    serials: set[str] = set()
    wildcard = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = [n.strip().lower().rstrip(".") for n in str(entry.get("name_value", "")).split("\n")]
        names = [n for n in names if n and (n == domain or n.endswith("." + domain))]
        if not names:
            # this certificate isn't for our domain at all (crt.sh's
            # wildcard %-match can surface unrelated results) -- its
            # serial number must never be attributed to `domain`.
            continue
        for name in names:
            if name.startswith("*."):
                wildcard = True
            elif name != domain:  # the apex domain itself isn't a "subdomain"
                subdomains.add(name)
        serial = str(entry.get("serial_number", "")).strip().upper()
        if serial:
            serials.add(serial)
    return {"available": True, "subdomains": subdomains, "serials": serials, "wildcard": wildcard}


# -- active: TLS ---------------------------------------------------------


def _probe_legacy_tls(domain: str) -> bool:
    """True if the server still completes a handshake capped at TLS
    1.0/1.1. Any failure (refused, unsupported by this OpenSSL build,
    timeout) reads as False -- absence of evidence isn't evidence of a
    legacy-TLS finding, only of not being able to prove one."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def check_tls_posture(domain: str, known_cert_serials: Optional[set[str]] = None) -> dict:
    """A real TLS handshake against the live target on 443 -- the same
    handshake any HTTPS client makes. Cross-checks the live certificate's
    serial number against `known_cert_serials` (from
    enumerate_subdomains_via_ct, an independent, third-party-logged data
    source) before trusting anything else this handshake observed: if the
    live serial doesn't appear in CT logs for this domain, something
    between here and the real target re-terminated TLS -- a corporate
    inspection proxy, this fleet's own sandboxed egress gateway, or worse
    -- and this handshake's other facts (protocol version, expiry) belong
    to that intermediary, not the target. Reporting them as the target's
    own posture in that case would be exactly the kind of unevidenced
    claim this fleet doesn't make, so interception_suspected short-circuits
    the rest of the analysis instead."""
    result: dict = {"reachable": False, "interception_suspected": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                serial = str(cert.get("serialNumber") or "").replace(":", "").upper()
                result.update(
                    reachable=True,
                    protocol=ssock.version(),
                    not_after=cert.get("notAfter"),
                    serial=serial,
                )
    except (OSError, ssl.SSLError, TimeoutError):
        return result

    if known_cert_serials:
        result["interception_suspected"] = result["serial"] not in known_cert_serials
    if not result["interception_suspected"]:
        result["accepts_legacy_tls"] = _probe_legacy_tls(domain)
    return result


# -- active: HTTP -------------------------------------------------------


def _http_request(url: str, method: str = "GET", timeout: float = 15.0) -> tuple[int, dict]:
    """One retry on a connection-level failure. An HTTP error status
    (404, 403, ...) is a normal, informative result, not a failure --
    it's returned immediately, not retried. Only headers are ever
    returned; the body is never read, so this adapter can never
    accidentally capture or log real secret content from a target that
    turns out to have one exposed."""
    last_exc: Exception = urllib.error.URLError("unreachable")
    for attempt in range(2):
        try:
            request = urllib.request.Request(url, method=method, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {})
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(1.0)
    raise last_exc


def check_http_security_headers(domain: str) -> Optional[dict]:
    """A single HTTPS GET of `/` -- what a browser visit does. None on
    any network failure (adapter degrades gracefully rather than
    crashing the target's whole scan over one unreachable check)."""
    try:
        status, headers = _http_request(f"https://{domain}/", method="GET")
    except (urllib.error.URLError, TimeoutError):
        return None
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in _SECURITY_HEADERS if h.lower() not in lower_headers]
    disclosed = {h: lower_headers[h.lower()] for h in _BANNER_HEADERS if h.lower() in lower_headers}
    return {"status": status, "missing_headers": missing, "disclosed_banners": disclosed}


def check_exposed_paths(domain: str) -> dict[str, Optional[int]]:
    """HEAD only, for every path checked, including security.txt -- the
    response body is never fetched, so a real exposed secret is never
    read or retained by this scan, only its HTTP status."""
    results: dict[str, Optional[int]] = {}
    for path in _EXPOSED_PATHS + (_SECURITY_TXT_PATH,):
        try:
            status, _headers = _http_request(f"https://{domain}{path}", method="HEAD")
            results[path] = status
        except (urllib.error.URLError, TimeoutError):
            results[path] = None
    return results


# -- finding assembly ---------------------------------------------------


def _finding(
    *,
    title: str,
    description: str,
    cwe: Optional[str],
    cvss: float,
    confidence: float,
    false_positive_likelihood: float,
    remediation: str,
    evidence: list[str],
    target_ref: str,
    regulatory_tags: list[str],
    authorization_ref: Optional[str] = None,
) -> dict:
    finding = {
        "title": title,
        "description": description,
        "technology": "DNS/Email/TLS",
        "location": {"kind": "dns_domain", "ref": target_ref},
        "identifiers": {"cve": [], "cwe": [cwe] if cwe else [], "ghsa": []},
        "cvss_v4": {"base": cvss, "environmental": None},
        "epss": 0.0,
        "kev_listed": False,
        "exploitation_status": "no_known_exploitation",
        "evidence_ref": evidence,
        "confidence": confidence,
        "false_positive_likelihood": false_positive_likelihood,
        "regulatory_tags": regulatory_tags,
        "suggested_remediation": remediation,
    }
    if authorization_ref is not None:
        finding["authorization_ref"] = authorization_ref
    return finding


def _email_security_findings(domain: str, txt_records: list[str], target_ref: str) -> list[dict]:
    findings = []

    spf = analyze_spf(txt_records)
    if spf["status"] == "missing":
        findings.append(
            _finding(
                title="No SPF record published",
                description=(
                    f"{domain} has no SPF (v=spf1) TXT record. Receiving mail servers have no authoritative list "
                    "of which hosts may send mail as this domain, making it easier to spoof sender addresses."
                ),
                cwe="CWE-290",
                cvss=6.5,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Publish an SPF record naming every legitimate sending host/service, ending in -all (hard fail).",
                evidence=[f"dns-txt://{domain}#spf-missing"],
                target_ref=target_ref,
                regulatory_tags=["NIS2", "GDPR"],
            )
        )
    elif spf["status"] == "permissive":
        findings.append(
            _finding(
                title="SPF record ends in +all (pass-all)",
                description=f"{domain}'s SPF record ({spf['record']}) ends in +all, which tells receivers to accept mail from ANY host as this domain -- equivalent to no SPF at all.",
                cwe="CWE-290",
                cvss=7.5,
                confidence=0.95,
                false_positive_likelihood=0.05,
                remediation="Change the record's final mechanism to -all (hard fail) once every legitimate sender is listed.",
                evidence=[f"dns-txt://{domain}#spf-permissive"],
                target_ref=target_ref,
                regulatory_tags=["NIS2", "GDPR"],
            )
        )
    elif spf["status"] == "multiple":
        findings.append(
            _finding(
                title="Multiple SPF records published",
                description=f"{domain} publishes {len(spf['records'])} SPF (v=spf1) TXT records. RFC 7208 requires exactly one; multiple records make SPF evaluation undefined across mail receivers.",
                cwe="CWE-16",
                cvss=4.0,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Merge all sending hosts into a single SPF record.",
                evidence=[f"dns-txt://{domain}#spf-multiple"],
                target_ref=target_ref,
                regulatory_tags=["NIS2"],
            )
        )

    dmarc = analyze_dmarc(domain)
    if dmarc["status"] == "missing":
        findings.append(
            _finding(
                title="No DMARC record published",
                description=f"_dmarc.{domain} has no DMARC (v=DMARC1) TXT record, so spoofed mail failing SPF/DKIM is neither rejected/quarantined nor reported back to the domain owner.",
                cwe="CWE-290",
                cvss=6.0,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Publish a DMARC record starting with p=quarantine or p=reject, with a rua= address for aggregate reports.",
                evidence=[f"dns-txt://_dmarc.{domain}#dmarc-missing"],
                target_ref=target_ref,
                regulatory_tags=["NIS2", "GDPR"],
            )
        )
    elif dmarc["status"] == "present" and dmarc.get("policy") == "none":
        findings.append(
            _finding(
                title="DMARC policy is p=none (monitor-only)",
                description=f"_dmarc.{domain}'s DMARC record is in monitor-only mode (p=none): spoofed mail failing SPF/DKIM is reported but not rejected or quarantined.",
                cwe=None,
                cvss=3.5,
                confidence=0.85,
                false_positive_likelihood=0.15,
                remediation="Move to p=quarantine, then p=reject, once aggregate reports confirm legitimate mail flows are all correctly authenticated.",
                evidence=[f"dns-txt://_dmarc.{domain}#dmarc-p-none"],
                target_ref=target_ref,
                regulatory_tags=["NIS2"],
            )
        )

    return findings


def _ct_findings(domain: str, ct: dict, target_ref: str) -> list[dict]:
    if not ct["available"]:
        return []
    findings = []
    if ct["subdomains"]:
        sample = ", ".join(sorted(ct["subdomains"])[:10])
        more = f" (+{len(ct['subdomains']) - 10} more)" if len(ct["subdomains"]) > 10 else ""
        findings.append(
            _finding(
                title=f"{len(ct['subdomains'])} subdomain(s) discovered via public Certificate Transparency logs",
                description=(
                    f"Certificates publicly logged for {domain} reveal {len(ct['subdomains'])} distinct subdomain(s): "
                    f"{sample}{more}. Not a vulnerability by itself, but it's exactly the attack-surface map a real "
                    "attacker would build first -- review for anything that should have been decommissioned or was "
                    "never meant to be publicly known."
                ),
                cwe=None,
                cvss=3.1,
                confidence=0.95,
                false_positive_likelihood=0.05,
                remediation="Review the list against your own inventory; decommission or re-issue certificates for anything unexpected.",
                evidence=[f"crt.sh://?q=%25.{domain}"],
                target_ref=target_ref,
                regulatory_tags=["ISO27001"],
            )
        )
    if ct["wildcard"]:
        findings.append(
            _finding(
                title="Wildcard certificate in use",
                description=f"A publicly logged certificate for {domain} covers *.{domain} -- every current and future subdomain shares one certificate's private key and validity window.",
                cwe=None,
                cvss=4.5,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Consider per-subdomain certificates for high-value subdomains so a key compromise on one doesn't extend to all.",
                evidence=[f"crt.sh://?q=%25.{domain}#wildcard"],
                target_ref=target_ref,
                regulatory_tags=["ISO27001"],
            )
        )
    return findings


def _tls_findings(domain: str, tls: dict, target_ref: str, authorization_ref: str) -> list[dict]:
    if not tls["reachable"]:
        return []
    findings = []
    if tls["interception_suspected"]:
        findings.append(
            _finding(
                title="Live TLS certificate not found in Certificate Transparency logs",
                description=(
                    f"The certificate presented by {domain}:443 during this scan (serial {tls['serial']}) does not "
                    "match any certificate publicly logged for this domain. That's consistent with TLS interception "
                    "somewhere between this scanner and the real target -- a corporate inspection proxy, this "
                    "scanner's own network egress path, or something more concerning -- and it also means this "
                    "scan's other TLS observations (protocol version, expiry) describe whatever presented that "
                    "certificate, not necessarily the real target, so they are deliberately not reported here. "
                    "Re-run from a network path known not to intercept TLS before treating this as a finding about "
                    f"{domain} itself."
                ),
                cwe=None,
                cvss=5.0,
                confidence=0.55,
                false_positive_likelihood=0.4,
                remediation="Re-run this check from a network path with no TLS-inspecting proxy in front of it; if the mismatch persists, investigate as a possible MITM.",
                evidence=[f"tls-handshake://{domain}:443#serial-{tls['serial']}"],
                target_ref=target_ref,
                regulatory_tags=["NIS2"],
                authorization_ref=authorization_ref,
            )
        )
        return findings

    if tls.get("not_after"):
        try:
            expiry = datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < _CERT_EXPIRY_WARNING_DAYS:
                findings.append(
                    _finding(
                        title="TLS certificate expired" if days_left < 0 else f"TLS certificate expires in {days_left} day(s)",
                        description=f"{domain}'s TLS certificate {'expired' if days_left < 0 else 'expires'} on {tls['not_after']}.",
                        cwe="CWE-295",
                        cvss=6.5 if days_left < 0 else 4.0,
                        confidence=0.95,
                        false_positive_likelihood=0.05,
                        remediation="Renew the certificate" + (" immediately" if days_left < 0 else " before it expires") + ", and set up expiry monitoring.",
                        evidence=[f"tls-handshake://{domain}:443#not-after"],
                        target_ref=target_ref,
                        regulatory_tags=["NIS2", "ISO27001"],
                        authorization_ref=authorization_ref,
                    )
                )
        except ValueError:
            pass

    if tls.get("accepts_legacy_tls"):
        findings.append(
            _finding(
                title="Server accepts legacy TLS 1.0/1.1",
                description=f"{domain}:443 completed a handshake capped at TLS 1.0/1.1, both deprecated (RFC 8996) and disallowed by PCI-DSS and most modern compliance baselines.",
                cwe="CWE-327",
                cvss=5.5,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Disable TLS 1.0/1.1 in the server's TLS configuration; require TLS 1.2 or higher.",
                evidence=[f"tls-handshake://{domain}:443#legacy-tls"],
                target_ref=target_ref,
                regulatory_tags=["NIS2", "ISO27001"],
                authorization_ref=authorization_ref,
            )
        )
    return findings


def _header_findings(domain: str, headers: Optional[dict], target_ref: str, authorization_ref: str) -> list[dict]:
    if headers is None:
        return []
    findings = []
    if headers["missing_headers"]:
        findings.append(
            _finding(
                title=f"{len(headers['missing_headers'])} security response header(s) missing",
                description=f"https://{domain}/ does not set: {', '.join(headers['missing_headers'])}.",
                cwe="CWE-693",
                cvss=4.0,
                confidence=0.85,
                false_positive_likelihood=0.15,
                remediation="Add the missing headers at the edge/CDN or application layer.",
                evidence=[f"http-headers://{domain}/#missing"],
                target_ref=target_ref,
                regulatory_tags=["ISO27001"],
                authorization_ref=authorization_ref,
            )
        )
    if headers["disclosed_banners"]:
        banners = ", ".join(f"{k}: {v}" for k, v in headers["disclosed_banners"].items())
        findings.append(
            _finding(
                title="Server/technology banner disclosed in response headers",
                description=f"https://{domain}/ discloses: {banners}. Version/technology disclosure narrows an attacker's search for a matching known vulnerability.",
                cwe="CWE-200",
                cvss=2.5,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Suppress or generalize these headers at the edge/CDN or application layer.",
                evidence=[f"http-headers://{domain}/#banners"],
                target_ref=target_ref,
                regulatory_tags=["ISO27001"],
                authorization_ref=authorization_ref,
            )
        )
    return findings


def _exposed_path_findings(domain: str, exposed: dict[str, Optional[int]], target_ref: str, authorization_ref: str) -> list[dict]:
    findings = []
    for path in _EXPOSED_PATHS:
        if exposed.get(path) == 200:
            findings.append(
                _finding(
                    title=f"Possibly sensitive path publicly reachable: {path}",
                    description=(
                        f"A HEAD request to https://{domain}{path} returned HTTP 200. This scan never fetched the "
                        "body (so no potential secret it may contain was read or logged) -- confirm manually before "
                        "treating this as confirmed exposure; a catch-all 200 response for every path would also "
                        "produce this result."
                    ),
                    cwe="CWE-538",
                    cvss=7.0,
                    confidence=0.5,
                    false_positive_likelihood=0.4,
                    remediation=f"Verify manually whether {path} serves real content; if so, remove it from the public webroot or block it at the edge.",
                    evidence=[f"http-head://{domain}{path}"],
                    target_ref=target_ref,
                    regulatory_tags=["NIS2", "GDPR"],
                    authorization_ref=authorization_ref,
                )
            )
    if exposed.get(_SECURITY_TXT_PATH) not in (200,):
        findings.append(
            _finding(
                title="No security.txt published",
                description=f"https://{domain}{_SECURITY_TXT_PATH} is not published. RFC 9116 recommends it so security researchers have a clear, authorized way to report findings.",
                cwe=None,
                cvss=0.0,
                confidence=0.9,
                false_positive_likelihood=0.1,
                remediation="Publish a security.txt per RFC 9116 with a contact and (ideally) a disclosure policy.",
                evidence=[f"http-head://{domain}{_SECURITY_TXT_PATH}"],
                target_ref=target_ref,
                regulatory_tags=["ISO27001"],
                authorization_ref=authorization_ref,
            )
        )
    return findings


# -- entry point ----------------------------------------------------------


def scan(target_ref: str, resolution: ScopeResolution) -> list[dict]:
    domain = _target_domain(target_ref)
    findings: list[dict] = []

    dns_records = resolve_dns_records(domain)
    findings += _email_security_findings(domain, dns_records.get("TXT", []), target_ref)

    ct = enumerate_subdomains_via_ct(domain)
    findings += _ct_findings(domain, ct, target_ref)

    authorization_ref = _ACTIVE_AUTHORIZATION_BY_TARGET.get(target_ref)
    if authorization_ref:
        tls = check_tls_posture(domain, ct.get("serials"))
        findings += _tls_findings(domain, tls, target_ref, authorization_ref)

        headers = check_http_security_headers(domain)
        findings += _header_findings(domain, headers, target_ref, authorization_ref)

        exposed = check_exposed_paths(domain)
        findings += _exposed_path_findings(domain, exposed, target_ref, authorization_ref)

    return findings
