"""DNS & Email Security connector — checks DMARC, SPF, DKIM, MX, DNSSEC per domain."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]

_DMARC_POLICY_STRENGTH = {"reject": 3, "quarantine": 2, "none": 1}


def _dns_query(name: str, rdtype: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(name, rdtype, lifetime=5.0)
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return []


def _check_spf(domain: str) -> dict[str, Any]:
    records = _dns_query(domain, "TXT")
    spf_records = [r for r in records if "v=spf1" in r]
    if not spf_records:
        return {"present": False, "record": None, "all_mechanism": None, "finding": "missing_spf"}
    record = spf_records[0].strip('"')
    all_mech = None
    for part in record.split():
        if part in ("+all", "-all", "~all", "?all"):
            all_mech = part
    finding = None
    if all_mech in ("+all", "?all"):
        finding = "spf_permissive"
    elif all_mech is None:
        finding = "spf_no_all"
    return {"present": True, "record": record, "all_mechanism": all_mech, "finding": finding}


def _check_dmarc(domain: str) -> dict[str, Any]:
    records = _dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r for r in records if "v=DMARC1" in r]
    if not dmarc_records:
        return {"present": False, "record": None, "policy": None, "pct": None, "finding": "missing_dmarc"}
    record = dmarc_records[0].strip('"')
    tags: dict[str, str] = {}
    for tag in record.split(";"):
        tag = tag.strip()
        if "=" in tag:
            k, _, v = tag.partition("=")
            tags[k.strip()] = v.strip()
    policy = tags.get("p", "none")
    pct = int(tags.get("pct", "100"))
    finding = None
    if policy == "none":
        finding = "dmarc_policy_none"
    elif pct < 100:
        finding = "dmarc_partial_coverage"
    return {"present": True, "record": record, "policy": policy, "pct": pct, "finding": finding}


def _check_dkim(domain: str, selectors: list[str]) -> dict[str, Any]:
    found_selectors = []
    for sel in selectors:
        records = _dns_query(f"{sel}._domainkey.{domain}", "TXT")
        if any("v=DKIM1" in r or "k=rsa" in r for r in records):
            found_selectors.append(sel)
    return {
        "selectors_checked": selectors,
        "selectors_found": found_selectors,
        "finding": "no_dkim_found" if not found_selectors else None,
    }


def _check_mx(domain: str) -> dict[str, Any]:
    records = _dns_query(domain, "MX")
    if not records:
        return {"present": False, "records": [], "finding": "no_mx"}
    return {"present": True, "records": records, "finding": None}


def _check_dnssec(domain: str) -> dict[str, Any]:
    try:
        import dns.resolver
        import dns.rdatatype

        resolver = dns.resolver.Resolver()
        resolver.use_dnssec = True
        try:
            ans = resolver.resolve(domain, "A", want_dnssec=True)
            validated = ans.canonical_name is not None
        except Exception:
            validated = False
        return {"enabled": validated, "finding": None if validated else "dnssec_not_enabled"}
    except Exception:
        return {"enabled": False, "finding": "dnssec_not_enabled"}


def _check_dmarc_reporting(dmarc_result: dict[str, Any]) -> str | None:
    record = dmarc_result.get("record") or ""
    tags: dict[str, str] = {}
    for tag in record.split(";"):
        tag = tag.strip()
        if "=" in tag:
            k, _, v = tag.partition("=")
            tags[k.strip()] = v.strip()
    has_rua = "rua" in tags
    has_ruf = "ruf" in tags
    if not has_rua and not has_ruf:
        return "dmarc_no_reporting"
    return None


def scan_domain(domain: str, dkim_selectors: list[str] | None = None) -> dict[str, Any]:
    selectors = dkim_selectors or _DEFAULT_DKIM_SELECTORS
    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain, selectors)
    mx = _check_mx(domain)
    dnssec = _check_dnssec(domain)
    reporting_finding = _check_dmarc_reporting(dmarc) if dmarc["present"] else None

    findings = []
    if spf["finding"] == "missing_spf":
        findings.append({"type": "missing_spf", "severity": "high", "domain": domain,
                         "title": "No SPF Record", "description": f"{domain} has no SPF TXT record, allowing any server to send email as this domain."})
    elif spf["finding"] == "spf_permissive":
        findings.append({"type": "spf_permissive", "severity": "high", "domain": domain,
                         "title": "Permissive SPF (+all / ?all)", "description": f"{domain} SPF ends with {spf['all_mechanism']}, which permits any sender."})
    elif spf["finding"] == "spf_no_all":
        findings.append({"type": "spf_no_all", "severity": "medium", "domain": domain,
                         "title": "SPF Missing -all Terminator", "description": f"{domain} SPF record has no explicit 'all' mechanism."})

    if dmarc["finding"] == "missing_dmarc":
        findings.append({"type": "missing_dmarc", "severity": "high", "domain": domain,
                         "title": "No DMARC Record", "description": f"{domain} has no DMARC policy, leaving email open to spoofing."})
    elif dmarc["finding"] == "dmarc_policy_none":
        findings.append({"type": "dmarc_policy_none", "severity": "medium", "domain": domain,
                         "title": "DMARC Policy Set to None", "description": f"{domain} DMARC is monitoring-only (p=none); unauthenticated mail is not rejected."})
    elif dmarc["finding"] == "dmarc_partial_coverage":
        findings.append({"type": "dmarc_partial_coverage", "severity": "low", "domain": domain,
                         "title": f"DMARC Partial Coverage ({dmarc['pct']}%)", "description": f"{domain} DMARC applies only to {dmarc['pct']}% of messages."})

    if reporting_finding == "dmarc_no_reporting":
        findings.append({"type": "dmarc_no_reporting", "severity": "low", "domain": domain,
                         "title": "DMARC Has No Reporting URIs", "description": f"{domain} DMARC has no rua/ruf addresses; spoofing attempts go undetected."})

    if dkim["finding"] == "no_dkim_found":
        findings.append({"type": "no_dkim_found", "severity": "medium", "domain": domain,
                         "title": "No DKIM Selectors Found", "description": f"No DKIM TXT records found under checked selectors for {domain}."})

    if mx["finding"] == "no_mx":
        findings.append({"type": "no_mx", "severity": "info", "domain": domain,
                         "title": "No MX Records", "description": f"{domain} has no MX records; may not be configured to receive email."})

    if dnssec["finding"] == "dnssec_not_enabled":
        findings.append({"type": "dnssec_not_enabled", "severity": "low", "domain": domain,
                         "title": "DNSSEC Not Enabled", "description": f"{domain} does not have DNSSEC validation, leaving DNS responses open to spoofing."})

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "mx": mx,
        "dnssec": dnssec,
        "findings": findings,
    }


def run(domains: list[str], dkim_selectors: list[str] | None = None) -> dict[str, Any]:
    results = []
    all_findings: list[dict] = []
    for domain in domains:
        try:
            result = scan_domain(domain, dkim_selectors)
            results.append(result)
            all_findings.extend(result["findings"])
        except Exception as exc:
            logger.warning("DNS scan error for %s: %s", domain, exc)
            results.append({"domain": domain, "error": str(exc), "findings": []})

    return {
        "domains": results,
        "findings": all_findings,
        "summary": {
            "total_domains": len(domains),
            "domains_with_spf": sum(1 for r in results if r.get("spf", {}).get("present")),
            "domains_with_dmarc": sum(1 for r in results if r.get("dmarc", {}).get("present")),
            "domains_with_dkim": sum(1 for r in results if r.get("dkim", {}).get("selectors_found")),
            "total_findings": len(all_findings),
        },
    }
