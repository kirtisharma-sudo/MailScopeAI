"""
Collects DNS / RDAP / (optionally) VirusTotal domain reputation.
Every external call is wrapped so that a network failure or missing API key
degrades to "unavailable" rather than raising, and rather than fabricating
a plausible-looking result.
"""
import socket
from datetime import datetime, timezone
import requests
from config import get_settings

settings = get_settings()

_UNAVAILABLE = "unavailable"

import re
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def is_plausible_domain(domain: str) -> bool:
    """Cheap, local sanity check before spending a network round-trip on
    something that clearly isn't a domain (whitespace, no TLD, control
    characters, etc.) — real DNS/RDAP validity still isn't guaranteed."""
    if not domain or not isinstance(domain, str):
        return False
    return bool(_DOMAIN_RE.match(domain.strip()))


def _dns_lookup(domain: str, rdtype: str) -> list[str] | str:
    try:
        import dns.resolver  # dnspython — optional dependency
        answers = dns.resolver.resolve(domain, rdtype, lifetime=4.0)
        return [str(r) for r in answers]
    except ImportError:
        # Fallback with stdlib socket for A records only
        if rdtype == "A":
            try:
                return list({addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET)})
            except Exception:
                return _UNAVAILABLE
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _dns_aaaa_lookup(domain: str) -> list[str] | str:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "AAAA", lifetime=4.0)
        return [str(r) for r in answers]
    except ImportError:
        try:
            return list({addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET6)})
        except Exception:
            return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _rdap_lookup(domain: str) -> dict | str:
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "handle": data.get("handle"),
                "status": data.get("status"),
                "events": data.get("events"),
                "entities": data.get("entities"),
            }
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _extract_registrar(rdap: dict | str) -> str:
    """Registrar name from RDAP entities with role 'registrar'. Real
    extraction only — returns 'unavailable' if the structure isn't there,
    never a guessed name."""
    if not isinstance(rdap, dict) or not rdap.get("entities"):
        return _UNAVAILABLE
    try:
        for entity in rdap["entities"]:
            if "registrar" in (entity.get("roles") or []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            return field[3]
                if entity.get("handle"):
                    return entity["handle"]
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _extract_domain_age_days(rdap: dict | str) -> int | str:
    """Computes age in days from the RDAP 'registration' event's actual
    date, if present. Never estimated/guessed — 'unavailable' otherwise."""
    if not isinstance(rdap, dict) or not rdap.get("events"):
        return _UNAVAILABLE
    try:
        for event in rdap["events"]:
            if event.get("eventAction") == "registration" and event.get("eventDate"):
                reg_date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                delta = datetime.now(timezone.utc) - reg_date
                return max(0, delta.days)
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _virustotal_domain(domain: str) -> dict | str:
    if not settings.VIRUSTOTAL_API_KEY:
        return _UNAVAILABLE
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=6,
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats or _UNAVAILABLE
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _build_interpretation(age_days, reputation) -> list[dict]:
    """Explicit observation -> interpretation pairs. Conservative language
    only — never states or implies malicious intent from a single weak signal."""
    notes = []
    if isinstance(age_days, int):
        if age_days < 30:
            notes.append({
                "observation": f"Domain was registered approximately {age_days} day(s) ago.",
                "interpretation": "Recent registration may increase suspicion when combined with other evidence, but is not proof of malicious activity — many legitimate domains are also newly registered.",
            })
        else:
            notes.append({
                "observation": f"Domain registration is approximately {age_days} day(s) old.",
                "interpretation": "An established registration age slightly reduces (but does not eliminate) the likelihood of a disposable phishing domain.",
            })
    if isinstance(reputation, dict) and reputation.get("malicious", 0):
        notes.append({
            "observation": f"{reputation['malicious']} reputation provider(s) flagged this domain as malicious.",
            "interpretation": "Third-party reputation flags are contextual evidence, not definitive proof — always combine with other signals.",
        })
    return notes


def gather_domain_intel(domain: str) -> dict:
    if not is_plausible_domain(domain):
        return {
            "domain": domain, "a_records": _UNAVAILABLE, "aaaa_records": _UNAVAILABLE,
            "mx_records": _UNAVAILABLE, "ns_records": _UNAVAILABLE, "rdap": _UNAVAILABLE,
            "age_days": _UNAVAILABLE, "registrar": _UNAVAILABLE, "reputation": _UNAVAILABLE,
            "interpretation": [], "note": "Domain string failed basic format validation; no external lookups were attempted.",
        }

    a_records = _dns_lookup(domain, "A")
    aaaa_records = _dns_aaaa_lookup(domain)
    mx_records = _dns_lookup(domain, "MX")
    ns_records = _dns_lookup(domain, "NS")
    rdap = _rdap_lookup(domain)
    reputation = _virustotal_domain(domain)
    age_days = _extract_domain_age_days(rdap)
    registrar = _extract_registrar(rdap)

    return {
        "domain": domain,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "rdap": rdap,
        "age_days": age_days,
        "registrar": registrar,
        "reputation": reputation,
        "interpretation": _build_interpretation(age_days, reputation),
    }
