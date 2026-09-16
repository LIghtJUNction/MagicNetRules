"""Strict, explicitly scoped adapters for build-time primary text feeds."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMATS = {"clash-domain", "dnsmasq", "cidr4", "cidr6", "domains-exact"}
OMITTABLE = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "PROCESS-NAME", "USER-AGENT"}
FIELDS = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword"}


def load_registry(path: Path = ROOT / "config/text-sources.json") -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate registry key: {key}")
            result[key] = value
        return result
    registry = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(registry, dict) or not registry:
        raise ValueError("Empty text source registry")
    for name, spec in registry.items():
        if not re.fullmatch(r"[a-z0-9-]+", name) or not isinstance(spec, dict):
            raise ValueError(f"Invalid text source: {name}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", spec["repository"]):
            raise ValueError(f"Invalid repository: {name}")
        for field in ("branch", "path", "license_branch", "license_path"):
            value = spec[field]
            if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./!-]+", value)
                    or any(part in ("", ".", "..") for part in value.split("/"))):
                raise ValueError(f"Unsafe {field}: {name}")
        if spec["format"] not in FORMATS:
            raise ValueError(f"Unsupported format: {name}")
        low, high = spec["min_entries"], spec["max_entries"]
        if type(low) is not int or type(high) is not int or not 1 <= low <= high <= 1000000:
            raise ValueError(f"Invalid entry bounds: {name}")
        omitted = spec.get("omit_types", [])
        if (not isinstance(omitted, list) or not set(omitted) <= OMITTABLE
                or (omitted and spec["format"] != "clash-domain")):
            raise ValueError(f"Invalid projection: {name}")
        if not isinstance(spec.get("license"), str) or not spec["license"]:
            raise ValueError(f"Missing license: {name}")
    return registry


def domain(value: str) -> str:
    """Canonicalize DNS names, never turn hosts/URLs/wildcards into suffixes."""
    if value != value.strip() or value.endswith("..") or any(c.isspace() for c in value):
        raise ValueError(f"Invalid domain: {value!r}")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise ValueError(f"Invalid domain: {value!r}")
    return value


def parse_text(data: bytes, spec: dict) -> tuple[dict, dict]:
    """Return a headless rule set and audit counts; unknown syntax fails closed.

    clash-domain is deliberately a domain-only projection, not a full Clash
    converter. Every omitted record type must be declared by the source owner
    configuration and is counted. In particular ASN and no-resolve never become
    broad IP rules. DNS server choices in dnsmasq inputs are not imported.
    """
    fmt = spec["format"]
    if fmt not in FORMATS:
        raise ValueError(f"Unsupported format: {fmt}")
    values: dict[str, set[str]] = {}
    skipped: dict[str, int] = {}
    accepted = 0
    for number, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        try:
            if fmt == "clash-domain":
                parts = [part.strip() for part in line.split(",")]
                kind = parts[0]
                if kind in spec.get("omit_types", []):
                    if len(parts) not in (2, 3) or not parts[1] or (len(parts) == 3 and parts[2] != "no-resolve"):
                        raise ValueError("Malformed projected-out rule")
                    if kind in ("IP-CIDR", "IP-CIDR6"):
                        net = ipaddress.ip_network(parts[1], strict=True)
                        if net.version != (4 if kind == "IP-CIDR" else 6):
                            raise ValueError("IP family mismatch")
                    elif kind == "IP-ASN" and (not parts[1].isdigit() or not 1 <= int(parts[1]) <= 4294967295):
                        raise ValueError("Invalid ASN")
                    skipped[kind] = skipped.get(kind, 0) + 1
                    continue
                if kind not in FIELDS or len(parts) != 2 or not parts[1]:
                    raise ValueError(f"Unsupported rule type/qualifier: {kind}")
                field = FIELDS[kind]
                if kind == "DOMAIN-KEYWORD":
                    value = parts[1].lower()
                    if not re.fullmatch(r"[a-z0-9_.-]+", value):
                        raise ValueError("Invalid domain keyword")
                else:
                    value = domain(parts[1])
            elif fmt == "dnsmasq":
                match = re.fullmatch(r"server=/([^/]+)/([^/]+)", line)
                if not match:
                    raise ValueError("Unsupported dnsmasq directive")
                ipaddress.ip_address(match[2])
                field, value = "domain_suffix", domain(match[1])
            elif fmt.startswith("cidr"):
                if "/" not in line:
                    raise ValueError("Expected a CIDR prefix")
                net = ipaddress.ip_network(line, strict=True)
                if net.version != int(fmt[-1]) or net.prefixlen == 0:
                    raise ValueError("Wrong IP family or default route")
                if not net.network_address.is_global or not net.broadcast_address.is_global:
                    raise ValueError("Non-global address in country feed")
                field, value = "ip_cidr", str(net)
            else:
                field, value = "domain", domain(line)
            values.setdefault(field, set()).add(value)
            accepted += 1
        except (ValueError, UnicodeError) as error:
            raise ValueError(f"{fmt} line {number}: {error}") from error
    count = sum(len(items) for items in values.values())
    if not spec["min_entries"] <= count <= spec["max_entries"]:
        raise ValueError(f"Unexpected {fmt} entry count: {count}")
    rule = {field: sorted(items) for field, items in sorted(values.items())}
    for protected in spec.get("must_not_match", []):
        protected = domain(protected)
        if (protected in values.get("domain", set())
                or any(protected == suffix or protected.endswith("." + suffix) for suffix in values.get("domain_suffix", set()))
                or any(word in protected for word in values.get("domain_keyword", set()))):
            raise ValueError(f"Source unexpectedly matches protected domain: {protected}")
    return {"version": 2, "rules": [rule]}, {
        "format": fmt, "accepted_entries": accepted, "unique_entries": count,
        "duplicates_removed": accepted - count, "omitted_types": dict(sorted(skipped.items())),
    }
