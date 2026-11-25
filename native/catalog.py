"""Optimize the source-readable sets in MagicNetRules without mixing policies."""
from collections import defaultdict
import gzip
import hashlib
import io
import ipaddress
import json
import tarfile

FIELDS = {"domain", "domain_suffix", "domain_regex", "domain_keyword", "ip_cidr"}


def compact(values):
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def compressed(data):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
        stream.write(data)
    return buffer.getvalue()


def optimize(groups):
    # All supported fields are destination conditions joined by OR. Keep each
    # source format version separate, especially historical suffix semantics.
    by_version = defaultdict(lambda: defaultdict(set))
    before = 0
    for group in groups:
        version = group["version"]
        if version not in (1, 2, 3, 4, 5):
            raise ValueError("unknown source format version")
        for rule in group["rules"]:
            if not rule or not rule.keys() <= FIELDS:
                raise ValueError("unsupported predicate or qualifier in source")
            for key, values in rule.items():
                if isinstance(values, str):
                    values = [values]
                if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                    raise ValueError("invalid source predicate values")
                before += len(values)
                by_version[version][key].update(values)
    output = []
    for version, kinds in sorted(by_version.items()):
        rule = {key: sorted(values) for key, values in kinds.items()}
        if "ip_cidr" in rule:
            ips = [ipaddress.ip_network(value, strict=True) for value in rule["ip_cidr"]]
            rule["ip_cidr"] = [
                str(prefix) for family in (4, 6)
                for prefix in ipaddress.collapse_addresses(ip for ip in ips if ip.version == family)
            ]
        output.append({"version": version, "rules": [rule]})
    count = sum(len(v) for group in output for v in group["rules"][0].values())
    return output, before, count


def build_catalog(raw, light):
    files = {}
    stats = {"input_entries": 0, "output_entries": 0, "logical_sets": 0,
             "baseline_compressed_bytes": 0}
    index = {}
    # Read only named regular assets. Never execute or extract archived scripts.
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        def read(name):
            entry = tar.getmember(name)
            if not entry.isreg() or entry.size > 48 * 1024 * 1024:
                raise ValueError("unexpected archive member")
            return tar.extractfile(entry).read()

        registry = json.loads(read("config/rulesets.json"))
        inputs = {
            p.name[8:-5]: json.loads(read(p.name)) for p in tar.getmembers()
            if p.name.startswith("sources/") and p.name.endswith(".json")
        }
        previous = set(inputs["hagezi-light-domains"]["rules"][0]["domain"])
        current = set(light)
        stats["updated_feed"] = {"previous_entries": len(previous), "added": len(current - previous),
                                 "removed": len(previous - current)}
        inputs["hagezi-light-domains"] = {"version": 2, "rules": [{"domain": light}]}
        names = {name: spec["sources"] for name, spec in registry["merged_rulesets"].items()}
        names.update(registry["service_rulesets"])
        names.update({name: [name] for name in registry["standalone_sources"]})
        for name, deps in sorted(names.items()):
            source_groups = [inputs[dep] for dep in deps]
            stats["baseline_compressed_bytes"] += len(compressed(compact(source_groups)))
            payload, before, after = optimize(source_groups)
            blob = compressed(compact(payload))
            digest = hashlib.sha256(blob).hexdigest()
            files["catalog/objects/" + digest + ".json.gz"] = blob
            index[name] = {"sha256": digest, "bytes": len(blob), "entries": after}
            stats["input_entries"] += before
            stats["output_entries"] += after
            stats["logical_sets"] += 1
        # These three SRS-only assets have no normalized source in this archive.
        manifest = {"version": 1, "sets": index, "binary_only_upstream": registry["binary_sources"]}
        files["catalog/index.json"] = compact(manifest) + b"\n"
        files["catalog/upstream-manifest.json"] = read("upstream-manifest.json")
        for entry in tar.getmembers():
            if entry.name.startswith("sources/") and entry.name.endswith(".LICENSE.txt"):
                files["catalog/licenses/" + entry.name.split("/")[-1]] = read(entry.name)
    stats["unique_objects"] = len(set(item["sha256"] for item in index.values()))
    stats["compressed_object_bytes"] = sum(len(v) for k, v in files.items() if k.endswith(".gz"))
    return files, stats
