# parser.py

import os
import config


def normalize_path(filepath: str) -> str:
    return os.path.normpath(filepath)


def filter_by_severity(findings: list) -> list:
    threshold = config.SEVERITY_LEVELS[config.SEVERITY_FILTER]
    return [
        f for f in findings
        if config.SEVERITY_LEVELS.get(f["severity"], 99) <= threshold
    ]


def aggregate(findings: list) -> list:
    """
    Merges findings with overlapping line ranges in the same file.
    Preserves all rule names, keeps the highest severity, and adds rule_count.
    Time complexity: O(n log n) due to sort, then O(n) merge pass.
    """
    if not findings:
        return []

    sev_rank = config.SEVERITY_LEVELS

    for f in findings:
        f["file"] = normalize_path(f["file"])

    # Sort by file then line_start so interval merge works in one pass
    sorted_findings = sorted(findings, key=lambda f: (f["file"], f["line_start"]))

    merged = []

    for finding in sorted_findings:
        if not merged:
            m = finding.copy()
            m["types"]      = [finding["type"]]
            m["rule_count"] = 1
            merged.append(m)
            continue

        last = merged[-1]

        # Merge if same file and line ranges overlap
        if (last["file"] == finding["file"] and
                finding["line_start"] <= last["line_end"]):

            if finding["type"] not in last["types"]:
                last["types"].append(finding["type"])

            last["rule_count"] = len(last["types"])
            last["type"]       = " / ".join(last["types"])

            # Keep highest severity (lowest rank number)
            if sev_rank.get(finding["severity"], 99) < sev_rank.get(last["severity"], 99):
                last["severity"] = finding["severity"]

            last["line_end"] = max(last["line_end"], finding["line_end"])

            # Merge sources
            if last.get("source") != finding["source"]:
                last["source"] = "regex + semgrep"

            # Prefer semgrep code block if multiline and longer
            if (finding["source"] == "semgrep"
                    and "\n" in finding.get("code", "")
                    and len(finding["code"]) > len(last.get("code", ""))):
                last["code"] = finding["code"]
        else:
            m = finding.copy()
            m["types"]      = [finding["type"]]
            m["rule_count"] = 1
            merged.append(m)

    return merged


def sort_by_severity(findings: list) -> list:
    return sorted(
        findings,
        key=lambda f: config.SEVERITY_LEVELS.get(f["severity"], 99)
    )


def parse(findings: list) -> list:
    print(f"\n[*] Parsing {len(findings)} raw findings...")

    findings = filter_by_severity(findings)
    print(f"    After severity filter : {len(findings)}")

    findings = aggregate(findings)
    print(f"    After aggregation     : {len(findings)}")

    findings = sort_by_severity(findings)
    print(f"    Sorted by severity    : done")

    return findings
