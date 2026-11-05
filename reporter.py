# reporter.py

import os
import json
from datetime import datetime
from collections import Counter, defaultdict
import config


def generate_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def ensure_directories():
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    os.makedirs(config.LLM_DIR,     exist_ok=True)


def format_line(finding: dict) -> str:
    if finding["line_start"] == finding["line_end"]:
        return str(finding["line_start"])
    return f"{finding['line_start']} - {finding['line_end']}"


def save_llm_queue(findings: list, timestamp: str):
    ensure_directories()

    severity_counts = Counter(f["severity"] for f in findings)

    payload = {
        "meta": {
            "timestamp": timestamp,
            "total":     len(findings),
            "critical":  severity_counts.get("CRITICAL", 0),
            "high":      severity_counts.get("HIGH",     0),
            "medium":    severity_counts.get("MEDIUM",   0),
            "low":       severity_counts.get("LOW",      0),
        },
        "findings": findings
    }

    filepath = os.path.join(config.LLM_DIR, f"scan_{timestamp}.json")

    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"[*] LLM queue saved to  {filepath}")


def _build_report_lines(findings: list, timestamp: str) -> list:
    severity_counts = Counter(f["severity"] for f in findings)

    # Group by file, sort files alphabetically
    file_groups = defaultdict(list)
    for f in findings:
        file_groups[f["file"]].append(f)

    sorted_files = sorted(file_groups.keys())

    out = []
    out.append("=" * 55)
    out.append("        VULNERABILITY SCAN REPORT")
    out.append("=" * 55)
    out.append(f"  Timestamp      : {timestamp}")
    out.append(f"  Total findings : {len(findings)}")
    out.append(f"  CRITICAL       : {severity_counts.get('CRITICAL', 0)}")
    out.append(f"  HIGH           : {severity_counts.get('HIGH',     0)}")
    out.append(f"  MEDIUM         : {severity_counts.get('MEDIUM',   0)}")
    out.append(f"  LOW            : {severity_counts.get('LOW',      0)}")
    out.append("=" * 55)

    for file_path in sorted_files:
        # Sort findings within file by line number ascending
        file_findings = sorted(file_groups[file_path], key=lambda x: x["line_start"])

        out.append(f"\n  FILE: {file_path}")
        out.append(f"  {'─' * 49}")

        for finding in file_findings:
            rule_count = finding.get("rule_count", 1)
            out.append(f"\n    [{finding['severity']}] {finding['type']}")
            if rule_count > 1:
                out.append(f"    Rules matched : {rule_count}")
            out.append(f"    Reference : {finding.get('reference', 'N/A')}")
            out.append(f"    Line      : {format_line(finding)}")
            out.append(f"    Source    : {finding['source']}")
            out.append(f"    Code      :")
            for code_line in finding["code"].splitlines():
                out.append(f"        {code_line}")
            out.append(f"    {'─' * 49}")

    return out


def save_report_and_print(findings: list, timestamp: str = None):
    ensure_directories()
    
    # Use the passed timestamp, or generate one if missing
    if not timestamp:
        timestamp = generate_timestamp()

    report_lines = _build_report_lines(findings, timestamp)
    report_text  = "\n".join(report_lines)

    filepath = os.path.join(config.REPORTS_DIR, f"report_{timestamp}.txt")
    with open(filepath, "w") as f:
        f.write(report_text)

    print(f"[*] Report saved to     {filepath}")
    print(report_text)
