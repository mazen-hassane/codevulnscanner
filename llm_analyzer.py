# llm_analyzer.py

import json
import os
import re
import requests
from collections import Counter
from datetime import datetime

import config
import reporter

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma4:26b"

PROMPT_TEMPLATE = """You are a security code analysis assistant.
Below is a JSON array of vulnerability findings from a static analysis scan.
For each finding, decide if it is a REAL vulnerability (CONFIRMED) or a false positive (UNCONFIRMED).

Base your decision on:
- The code snippet provided
- The vulnerability type
- Whether the code pattern actually introduces risk in context

Respond ONLY with a valid JSON array, no explanation, no markdown. Format:
[{{"index": 0, "verdict": "CONFIRMED"}}, {{"index": 1, "verdict": "UNCONFIRMED"}}, ...]

Findings:
{findings_json}
"""


def load_latest_queue() -> tuple:
    if not os.path.exists(config.LLM_DIR):
        print("  [!] LLM queue directory not found.")
        return None, None

    files = sorted([
        f for f in os.listdir(config.LLM_DIR)
        if f.startswith("scan_") and f.endswith(".json")
    ])

    if not files:
        print("  [!] No scan files found in LLM queue.")
        return None, None

    latest = os.path.join(config.LLM_DIR, files[-1])
    print(f"[*] Loading LLM queue: {latest}")

    with open(latest, "r") as f:
        payload = json.load(f)

    return payload.get("findings", []), payload.get("meta", {})


def _call_ollama(findings: list) -> list:
    findings_json = json.dumps(
        [{"index": i, "type": f["type"], "severity": f["severity"],
          "code": f["code"], "file": f["file"]} for i, f in enumerate(findings)],
        indent=2
    )

    prompt = PROMPT_TEMPLATE.format(findings_json=findings_json)

    try:
        resp = requests.post(OLLAMA_URL, json={
            "model":  OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=300)

        raw = resp.json().get("response", "")

        # Strip markdown fences if present
        raw = re.sub(r"```(?:json)?", "", raw).strip()

        verdicts = json.loads(raw)
        return verdicts

    except requests.exceptions.ConnectionError:
        print("  [!] Ollama not reachable at localhost:11434 — all tagged [UNCONFIRMED]")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        print(f"  [!] Failed to parse Ollama response: {e} — all tagged [UNCONFIRMED]")
        return []


def _apply_tags(findings: list, verdicts: list) -> list:
    verdict_map = {v["index"]: v["verdict"] for v in verdicts if "index" in v and "verdict" in v}

    tagged = []
    for i, f in enumerate(findings):
        fc = f.copy()
        fc["llm_tag"] = verdict_map.get(i, "UNCONFIRMED")
        tagged.append(fc)

    confirmed   = sum(1 for f in tagged if f["llm_tag"] == "CONFIRMED")
    unconfirmed = sum(1 for f in tagged if f["llm_tag"] == "UNCONFIRMED")
    print(f"    Confirmed   : {confirmed}")
    print(f"    Unconfirmed : {unconfirmed}")

    return tagged


def _build_llm_report_lines(tagged: list, timestamp: str) -> list:
    from collections import defaultdict

    severity_counts = Counter(f["severity"] for f in tagged)
    confirmed_counts = Counter(f["severity"] for f in tagged if f["llm_tag"] == "CONFIRMED")

    file_groups = defaultdict(list)
    for f in tagged:
        file_groups[f["file"]].append(f)

    out = []
    out.append("=" * 55)
    out.append("     LLM-ANALYZED VULNERABILITY REPORT")
    out.append("=" * 55)
    out.append(f"  Timestamp        : {timestamp}")
    out.append(f"  Total findings   : {len(tagged)}")
    out.append(f"  Confirmed        : {sum(1 for f in tagged if f['llm_tag'] == 'CONFIRMED')}")
    out.append(f"  Unconfirmed (FP) : {sum(1 for f in tagged if f['llm_tag'] == 'UNCONFIRMED')}")
    out.append(f"  CRITICAL         : {severity_counts.get('CRITICAL', 0)}")
    out.append(f"  HIGH             : {severity_counts.get('HIGH',     0)}")
    out.append(f"  MEDIUM           : {severity_counts.get('MEDIUM',   0)}")
    out.append(f"  LOW              : {severity_counts.get('LOW',      0)}")
    out.append("=" * 55)

    for file_path in sorted(file_groups.keys()):
        file_findings = sorted(file_groups[file_path], key=lambda x: x["line_start"])

        out.append(f"\n  FILE: {file_path}")
        out.append(f"  {'─' * 49}")

        for f in file_findings:
            rule_count = f.get("rule_count", 1)
            tag        = f["llm_tag"]
            out.append(f"\n    [{f['severity']}] [{tag}] {f['type']}")
            if rule_count > 1:
                out.append(f"    Rules matched : {rule_count}")
            out.append(f"    Reference : {f.get('reference', 'N/A')}")
            out.append(f"    Line      : {reporter.format_line(f)}")
            out.append(f"    Source    : {f['source']}")
            out.append(f"    Code      :")
            for code_line in f["code"].splitlines():
                out.append(f"        {code_line}")
            out.append(f"    {'─' * 49}")

    return out


def run():
    findings, meta = load_latest_queue()

    if not findings:
        print("[!] LLM analysis skipped — no findings in queue.")
        return

    print(f"[*] Sending {len(findings)} findings to Ollama ({OLLAMA_MODEL})...")
    verdicts = _call_ollama(findings)
    tagged   = _apply_tags(findings, verdicts)

    timestamp    = reporter.generate_timestamp()
    report_lines = _build_llm_report_lines(tagged, timestamp)
    report_text  = "\n".join(report_lines)

    os.makedirs(config.LLM_REPORTS_DIR, exist_ok=True)
    filepath = os.path.join(config.LLM_REPORTS_DIR, f"LLMoutput_{timestamp}.txt")
    with open(filepath, "w") as f:
        f.write(report_text)

    print(f"[*] LLM report saved to {filepath}")
