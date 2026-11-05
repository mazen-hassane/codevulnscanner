# scanner.py

import os
import re
import subprocess
import json
from collections import Counter
import config


def detect_languages(path: str) -> list:
    extension_counts = Counter()

    for root, _, files in os.walk(path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext:
                extension_counts[ext] += 1

    detected = []
    for ext, lang_config in config.LANGUAGE_MAP.items():
        for lang_ext in lang_config["extensions"]:
            if extension_counts[lang_ext] > 0:
                detected.append(lang_config)
                break

    return detected


def extract_code_block(lines: list, line_num: int, pattern: str) -> tuple:
    total = len(lines)
    start = line_num - 1
    end   = line_num - 1

    for i in range(line_num, min(line_num + 5, total)):
        next_line = lines[i].strip()
        end = i
        if any(next_line.endswith(c) for c in [';', '{', '}', '']):
            break

    code_block = "".join(lines[start:end + 1]).strip()
    return code_block, start + 1, end + 1


def detect_use_after_free(lines: list, filepath: str) -> list:
    findings    = []
    freed       = {}  # var_name -> line number of free()

    free_re     = re.compile(r'\bfree\s*\(\s*(\w+)\s*\)')

    # First pass: collect every pointer passed to free()
    for line_num, line in enumerate(lines, start=1):
        m = free_re.search(line)
        if m:
            freed[m.group(1)] = line_num   # last free() wins

    # Second pass: look for usage of each freed pointer after its free() line
    for var, free_line in freed.items():
        usage_re    = re.compile(r'\b' + re.escape(var) + r'\b')
        reassign_re = re.compile(r'\b' + re.escape(var) + r'\s*=(?!=)')  # assignment, not ==

        for line_num, line in enumerate(lines, start=1):
            if line_num <= free_line:
                continue
            if not line.strip():
                continue
            # Skip reassignments (NULL, 0, or fresh allocation)
            if reassign_re.search(line):
                continue
            if usage_re.search(line):
                code_block, block_start, block_end = extract_code_block(
                    lines, line_num, ""
                )
                findings.append({
                    "file":       os.path.normpath(filepath),
                    "line_start": block_start,
                    "line_end":   block_end,
                    "type":       "use-after-free",
                    "severity":   "CRITICAL",
                    "reference":  "N/A",
                    "code":       code_block,
                    "source":     "regex"
                })
                break  # report only first usage per freed variable

    return findings


def regex_scan(path: str, lang_config: dict) -> list:
    findings   = []
    extensions = lang_config["extensions"]
    patterns   = lang_config["patterns"]
    severity   = lang_config["severity"]
    references = lang_config.get("references", {})

    for root, _, files in os.walk(path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in extensions:
                continue

            filepath = os.path.join(root, file)

            try:
                with open(filepath, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"  [!] Could not read {filepath}: {e}")
                continue

            for line_num, line in enumerate(lines, start=1):
                for vuln_name, pattern in lang_config["regex"].items():
                    if re.search(pattern, line):
                        category  = patterns.get(vuln_name, vuln_name)
                        sev       = severity.get(category, severity.get(vuln_name, "MEDIUM"))
                        ref       = references.get(category, references.get(vuln_name, "N/A"))

                        code_block, block_start, block_end = extract_code_block(
                            lines, line_num, pattern
                        )
                        findings.append({
                            "file":       os.path.normpath(filepath),
                            "line_start": block_start,
                            "line_end":   block_end,
                            "type":       category,
                            "severity":   sev,
                            "reference":  ref,
                            "code":       code_block,
                            "source":     "regex"
                        })

            # Two-pass use-after-free detection for C only
            if lang_config["name"] == "C":
                findings.extend(detect_use_after_free(lines, filepath))

    return findings


def semgrep_scan(path: str) -> list:
    """Single Semgrep invocation covering all languages."""
    findings = []

    severity_map = {
        "ERROR":   "CRITICAL",
        "WARNING": "HIGH",
        "INFO":    "MEDIUM",
        "NOTE":    "LOW",
    }

    # Collect and deduplicate all rulesets across every language
    seen_rules = set()
    unique_rules = []
    for lang_config in config.LANGUAGE_MAP.values():
        for rule in lang_config["semgrep_rules"].split(","):
            rule = rule.strip()
            if rule not in seen_rules and not rule.endswith(".yaml"):
                seen_rules.add(rule)
                unique_rules.append(rule)
    command = ["semgrep"]
    for rule in unique_rules:
        command += ["--config", rule]
    command += [
        "--json",
        "--no-git-ignore",
        "--metrics=off",
        "--timeout", str(config.SEMGREP_TIMEOUT),
        path
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode not in (0, 1):
            stderr_full = result.stderr.strip() if result.stderr else "no error message"
            print(f"  [!] Semgrep error:")
            print(f"      Command     : {' '.join(command)}")
            print(f"      Return code : {result.returncode}")
            print(f"      Stderr      : {stderr_full}")
            return findings

        if not result.stdout.strip():
            print("  [!] Semgrep returned empty output")
            return findings

        raw = json.loads(result.stdout)

        for match in raw.get("results", []):
            filepath   = match.get("path", "")
            ext        = os.path.splitext(filepath)[1].lower()
            lang_config = config.EXTENSION_TO_LANG.get(ext)

            if lang_config is None:
                continue  # Unknown extension — skip

            check_id     = match.get("check_id", "unknown")
            vuln_type    = check_id.split(".")[-1] if "." in check_id else check_id
            raw_severity = match.get("extra", {}).get("severity", "INFO").upper()
            code_lines   = match.get("extra", {}).get("lines", "")
            line_start   = match.get("start", {}).get("line", 0)
            line_end     = match.get("end",   {}).get("line", line_start)

            if not line_start:
                continue

            if not code_lines or not code_lines.strip():
                code_lines = f"(no code snippet available for {vuln_type})"

            findings.append({
                "file":       os.path.normpath(filepath),
                "line_start": line_start,
                "line_end":   line_end,
                "type":       vuln_type,
                "severity":   severity_map.get(raw_severity, "MEDIUM"),
                "reference":  "Semgrep",
                "code":       code_lines.strip(),
                "source":     "semgrep"
            })

    except FileNotFoundError:
        print("  [!] Semgrep not found — skipping Semgrep scan, using regex only.")
    except subprocess.TimeoutExpired:
        print("  [!] Semgrep timed out — skipping Semgrep scan.")
    except json.JSONDecodeError as e:
        print(f"  [!] Could not parse Semgrep output: {e}")

    return findings


def scan(path: str) -> list:
    all_findings = []

    if not os.path.exists(path):
        print(f"[!] Target path does not exist: {path}")
        return all_findings

    print(f"\n[*] Scanning: {path}")

    languages = detect_languages(path)

    if not languages:
        print("[!] No recognized source files found in target folder.")
        return all_findings

    print(f"[*] Detected languages: {[l['name'] for l in languages]}\n")

    total_regex = 0

    for lang in languages:
        print(f"[*] Scanning {lang['name']} files (regex)...")
        regex_findings = regex_scan(path, lang)
        all_findings.extend(regex_findings)
        total_regex += len(regex_findings)
        print(f"    Regex → {len(regex_findings)} raw matches")

    print(f"\n[*] Running Semgrep (single pass, all languages)...")
    semgrep_findings = semgrep_scan_all(path)
    all_findings.extend(semgrep_findings)

    print(f"\n[*] Raw matches before deduplication:")
    print(f"    Regex   total → {total_regex}")
    print(f"    Semgrep total → {len(semgrep_findings)}")
    print(f"    Combined      → {len(all_findings)}")

    return all_findings

def scan(path: str) -> list:
    all_findings  = []

    if not os.path.exists(path):
        print(f"[!] Target path does not exist: {path}")
        return all_findings

    print(f"\n[*] Scanning: {path}")

    languages = detect_languages(path)

    if not languages:
        print("[!] No recognized source files found in target folder.")
        return all_findings

    print(f"[*] Detected languages: {[l['name'] for l in languages]}\n")

    total_regex   = 0
    total_semgrep = 0

    for lang in languages:
        print(f"[*] Scanning {lang['name']} files...")

        regex_findings   = regex_scan(path, lang)
        semgrep_findings = semgrep_scan(path)

        all_findings.extend(regex_findings)
        all_findings.extend(semgrep_findings)

        total_regex   += len(regex_findings)
        total_semgrep += len(semgrep_findings)

        print(f"    Regex   → {len(regex_findings)} raw matches")
        print(f"    Semgrep → {len(semgrep_findings)} raw matches")

    print(f"\n[*] Raw matches before deduplication:")
    print(f"    Regex   total → {total_regex}")
    print(f"    Semgrep total → {total_semgrep}")
    print(f"    Combined      → {len(all_findings)}")

    return all_findings
