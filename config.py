# config.py

from patterns import (
    c_patterns,
    python_patterns,
    javascript_patterns,
    java_patterns,
    php_patterns,
    rust_patterns
)

# ─── Paths ────────────────────────────────────────────────────────────────────
TARGET_PATH  = "./target_code"

REPORTS_DIR  = "./output/reports"
LLM_DIR      = "./output/.llm_queue" 
LLM_REPORTS_DIR = "./output/llm_reports"

# ─── Severity ─────────────────────────────────────────────────────────────────
SEVERITY_FILTER = "LOW"

SEVERITY_LEVELS = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3
}

# ─── Language Map ─────────────────────────────────────────────────────────────
LANGUAGE_MAP = {
    ".c": {
        "name":          "C",
        "semgrep_rules": "p/security-audit,p/secrets,.semgrep/custom-c-rules.yaml",
        "extensions":    [".c", ".h"],
        "patterns":      c_patterns.PATTERNS,
        "regex":         c_patterns.REGEX,
        "severity":      c_patterns.SEVERITY,
    },
    ".py": {
        "name":          "Python",
        "semgrep_rules": "p/security-audit,p/secrets",
        "extensions":    [".py"],
        "patterns":      python_patterns.PATTERNS,
        "severity":      python_patterns.SEVERITY,
        "regex":         python_patterns.REGEX,
    },
    ".js": {
        "name":          "JavaScript",
        "semgrep_rules": "p/security-audit,p/secrets",
        "extensions":    [".js", ".ts"],
        "patterns":      javascript_patterns.PATTERNS,
        "regex":         javascript_patterns.REGEX,
        "severity":      javascript_patterns.SEVERITY,
    },
    ".java": {
        "name":          "Java",
        "semgrep_rules": "p/security-audit,p/secrets",
        "extensions":    [".java"],
        "patterns":      java_patterns.PATTERNS,
        "regex":         java_patterns.REGEX,
        "severity":      java_patterns.SEVERITY,
    },
    ".php": {
        "name":          "PHP",
        "semgrep_rules": "p/security-audit,p/secrets",
        "extensions":    [".php"],
        "patterns":      php_patterns.PATTERNS,
        "regex":         php_patterns.REGEX,
        "severity":      php_patterns.SEVERITY,
    },
    ".rs": {
        "name":          "Rust",
        "semgrep_rules": "p/security-audit,p/secrets",
        "extensions":    [".rs"],
        "patterns":      rust_patterns.PATTERNS,
        "regex":         rust_patterns.REGEX,
        "severity":      rust_patterns.SEVERITY,
    },
}
# ─── Extension → Language reverse map ─────────────────────────────────────────
EXTENSION_TO_LANG = {}
for _ext, _lang_config in LANGUAGE_MAP.items():
    for _lang_ext in _lang_config["extensions"]:
        EXTENSION_TO_LANG[_lang_ext] = _lang_config
# ─── Semgrep Settings ─────────────────────────────────────────────────────────
SEMGREP_TIMEOUT = 75
