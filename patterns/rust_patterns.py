# patterns/rust_patterns.py

PATTERNS = {
    #----input validation ------------------------------------------------------
    "input-validation-cmd-arg":         "input-validation",
    "input-validation-config-exec":     "input-validation",
    "input-validation-format-exec":     "input-validation",
    "input-validation-user-spawn":      "input-validation",
    "input-validation-shell-string":    "input-validation",

    # ─── Unsafe Code ──────────────────────────────────────────────────────────
    "unsafe-block":                 "unsafe-code",
    "unsafe-impl":                  "unsafe-code",
    "unsafe-trait":                 "unsafe-code",
    "unsafe-fn":                    "unsafe-code",

    # ─── Raw Pointer ──────────────────────────────────────────────────────────
    "raw-pointer-mut":              "raw-pointer",
    "raw-pointer-const":            "raw-pointer",
    "raw-pointer-deref":            "raw-pointer",
    "pointer-cast":                 "raw-pointer",

    # ─── Error Handling ───────────────────────────────────────────────────────
    "unwrap-result":                "error-handling",
    "expect-result":                "error-handling",
    "unwrap-or-else":               "error-handling",
    "panic-macro":                  "error-handling",
    "unreachable-macro":            "error-handling",

    # ─── Integer Overflow ─────────────────────────────────────────────────────
    "integer-overflow-cast":        "integer-overflow",
    "wrapping-arithmetic":          "integer-overflow",
    "unchecked-arithmetic":         "integer-overflow",
    "integer-overflow-index":       "integer-overflow",

    # ─── FFI Vulnerability ────────────────────────────────────────────────────
    "ffi-extern":                   "ffi-vulnerability",
    "ffi-transmute":                "ffi-vulnerability",
    "ffi-from-raw":                 "ffi-vulnerability",
    "ffi-raw-parts":                "ffi-vulnerability",
    "ffi-slice-from-raw":           "ffi-vulnerability",

    # ─── Concurrency ──────────────────────────────────────────────────────────
    "mutex-poisoned":               "concurrency",
    "send-sync-impl":               "concurrency",
    "data-race-static-mut":         "concurrency",
    "arc-mutex-deadlock":           "concurrency",

    # ─── Weak Cryptography ────────────────────────────────────────────────────
    "weak-crypto-md5":              "weak-cryptography",
    "weak-random":                  "weak-cryptography",
    "no-constant-time":             "weak-cryptography",

    # ─── Hardcoded Secret ─────────────────────────────────────────────────────
    "hardcoded-secret":             "hardcoded-secret",

    # ─── Command Injection ────────────────────────────────────────────────────
    "cmd-exec-config-interpolate":  "command-injection",
    "cmd-exec-command-new-sh":      "command-injection",
    "cmd-exec-arg-user-input":      "command-injection",
    "cmd-exec-format-cmd":          "command-injection",
    "cmd-exec-config-hashmap":      "command-injection",
    "cmd-exec-insert-no-validate":  "command-injection",
    "cmd-exec-config-get-cmd":      "command-injection",
    "cmd-exec-shell-metachar":      "command-injection",
    "cmd-exec-arg-c-flag":          "command-injection",
    "cmd-exec-spawn-format":        "command-injection",

    # ─── Memory ───────────────────────────────────────────────────────────────
    "forget-memory":                "ffi-vulnerability",
    "drop-raw":                     "ffi-vulnerability",
    "uninitialized-memory":         "ffi-vulnerability",
    "zeroed-memory":                "ffi-vulnerability",
}

REGEX = {
    "input-validation-cmd-arg":         r'Command::new\s*\([^)]+\)\s*(?:\n[^;]*)*\.arg\s*\(\s*&?\w+\s*\)',
    "input-validation-config-exec":     r'self\.\w+\.(get|entry)\s*\([^)]+\)[^;]*\n[^;]*\.arg\s*\(',
    "input-validation-format-exec":     r'let\s+\w+\s*=\s*format!\s*\([^)]+\);\s*\n[^;]*Command',
    "input-validation-user-spawn":      r'\.(spawn|output|status)\s*\(\s*\)\s*\.expect\s*\(',
    "input-validation-shell-string":    r'Command::new\s*\(\s*"(sh|bash)"\s*\)[^;]*\.arg\s*\(\s*"-c"\s*\)[^;]*\.arg\s*\(',
    "unsafe-block":                 r'\bunsafe\s*\{',
    "unsafe-impl":                  r'\bunsafe\s+impl\b',
    "unsafe-trait":                 r'\bunsafe\s+trait\b',
    "unsafe-fn":                    r'\bunsafe\s+fn\b',
    "raw-pointer-mut":              r'\*mut\s+\w+',
    "raw-pointer-const":            r'\*const\s+\w+',
    "raw-pointer-deref":            r'\*\s*\w+\s*(?:as\s*\*)',
    "pointer-cast":                 r'as\s+\*\s*(mut|const)',
    "unwrap-result":                r'\.unwrap\s*\(\s*\)',
    "expect-result":                r'\.expect\s*\(\s*"[^"]*"\s*\)',
    "unwrap-or-else":               r'\.unwrap_or_else\s*\(',
    "panic-macro":                  r'\bpanic!\s*\(',
    "unreachable-macro":            r'\bunreachable!\s*\(',
    "integer-overflow-cast":        r'as\s+(i8|i16|i32|u8|u16|u32)',
    "wrapping-arithmetic":          r'\.(wrapping_add|wrapping_sub|wrapping_mul)\s*\(',
    "unchecked-arithmetic":         r'\.(unchecked_add|unchecked_sub|unchecked_mul)\s*\(',
    "integer-overflow-index":       r'\w+\[(\w+\s*as\s*usize|\w+\s*\+\s*\w+)\]',
    "ffi-extern":                   r'\bextern\s+["\']C["\']\s*\{',
    "ffi-transmute":                r'std::mem::transmute\s*::<',
    "ffi-from-raw":                 r'\bBox::from_raw\s*\(',
    "ffi-raw-parts":                r'Vec::from_raw_parts\s*\(',
    "ffi-slice-from-raw":           r'std::slice::from_raw_parts\s*\(',
    "mutex-poisoned":               r'\.lock\s*\(\s*\)\.unwrap\s*\(\s*\)',
    "send-sync-impl":               r'unsafe\s+impl\s+Send\s+for',
    "data-race-static-mut":         r'static\s+mut\s+\w+',
    "arc-mutex-deadlock":           r'Arc::new\s*\(\s*Mutex::new',
    "weak-crypto-md5":              r'Md5::new\s*\(\s*\)',
    "weak-random":                  r'rand::random\s*::<',
    "no-constant-time":             r'==\s*password|password\s*==',
    "hardcoded-secret":             r'(password|secret|api_key|token)\s*=\s*"[^"]{4,}"',
    "cmd-exec-config-interpolate":  r'format!\s*\(\s*"[^"]*\{\}[^"]*",\s*\w+\.(get|config|settings)',
    "cmd-exec-command-new-sh":      r'Command::new\s*\(\s*"sh"\s*\)',
    "cmd-exec-arg-user-input":      r'Command::new\s*\([^)]+\)\s*\n[^;]*\.arg\s*\(\s*&?\w+',
    "cmd-exec-format-cmd":          r'format!\s*\(\s*"[^"]*\{\}[^"]*"[^)]*\)\s*;\s*\n[^;]*Command',
    "cmd-exec-config-hashmap":      r'HashMap<String,\s*String>[^;]*;\s*(?!.*validate)',
    "cmd-exec-insert-no-validate":  r'\.insert\s*\(\s*\w+\s*,\s*\w+\s*\)\s*;(?!\s*\n\s*.*validate)',
    "cmd-exec-config-get-cmd":      r'config\.(get|entry)\s*\([^)]+\)[^;]*\n[^;]*Command::new',
    "cmd-exec-shell-metachar":      r'Command::new\s*\(\s*"(sh|bash|cmd|powershell)"\s*\)',
    "cmd-exec-arg-c-flag":          r'\.arg\s*\(\s*"-c"\s*\)',
    "cmd-exec-spawn-format":        r'\.(spawn|output|status)\s*\(\s*\)\s*\n[^;]*format!',
    "forget-memory":                r'std::mem::forget\s*\(',
    "drop-raw":                     r'std::ptr::drop_in_place\s*\(',
    "uninitialized-memory":         r'std::mem::uninitialized\s*\(\s*\)',
    "zeroed-memory":                r'std::mem::zeroed\s*\(\s*\)',
}

SEVERITY = {
    "unsafe-code":          "HIGH",
    "raw-pointer":          "MEDIUM",
    "error-handling":       "LOW",
    "integer-overflow":     "HIGH",
    "ffi-vulnerability":    "CRITICAL",
    "concurrency":          "HIGH",
    "weak-cryptography":    "HIGH",
    "hardcoded-secret":     "CRITICAL",
    "command-injection":    "CRITICAL",
    "input-validation":     "CRITICAL",
    }
