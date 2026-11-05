# patterns/javascript_patterns.py

PATTERNS = {

    # ─── XSS ──────────────────────────────────────────────────────────────────
    "xss-inner-html":               "xss",
    "xss-outer-html":               "xss",
    "xss-document-write":           "xss",
    "xss-insert-adjacent":          "xss",
    "xss-jquery-html":              "xss",
    "xss-dangerously-set":          "xss",

    # ─── Injection ────────────────────────────────────────────────────────────
    "eval-injection":               "injection",
    "function-injection":           "injection",
    "settimeout-injection":         "injection",
    "setinterval-injection":        "injection",
    "sql-injection-concat":         "injection",
    "sql-injection-template":       "injection",
    "command-inject-exec":          "injection",
    "command-inject-spawn":         "injection",
    "nosql-injection":              "injection",
    "nosql-inject-req-body":        "injection",
    "nosql-inject-ne-operator":     "injection",
    "nosql-inject-gt-operator":     "injection",
    "nosql-inject-where-operator":  "injection",
    "nosql-inject-regex-operator":  "injection",
    "nosql-inject-or-operator":     "injection",
    "nosql-inject-direct-query":    "injection",
    "nosql-inject-user-filter":     "injection",
    "nosql-inject-aggregate":       "injection",
    "nosql-inject-no-sanitize":     "injection",

    # ─── Prototype Pollution ──────────────────────────────────────────────────
    "prototype-pollution-merge":    "prototype-pollution",
    "prototype-pollution-set":      "prototype-pollution",
    "prototype-pollution-proto":    "prototype-pollution",

    # ─── Weak Cryptography ────────────────────────────────────────────────────
    "weak-crypto-md5":              "weak-cryptography",
    "weak-crypto-sha1":             "weak-cryptography",
    "weak-random":                  "weak-cryptography",

    # ─── Hardcoded Secret ─────────────────────────────────────────────────────
    "hardcoded-secret":             "hardcoded-secret",
    "hardcoded-jwt-secret":         "hardcoded-secret",
    "sensitive-hardcoded-token":    "hardcoded-secret",
    "sensitive-hardcoded-password": "hardcoded-secret",
    "sensitive-api-key-src":        "hardcoded-secret",

    # ─── Path Traversal ───────────────────────────────────────────────────────
    "path-traversal-join":          "path-traversal",
    "path-traversal-resolve":       "path-traversal",
    "path-traversal-readfile":      "path-traversal",

    # ─── Authentication Weakness ──────────────────────────────────────────────
    "no-rate-limit":                "authentication-weakness",
    "weak-jwt":                     "authentication-weakness",
    "debug-mode":                   "authentication-weakness",
    "cors-wildcard":                "authentication-weakness",

    # ─── Sensitive Data Exposure ──────────────────────────────────────────────
    "sensitive-response-token":     "sensitive-data-exposure",
    "sensitive-console-log":        "sensitive-data-exposure",
    "sensitive-jwt-exposed":        "sensitive-data-exposure",
    "sensitive-env-response":       "sensitive-data-exposure",
    "sensitive-error-details":      "sensitive-data-exposure",
    "sensitive-user-data-log":      "sensitive-data-exposure",
    "sensitive-cookie-no-httponly": "sensitive-data-exposure",

    # ─── Network Vulnerability ────────────────────────────────────────────────
    "ssrf-axios":                   "network-vulnerability",
    "ssrf-fetch":                   "network-vulnerability",
    "open-redirect":                "network-vulnerability",
    "xxe-parse":                    "network-vulnerability",

    # ─── File Operations ──────────────────────────────────────────────────────
    "insecure-file-upload":         "path-traversal",
    "world-readable-file":          "path-traversal",
    "arbitrary-file-write":         "path-traversal",
}

REGEX = {
    "xss-inner-html":               r'innerHTML\s*=\s*',
    "xss-outer-html":               r'outerHTML\s*=\s*',
    "xss-document-write":           r'document\.write\s*\(',
    "xss-insert-adjacent":          r'insertAdjacentHTML\s*\(',
    "xss-jquery-html":              r'\$\([^)]+\)\.html\s*\(\s*\w+',
    "xss-dangerously-set":          r'dangerouslySetInnerHTML',
    "eval-injection":               r'\beval\s*\(',
    "function-injection":           r'new\s+Function\s*\(',
    "settimeout-injection":         r'setTimeout\s*\(\s*\w+\s*,',
    "setinterval-injection":        r'setInterval\s*\(\s*\w+\s*,',
    "sql-injection-concat":         r'(query|execute)\s*\(\s*["`\'].*\+\s*\w+',
    "sql-injection-template":       r'(query|execute)\s*\(\s*`[^`]*\$\{',
    "command-inject-exec":          r'exec\s*\(\s*`[^`]*\$\{',
    "command-inject-spawn":         r'spawn\s*\(\s*\w+\s*,\s*\[',
    "nosql-injection":              r'\$where\s*:\s*\w+',
    "nosql-inject-req-body":        r'(findOne|find|findById|update|delete)\s*\(\s*\{[^}]*req\.(body|query|params)',
    "nosql-inject-ne-operator":     r'\{\s*["\']?\$ne["\']?\s*:',
    "nosql-inject-gt-operator":     r'\{\s*["\']?\$gt["\']?\s*:',
    "nosql-inject-where-operator":  r'\{\s*["\']?\$where["\']?\s*:',
    "nosql-inject-regex-operator":  r'\{\s*["\']?\$regex["\']?\s*:.*req\.',
    "nosql-inject-or-operator":     r'\{\s*["\']?\$or["\']?\s*:\s*\[.*req\.',
    "nosql-inject-direct-query":    r'collection\s*\(\s*["\'\w]+\s*\)\s*\.\s*(find|findOne|update|delete)\s*\(\s*req\.',
    "nosql-inject-user-filter":     r'(filter|query|criteria)\s*=\s*\{\s*\w+\s*:\s*req\.(body|query|params)\.\w+\s*\}',
    "nosql-inject-aggregate":       r'aggregate\s*\(\s*\[.*req\.(body|query|params)',
    "nosql-inject-no-sanitize":     r'(findOne|find)\s*\(\s*\{\s*\w+\s*:\s*req\.body\.\w+\s*\}\s*\)',
    "prototype-pollution-merge":    r'(merge|extend|assign)\s*\(\s*\w+\s*,\s*\w+',
    "prototype-pollution-set":      r'\w+\[(\w+|\[)[^\]]*\]\s*=\s*',
    "prototype-pollution-proto":    r'__proto__',
    "weak-crypto-md5":              r'(md5|MD5)\s*\(',
    "weak-crypto-sha1":             r'(sha1|SHA1)\s*\(',
    "weak-random":                  r'Math\.random\s*\(\s*\)',
    "hardcoded-secret":             r'(password|secret|apiKey|api_key|token)\s*=\s*["\'][^"\']{4,}["\']',
    "hardcoded-jwt-secret":         r'jwt\.sign\s*\([^)]*["\'][^"\']{4,}["\']',
    "sensitive-hardcoded-token":    r'(secret|token|api_key|apikey|password|auth)\s*[:=]\s*["\'][^"\']{6,}["\']',
    "sensitive-hardcoded-password": r'(password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']',
    "sensitive-api-key-src":        r'(API_KEY|SECRET_KEY|PRIVATE_KEY)\s*=\s*["\'][^"\']{6,}["\']',
    "path-traversal-join":          r'path\.join\s*\([^)]*req\.',
    "path-traversal-resolve":       r'path\.resolve\s*\([^)]*req\.',
    "path-traversal-readfile":      r'fs\.readFile\s*\(\s*\w+',
    "no-rate-limit":                r'app\.(get|post)\s*\([^)]*login[^)]*\)',
    "weak-jwt":                     r'jwt\.verify\s*\([^)]*algorithms\s*:\s*\[\s*["\']none["\']',
    "debug-mode":                   r'(debug|DEBUG)\s*:\s*true',
    "cors-wildcard":                r'Access-Control-Allow-Origin.*\*',
    "sensitive-response-token":     r'res\.(json|send)\s*\([^)]*\b(secret|token|password|key|auth)\b',
    "sensitive-console-log":        r'console\.(log|error|warn)\s*\([^)]*\b(password|secret|token|key)\b',
    "sensitive-jwt-exposed":        r'res\.(json|send)\s*\([^)]*jwt\.(sign|token)',
    "sensitive-env-response":       r'res\.(json|send)\s*\([^)]*process\.env\.\w+',
    "sensitive-error-details":      r'res\.(status|send|json)\s*\([^)]*error\.(message|stack)',
    "sensitive-user-data-log":      r'console\.log\s*\([^)]*\b(user|account|profile)\b',
    "sensitive-cookie-no-httponly": r'res\.cookie\s*\([^)]*(?!.*httpOnly\s*:\s*true)',
    "ssrf-axios":                   r'axios\.(get|post)\s*\(\s*\w+',
    "ssrf-fetch":                   r'fetch\s*\(\s*\w+',
    "open-redirect":                r'res\.redirect\s*\(\s*req\.',
    "xxe-parse":                    r'DOMParser\s*\(\s*\)',
    "insecure-file-upload":         r'multer\s*\(\s*\{[^}]*dest',
    "world-readable-file":          r'fs\.chmod\s*\([^)]*0o?777[^)]*\)',
    "arbitrary-file-write":         r'fs\.writeFile\s*\(\s*\w+',
}

SEVERITY = {
    "xss":                      "HIGH",
    "injection":                "CRITICAL",
    "prototype-pollution":      "HIGH",
    "weak-cryptography":        "HIGH",
    "hardcoded-secret":         "CRITICAL",
    "path-traversal":           "HIGH",
    "authentication-weakness":  "MEDIUM",
    "sensitive-data-exposure":  "HIGH",
    "network-vulnerability":    "HIGH",
}
