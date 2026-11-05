# patterns/java_patterns.py

PATTERNS = {

    # ─── SQL Injection ────────────────────────────────────────────────────────
    "sql-injection-query":              "sql-injection",
    "sql-injection-execute":            "sql-injection",
    "sql-injection-statement":          "sql-injection",
    "sql-injection-string-format":      "sql-injection",
    "sql-injection-template":           "sql-injection",

    # ─── Command Injection ────────────────────────────────────────────────────
    "command-inject-runtime":           "command-injection",
    "command-inject-processbuilder":    "command-injection",
    "command-inject-groovy":            "command-injection",
    "command-inject-scriptengine":      "command-injection",

    # ─── Insecure Deserialization ─────────────────────────────────────────────
    "insecure-deserialize-object":      "insecure-deserialization",
    "insecure-deserialize-xmldecoder":  "insecure-deserialization",
    "insecure-deserialize-kryo":        "insecure-deserialization",
    "insecure-deserialize-json":        "insecure-deserialization",
    "insecure-deserialize-xstream":     "insecure-deserialization",

    # ─── XXE ──────────────────────────────────────────────────────────────────
    "xxe-documentbuilder":              "xxe",
    "xxe-saxparser":                    "xxe",
    "xxe-xmlreader":                    "xxe",
    "xxe-transformer":                  "xxe",

    # ─── Zip Slip ─────────────────────────────────────────────────────────────
    "zip-slip-zipentry-name":           "zip-slip",
    "zip-slip-new-file":                "zip-slip",
    "zip-slip-no-canonical":            "zip-slip",
    "zip-slip-extract-dir":             "zip-slip",
    "zip-slip-mkdirs":                  "zip-slip",
    "zip-slip-fileoutputstream":        "zip-slip",
    "zip-slip-no-startswith":           "zip-slip",
    "zip-slip-tarentry":                "zip-slip",
    "zip-slip-path-resolve":            "zip-slip",
    "zip-slip-no-normalize":            "zip-slip",

    # ─── Path Traversal ───────────────────────────────────────────────────────
    "path-traversal-file":              "path-traversal",
    "path-traversal-paths":             "path-traversal",
    "path-traversal-resource":          "path-traversal",

    # ─── Weak Cryptography ────────────────────────────────────────────────────
    "weak-crypto-md5":                  "weak-cryptography",
    "weak-crypto-sha1":                 "weak-cryptography",
    "weak-crypto-des":                  "weak-cryptography",
    "weak-crypto-ecb":                  "weak-cryptography",
    "weak-random":                      "weak-cryptography",
    "no-secure-random":                 "weak-cryptography",

    # ─── Authentication Weakness ──────────────────────────────────────────────
    "trust-all-certs":                  "authentication-weakness",
    "no-hostname-verify":               "authentication-weakness",
    "weak-ssl-protocol":                "authentication-weakness",
    "hardcoded-password":               "authentication-weakness",
    "hardcoded-secret":                 "authentication-weakness",
    # Fix 14: five additional hardcoded-password patterns
    "hardcoded-password-field":         "authentication-weakness",
    "hardcoded-password-static":        "authentication-weakness",
    "hardcoded-password-string":        "authentication-weakness",
    "hardcoded-password-property":      "authentication-weakness",
    "hardcoded-password-spring":        "authentication-weakness",

    # ─── Info Disclosure ──────────────────────────────────────────────────────
    "info-disclosure-system-err":       "info-disclosure",
    "info-disclosure-exception-msg":    "info-disclosure",
    "info-disclosure-stack-trace":      "info-disclosure",
    "info-disclosure-log-exception":    "info-disclosure",
    "info-disclosure-return-message":   "info-disclosure",
    "info-disclosure-response-error":   "info-disclosure",
    "info-disclosure-hardcoded-path":   "info-disclosure",
    "info-disclosure-server-info":      "info-disclosure",
    "info-disclosure-sql-error":        "info-disclosure",
    "info-disclosure-debug-output":     "info-disclosure",

    # ─── Network Vulnerability ────────────────────────────────────────────────
    "ssrf-url-open":                    "network-vulnerability",
    "open-redirect":                    "network-vulnerability",
    "cors-wildcard":                    "network-vulnerability",

    # ─── File Operations ──────────────────────────────────────────────────────
    "insecure-tempfile":                "path-traversal",
    "world-readable":                   "path-traversal",
    "insecure-file-upload":             "path-traversal",
}

REGEX = {
    "sql-injection-query":              r'(createQuery|createNativeQuery)\s*\(\s*"[^"]*"\s*\+',
    "sql-injection-execute":            r'executeQuery\s*\(\s*"[^"]*"\s*\+',
    "sql-injection-statement":          r'createStatement\s*\(\s*\)',
    "sql-injection-string-format":      r'(String\.format|MessageFormat\.format)\s*\([^)]*SELECT',
    "sql-injection-template":           r'jdbcTemplate\.(query|update)\s*\(\s*"[^"]*"\s*\+',
    "command-inject-runtime":           r'Runtime\.getRuntime\(\)\.exec\s*\(',
    "command-inject-processbuilder":    r'new\s+ProcessBuilder\s*\(',
    "command-inject-groovy":            r'Eval\.me\s*\(',
    "command-inject-scriptengine":      r'ScriptEngine\s*\w+\s*=',
    "insecure-deserialize-object":      r'ObjectInputStream\s*\w+\s*=',
    "insecure-deserialize-xmldecoder":  r'XMLDecoder\s*\w+\s*=',
    "insecure-deserialize-kryo":        r'kryo\.readObject\s*\(',
    "insecure-deserialize-json":        r'objectMapper\.readValue\s*\([^)]*Object\.class\)',
    "insecure-deserialize-xstream":     r'xstream\.fromXML\s*\(',
    "xxe-documentbuilder":              r'DocumentBuilderFactory\.newInstance\s*\(\s*\)',
    "xxe-saxparser":                    r'SAXParserFactory\.newInstance\s*\(\s*\)',
    "xxe-xmlreader":                    r'XMLReaderFactory\.createXMLReader\s*\(\s*\)',
    "xxe-transformer":                  r'TransformerFactory\.newInstance\s*\(\s*\)',
    "zip-slip-zipentry-name":           r'zipEntry\.getName\s*\(\s*\)',
    "zip-slip-new-file":                r'new\s+File\s*\([^)]*zipEntry\.getName\s*\(\s*\)',
    "zip-slip-no-canonical":            r'new\s+File\s*\([^)]*\)\s*;(?!.*getCanonicalPath)',
    "zip-slip-extract-dir":             r'new\s+File\s*\(\s*\w+\s*,\s*\w+\.getName\s*\(\s*\)\s*\)',
    "zip-slip-mkdirs":                  r'new\s+File\s*\([^)]*getName[^)]*\)[^;]*;\s*\n[^;]*mkdirs',
    "zip-slip-fileoutputstream":        r'new\s+FileOutputStream\s*\(\s*new\s+File\s*\([^)]*getName',
    "zip-slip-no-startswith":           r'ZipEntry\s+\w+[^;]*;\s*(?!.*startsWith)',
    "zip-slip-tarentry":                r'(TarEntry|ArchiveEntry)\.getName\s*\(\s*\)',
    "zip-slip-path-resolve":            r'Paths\.get\s*\([^)]*getNextEntry\s*\(\s*\)',
    "zip-slip-no-normalize":            r'new\s+File\s*\([^)]*\)\s*(?!.*normalize\s*\(\s*\))',
    "path-traversal-file":              r'new\s+File\s*\([^)]*\+[^)]*\)',
    "path-traversal-paths":             r'Paths\.get\s*\([^)]*\+[^)]*\)',
    "path-traversal-resource":          r'getResourceAsStream\s*\(\s*\w+',
    "weak-crypto-md5":                  r'MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)',
    "weak-crypto-sha1":                 r'MessageDigest\.getInstance\s*\(\s*"SHA-1"\s*\)',
    "weak-crypto-des":                  r'Cipher\.getInstance\s*\(\s*"DES',
    "weak-crypto-ecb":                  r'Cipher\.getInstance\s*\(\s*"[^"]*\/ECB\/',
    "weak-random":                      r'new\s+Random\s*\(\s*\)',
    "no-secure-random":                 r'Math\.random\s*\(\s*\)',
    "trust-all-certs":                  r'TrustAllCerts|X509TrustManager',
    "no-hostname-verify":               r'setHostnameVerifier\s*\([^)]*ALLOW_ALL',
    "weak-ssl-protocol":                r'SSLContext\.getInstance\s*\(\s*"SSL[^v"]',
    "hardcoded-password":               r'getConnection\s*\([^)]*"[^"]{4,}"[^)]*"[^"]{4,}"',
    "hardcoded-secret":                 r'(password|secret|apiKey)\s*=\s*"[^"]{4,}"',
    # Fix 14: five expanded hardcoded-password patterns ─────────────────────
    # 1. Private field declaration: private String password = "..."
    "hardcoded-password-field":         r'private\s+String\s+\w*[Pp]assword\w*\s*=\s*"[^"]{4,}"',
    # 2. Final/static constant: static final String PASSWORD = "..."
    "hardcoded-password-static":        r'(final\s+static|static\s+final)\s+String\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*"[^"]{4,}"',
    # 3. Any local/field String assignment with a credential-like name
    "hardcoded-password-string":        r'\bString\s+\w*(password|secret|apiKey|api_key|passwd)\w*\s*=\s*"[^"]{4,}"',
    # 4. Properties.getProperty("key", "hardcoded-default")
    "hardcoded-password-property":      r'getProperty\s*\(\s*"[^"]+"\s*,\s*"[^"]{4,}"\s*\)',
    # 5. Spring @Value with a literal instead of a ${...} placeholder
    "hardcoded-password-spring":        r'@Value\s*\(\s*"(?!\$\{)[^"]{4,}"\s*\)',
    # ─────────────────────────────────────────────────────────────────────────
    "info-disclosure-system-err":       r'System\.(err|out)\.println\s*\([^)]*e\.getMessage\s*\(\s*\)',
    "info-disclosure-exception-msg":    r'(response|res|out)\.(write|print|println)\s*\([^)]*e\.(getMessage|toString|getStackTrace)',
    "info-disclosure-stack-trace":      r'e\.printStackTrace\s*\(\s*\)',
    "info-disclosure-log-exception":    r'(logger|log)\.(error|debug|warn)\s*\([^)]*e\.getMessage',
    "info-disclosure-return-message":   r'return\s+[^;]*(e\.getMessage|e\.toString)\s*\(\s*\)',
    "info-disclosure-response-error":   r'(response|resp)\.getWriter\s*\(\s*\)[^;]*;\s*\n[^;]*e\.getMessage',
    "info-disclosure-hardcoded-path":   r'(EXTRACT_DIR|BASE_DIR|ROOT_DIR)\s*=\s*"[^"]{4,}"',
    "info-disclosure-server-info":      r'(getServerInfo|getServletInfo|getServerName)\s*\(\s*\)',
    "info-disclosure-sql-error":        r'catch\s*\(\s*(SQLException|PDOException)\s*\w+\s*\)[^}]*\.(write|print|send)',
    "info-disclosure-debug-output":     r'System\.out\.println\s*\([^)]*\b(password|secret|token|key|user)\b',
    "ssrf-url-open":                    r'new\s+URL\s*\(\s*\w+\s*\)\.openConnection',
    "open-redirect":                    r'sendRedirect\s*\(\s*request\.getParameter',
    "cors-wildcard":                    r'setHeader\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*"\*"',
    "insecure-tempfile":                r'File\.createTempFile\s*\(',
    "world-readable":                   r'setReadable\s*\(\s*true\s*,\s*false\s*\)',
    "insecure-file-upload":             r'transferTo\s*\(\s*new\s+File',
}

SEVERITY = {
    "sql-injection":            "CRITICAL",
    "command-injection":        "CRITICAL",
    "insecure-deserialization": "CRITICAL",
    "xxe":                      "HIGH",
    "zip-slip":                 "CRITICAL",
    "path-traversal":           "HIGH",
    "weak-cryptography":        "HIGH",
    "authentication-weakness":  "CRITICAL",
    "info-disclosure":          "MEDIUM",
    "network-vulnerability":    "HIGH",
}
