import re

# PII detection patterns
PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "phone_fr": re.compile(r"(?:\+33|0)[1-9](?:[\s.-]?\d{2}){4}"),
    "phone_intl": re.compile(r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "ssn_fr": re.compile(r"\b[12]\d{2}(0[1-9]|1[0-2])\d{5}\d{3}\b"),  # Numéro sécu français
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "api_key": re.compile(r"(?i)(api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{16,})"),
    "stack_trace": re.compile(r"(Traceback \(most recent call last\)|at .+\(.+\.java:\d+\)|System\.Exception|NullPointerException)"),
    "internal_path": re.compile(r"(/var/www|/home/\w+|C:\\Users|/etc/|/usr/local)"),
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — enforces HTTPS",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-Frame-Options": "Prevents clickjacking",
    "Content-Security-Policy": "Prevents XSS and data injection",
    "X-XSS-Protection": "Legacy XSS filter (still useful)",
    "Cache-Control": "Controls response caching",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features",
}

INJECTION_PAYLOADS = {
    "sql": ["' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT null,null--", "' OR 1=1--"],
    "nosql": ['{"$gt": ""}', '{"$where": "sleep(1000)"}', '{"$regex": ".*"}'],
    "xss": ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)"],
    "path_traversal": ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "%2e%2e%2f%2e%2e%2f"],
}
