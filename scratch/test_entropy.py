import sys, math, re
from collections import Counter

_SECRET_PLACEHOLDERS = {
    "", "null", "undefined", "none", "nil", "true", "false", "n/a", "na",
    "changeme", "changeit", "password", "secret", "your_api_key", "your-api-key",
    "xxx", "xxxx", "xxxxx", "todo", "tbd", "test", "testing", "demo", "sample",
    "dummy", "fake", "example", "placeholder", "insert_key_here", "redacted",
    "0123456789abcdef", "abcdef0123456789", "1234567890123456", "abcdefghijklmnop",
    "0000000000000000", "ffffffffffffffff", "aaaaaaaaaaaaaaaa",
}

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())

def is_high_entropy_secret(s: str) -> bool:
    if not s or len(s) < 20 or len(s) > 120:
        return False
    low = s.lower().strip("'\"")
    if low in _SECRET_PLACEHOLDERS:
        return False
    if re.fullmatch(r"(.)\1{7,}", low):
        return False
    # If standard hex
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        # Must have both digits and hex letters
        if not (re.search(r"\d", s) and re.search(r"[a-fA-F]", s)):
            return False
        return _shannon_entropy(s.lower()) >= 3.2

    # Base64 / Alphanumeric token
    if re.fullmatch(r"[0-9a-zA-Z+/=_\-]+", s):
        char_types = sum([
            bool(re.search(r"[A-Z]", s)),
            bool(re.search(r"[a-z]", s)),
            bool(re.search(r"\d", s)),
        ])
        if char_types < 2:
            return False
        # Avoid common snake_case or kebab-case English sentences
        if re.fullmatch(r"[a-z0-9_]+", s) or re.fullmatch(r"[a-z0-9\-]+", s):
            return False
        return _shannon_entropy(s) >= 3.8

    return False

test_cases = [
    ("d41d8cd98f00b204e9800998ecf8427e", True),          # 32-char hex secret (e.g. MD5/AES key)
    ("11111111111111111111111111111111", False),         # repeated low entropy
    ("abcdef0123456789abcdef0123456789", False),         # in placeholders
    ("K9xL2vP5mQ8zR1wT4yU7aB3cZ8jK1mL9", True),          # 32-char high entropy base64 key
    ("application_json_utf8_charset_support", False),    # normal English words
    ("user_profile_settings_controller", False),         # snake_case identifier
    ("Content-Type: application/json", False),           # header
]

for val, expected in test_cases:
    res = is_high_entropy_secret(val)
    print(f"Val: {val[:25]}... -> High?: {res} (expected: {expected}) -> {'PASS' if res == expected else 'FAIL'}")
