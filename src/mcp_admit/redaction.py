import re

SECRET_VALUE_RE = re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*([^\s,;]+)")

def redact_text(value: str) -> str:
    def _sub(m: re.Match[str]) -> str:
        return f"{m.group(1)}=[REDACTED]"
    return SECRET_VALUE_RE.sub(_sub, value)

def redact_secret_value(value: str) -> str:
    if len(value) <= 4:
        return "[REDACTED]"
    return value[:2] + "***" + value[-2:]
