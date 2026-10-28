import json, re

raw_arg = 'policy="{\\"id\\":127,\\"annualResigningEnabled\\":true,\\"resigningDate\\":\\"2026-10-08\\",\\"policyCode\\":\\"COC-480\\",\\"status\\":\\"DRAFT\\",\\"policySummary\\":\\"Test profile sum\\",\\"policyDocument\\":null}"'

s = str(raw_arg or "")
eq = s.find("=")
key = s[:eq].strip()
rest = s[eq + 1:]

val = rest.strip()
if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
    try:
        unquoted = json.loads(val)
        if isinstance(unquoted, (str, dict, list)):
            val = unquoted if isinstance(unquoted, str) else json.dumps(unquoted)
    except Exception:
        inner = val[1:-1]
        if r'\"' in inner:
            val = inner.replace(r'\"', '"')
        else:
            val = inner

print("Cleaned val:")
print(val)
print("Is valid JSON object?", isinstance(json.loads(val), dict))
