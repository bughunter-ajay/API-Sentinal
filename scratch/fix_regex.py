with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "payload_match = re.search" in line:
        new_lines.append('                            payload_match = re.search(r"payload=([^\\s,)]+)", clean_msg) or re.search(r"""payload\\s*[:=]\\s*[\'"]?([^\'"]+)[\'"]?""", clean_msg)\n')
    else:
        new_lines.append(line)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print("Regex fixed successfully!")
