import sys, os
sys.path.insert(0, "UltronScan")
from backend.main import (
    generate_dalfox_standalone_report,
    generate_standalone_report,
    generate_commix_standalone_report,
    generate_arjun_standalone_report
)

nine_endpoints = [
    # 5 Scanned endpoints (1 vulnerable from portswigger, 4 clean from visionwaves)
    {"id": "ep-1", "method": "GET", "url": "https://0a8000c803698c3280a5176c00ee00cc.web-security-academy.net/?search=xss", "param_names": ["search"], "status": "Vulnerable (1 XSS)", "selected": True},
    {"id": "ep-2", "method": "POST", "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-component-items/submit?componentId=5246", "param_names": ["componentId", "amount"], "status": "Clean (0 XSS)", "selected": True},
    {"id": "ep-3", "method": "GET", "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/dashboard?componentId=5246", "param_names": ["componentId"], "status": "Clean (0 XSS)", "selected": True},
    {"id": "ep-4", "method": "GET", "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/requests?componentId=5246&employeeId=10494", "param_names": ["componentId", "employeeId"], "status": "Clean (0 XSS)", "selected": True},
    {"id": "ep-5", "method": "GET", "url": "https://one-sit.visionwaves.com/apim/base/1.0/base/util/rest/notifications/counts", "param_names": [], "status": "Clean (0 XSS)", "selected": True},
    
    # 4 UNCHECKED / PENDING endpoints
    {"id": "ep-6", "method": "GET", "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/6117", "param_names": [], "status": "Pending", "selected": False},
    {"id": "ep-7", "method": "GET", "url": "https://one-sit.visionwaves.com/apim/fb/1.0/rest/attachments/resources/01a17c1b-4ce9-701b-bb7d-812f5b5ab551", "param_names": [], "status": "Pending", "selected": False},
    {"id": "ep-8", "method": "GET", "url": "https://one-sit.visionwaves.com/apim/fb/1.0/rest/attachments/resources/download/01a17c1b-4ce9-701b-bb7d-812f5b5ab551", "param_names": [], "status": "Pending", "selected": False},
    {"id": "ep-9", "method": "PATCH", "url": "https://one-sit.visionwaves.com/apim/fb/1.0/rest/attachments/resources/update-mappings", "param_names": ["documentIds"], "status": "Pending", "selected": False}
]

findings = [
    {
        "type": "Verified Reflected XSS",
        "severity": "CRITICAL",
        "param": "search",
        "url": "https://0a8000c803698c3280a5176c00ee00cc.web-security-academy.net/?search=xss",
        "method": "GET",
        "payload": "<svg onload=alert(1)>",
        "evidence": "DOM verification",
        "poc_curl": "curl '...'"
    }
]

stats = {"scanned_endpoints": 5, "total_findings": 1, "verified_xss": 1, "dom_xss": 0, "stored_xss": 0, "reflected_xss": 1}

# 1. Dalfox
html = generate_dalfox_standalone_report("Dalfox Report", "Initial Target", findings, stats, nine_endpoints)
assert "2 Target Hosts" in html, "Target Surface must be '2 Target Hosts'"
assert "2 Target Hosts (" not in html, "Host listing in parentheses should NOT be present in header"
assert "5 Target APIs" in html, "Scope table badge must say '5 Target APIs' (NOT 9!)"
assert "other-salary-components/6117" not in html, "Pending ep-6 must NOT be in report"
assert "attachments/resources/update-mappings" not in html, "Pending ep-9 must NOT be in report"
print("✅ DALFOX: Short '2 Target Hosts' header & 5 audited endpoints verified (Pending endpoints excluded)!")

# 2. SQLMap
html_sql = generate_standalone_report("SQLMap Report", "Initial Target", [], {"scanned_count": 5}, nine_endpoints)
assert "2 Target Hosts" in html_sql, "SQLMap Target Surface must be '2 Target Hosts'"
assert "2 Target Hosts (" not in html_sql, "SQLMap Host listing in parentheses should NOT be present"
assert "5 Target APIs" in html_sql, "SQLMap Scope table badge must say '5 Target APIs'"
assert "other-salary-components/6117" not in html_sql, "Pending ep-6 must NOT be in SQLMap report"
print("✅ SQLMAP: Short '2 Target Hosts' header & 5 audited endpoints verified!")

# 3. Commix
html_cmx = generate_commix_standalone_report("Commix Report", "Initial Target", [], {"scanned_count": 5}, nine_endpoints)
assert "2 Target Hosts" in html_cmx, "Commix Target Surface must be '2 Target Hosts'"
assert "2 Target Hosts (" not in html_cmx, "Commix Host listing in parentheses should NOT be present"
assert "5 Target APIs" in html_cmx, "Commix Scope table badge must say '5 Target APIs'"
assert "other-salary-components/6117" not in html_cmx, "Pending ep-6 must NOT be in Commix report"
print("✅ COMMIX: Short '2 Target Hosts' header & 5 audited endpoints verified!")

# 4. Arjun
html_arj = generate_arjun_standalone_report("Arjun Report", "Initial Target", [], {"scanned_count": 5}, nine_endpoints)
assert "2 Target Hosts" in html_arj, "Arjun Target Surface must be '2 Target Hosts'"
assert "2 Target Hosts (" not in html_arj, "Arjun Host listing in parentheses should NOT be present"
assert "5 Target APIs" in html_arj, "Arjun Scope table badge must say '5 Target APIs'"
assert "other-salary-components/6117" not in html_arj, "Pending ep-6 must NOT be in Arjun report"
print("✅ ARJUN: Short '2 Target Hosts' header & 5 audited endpoints verified!")

print("\n🎉 ALL CHECKS PASSED FLAWLESSLY ACROSS ALL 4 APPS!")
