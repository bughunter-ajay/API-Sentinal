import sys, os
sys.path.insert(0, "UltronScan")
from backend.main import (
    generate_dalfox_standalone_report,
    generate_standalone_report,
    generate_commix_standalone_report,
    generate_arjun_standalone_report
)

sample_endpoints = [
    {
        "id": "ep-1",
        "method": "POST",
        "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-component-items/submit?componentId=5246",
        "param_names": ["componentId", "amount", "description"],
        "status": "Clean (0 XSS)"
    },
    {
        "id": "ep-2",
        "method": "GET",
        "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/dashboard?componentId=5246",
        "param_names": ["componentId"],
        "status": "Clean (0 XSS)"
    },
    {
        "id": "ep-3",
        "method": "GET",
        "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/requests?componentId=5246&employeeId=10494",
        "param_names": ["componentId", "employeeId"],
        "status": "Clean (0 XSS)"
    },
    {
        "id": "ep-4",
        "method": "GET",
        "url": "https://0aab00804d80f20808d03c600430038.web-security-academy.net/?search=xss",
        "param_names": ["search"],
        "status": "Vulnerable (1 XSS)"
    }
]

sample_dalfox_findings = [
    {
        "type": "Verified Reflected XSS",
        "severity": "CRITICAL",
        "param": "search",
        "url": "https://0aab00804d80f20808d03c600430038.web-security-academy.net/?search=xss",
        "method": "GET",
        "payload": "https://0aab00804d80f20808d03c600430038.web-security-academy.net/?search=%3Csvg%20onload%3Dalert%281%29%3E",
        "evidence": "DOM verification successful for param search",
        "poc_curl": "curl -i -k 'https://0aab00804d80f20808d03c600430038.web-security-academy.net/?search=%3Csvg%20onload%3Dalert%281%29%3E'"
    }
]

stats = {"scanned_endpoints": 4, "total_findings": 1, "verified_xss": 1, "dom_xss": 0, "stored_xss": 0, "reflected_xss": 1}

# 1. Test Dalfox Report
dfx_html = generate_dalfox_standalone_report("Dalfox Report", "Initial Target", sample_dalfox_findings, stats, sample_endpoints)
assert "2 Target Hosts" in dfx_html, "Dalfox report missing 2 Target Hosts in header"
assert "one-sit.visionwaves.com" in dfx_html, "Dalfox report missing one-sit.visionwaves.com"
assert "web-security-academy.net" in dfx_html, "Dalfox report missing web-security-academy.net"
assert "📋 Audited Endpoints &amp; Scope Surface" in dfx_html or "📋 Audited Endpoints & Scope Surface" in dfx_html, "Dalfox report missing Scope Section"
assert "Passed Clean (0 Vulns)" in dfx_html, "Dalfox report missing clean status in scope table"
assert "Vulnerable (1 Finding)" in dfx_html, "Dalfox report missing vulnerable status in scope table"
print("✅ Test 1: Dalfox Standalone Report verified with multi-host Target Surface & Endpoints Scope table!")

# 2. Test SQLMap Report
sql_html = generate_standalone_report("SQLMap Report", "Target APIs", [], {"scanned_count": 4}, sample_endpoints)
assert "2 Target Hosts" in sql_html, "SQLMap report missing 2 Target Hosts"
assert "📋 Audited Endpoints &amp; Scope Surface" in sql_html or "📋 Audited Endpoints & Scope Surface" in sql_html, "SQLMap report missing Scope Section"
print("✅ Test 2: SQLMap Standalone Report verified with multi-host Target Surface & Endpoints Scope table!")

# 3. Test Commix Report
cmx_html = generate_commix_standalone_report("Commix Report", "Target APIs", [], {"scanned_count": 4}, sample_endpoints)
assert "2 Target Hosts" in cmx_html, "Commix report missing 2 Target Hosts"
assert "📋 Audited Endpoints &amp; Scope Surface" in cmx_html or "📋 Audited Endpoints & Scope Surface" in cmx_html, "Commix report missing Scope Section"
print("✅ Test 3: Commix Standalone Report verified with multi-host Target Surface & Endpoints Scope table!")

# 4. Test Arjun Report
arj_html = generate_arjun_standalone_report("Arjun Report", "Target APIs", [], {"scanned_count": 4}, sample_endpoints)
assert "2 Target Hosts" in arj_html, "Arjun report missing 2 Target Hosts"
assert "📋 Audited Endpoints &amp; Scope Surface" in arj_html or "📋 Audited Endpoints & Scope Surface" in arj_html, "Arjun report missing Scope Section"
print("✅ Test 4: Arjun Standalone Report verified with multi-host Target Surface & Endpoints Scope table!")

print("\n🎉 ALL 4 REPORTS VERIFIED WITH SCOPE LISTING AND MULTI-HOST TARGET SURFACE!")
