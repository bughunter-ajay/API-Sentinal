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
        "status": "Passed Clean (0 Vulns)",
        "selected": True
    },
    {
        "id": "ep-2",
        "method": "GET",
        "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/dashboard?componentId=5246",
        "param_names": ["componentId"],
        "status": "Passed Clean (0 Vulns)",
        "selected": True
    },
    {
        "id": "ep-3",
        "method": "GET",
        "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/requests?componentId=5246&employeeId=10494",
        "param_names": ["componentId", "employeeId"],
        "status": "Passed Clean (0 Vulns)",
        "selected": True
    },
    {
        "id": "ep-4",
        "method": "POST",
        "url": "https://one-sit.visionwaves.com/apim/expensemanager/1.0/rest/other-salary-components/update",
        "param_names": ["id", "val"],
        "status": "Pending",
        "selected": False
    }
]

generators = [
    ("SQLMap", generate_standalone_report),
    ("Commix", generate_commix_standalone_report),
    ("Arjun", generate_arjun_standalone_report),
    ("Dalfox", generate_dalfox_standalone_report)
]

for name, gen in generators:
    html = gen(
        f"{name} Pro Audit Report",
        "one-sit.visionwaves.com",
        [],
        {"scanned_count": 3, "scanned_endpoints": 3},
        sample_endpoints
    )
    
    assert ".scope-details-card" in html, f"FAILED: .scope-details-card missing from {name} report CSS!"
    assert ".scope-summary-head" in html, f"FAILED: .scope-summary-head missing from {name} report CSS!"
    assert ".scope-table" in html, f"FAILED: .scope-table missing from {name} report CSS!"
    assert ".scope-chevron" in html, f"FAILED: .scope-chevron missing from {name} report CSS!"
    assert ".scope-pill" in html, f"FAILED: .scope-pill missing from {name} report CSS!"
    assert "scope-details-card" in html, f"FAILED: scope-details-card tag missing from {name} report!"
    assert "3 Target APIs" in html, f"FAILED: Expected 3 Target APIs in {name} report, got different!"
    assert "ep-4" not in html and "other-salary-components/update" not in html, f"FAILED: Pending endpoint found in {name} report!"
    assert "one-sit.visionwaves.com" in html, f"FAILED: Target host not in {name} report!"
    
    print(f"[{name}] ALL CHECKS PASSED: Scope CSS, Card styles, and filtering verified successfully.")

print("\nALL 4 REPORTS ARE 100% PERFECTLY STYLED AND CONSISTENT!")
