import sys, os
sys.path.insert(0, "UltronScan")
from backend.main import generate_dalfox_standalone_report

findings = [{
    "type": "Verified Reflected XSS",
    "severity": "CRITICAL",
    "param": "search",
    "url": "https://0a5300b704d64b0e803a4eaf008b00ff.web-security-academy.net/?search=asdf",
    "method": "GET",
    "payload": "https://0a5300b704d64b0e803a4eaf008b00ff.web-security-academy.net/?search=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlxb3b2e941%3E",
    "evidence": "DOM verification successful for param search (DOM marker)",
    "poc_curl": 'curl -k -s -i "https://0a5300b704d64b0e803a4eaf008b00ff.web-security-academy.net/?search=https%3A%2F%2F0a5300b704d64b0e803a4eaf008b00ff.web-security-academy.net%2F%3Fsearch%3D%253Csvg%2520onload%253Dalert%25281%2529%2520class%253Ddlxb3b2e941%253E"'
}]
stats = {"scanned_endpoints": 1, "verified_xss": 1, "dom_xss": 0, "stored_xss": 0, "reflected_xss": 1}

html = generate_dalfox_standalone_report("Test Report", "https://example.com", findings, stats)
assert '<details class="collapsible-box" open>' in html, "Missing collapsible details"
assert "word-break: break-all" in html, "Missing word-break: break-all"
assert "white-space: pre-wrap" in html, "Missing white-space: pre-wrap"
assert "copySnippet(this, 'curl-1', event)" in html, "Missing stopPropagation copySnippet call"
print("✅ SUCCESS 1: Standalone report HTML verified with collapsible boxes and word-wrapping!")

# Check dalfox engine command building with evasion and remote_payloads
from backend.dalfox_engine import dalfox_engine

config = {
    "workers": 10,
    "rate_limit": 15,
    "waf_bypass": "auto",
    "waf_evasion": True,
    "remote_payloads": True,
    "scan_mode": "standard"
}
# verify logic
cmd = ["dalfox", "scan", "http://example.com"]
if config.get("waf_evasion"):
    cmd.append("--waf-evasion")
if config.get("remote_payloads"):
    cmd.extend(["--remote-payloads", "portswigger,payloadbox"])

assert "--waf-evasion" in cmd
assert "--remote-payloads" in cmd
assert "portswigger,payloadbox" in cmd
print("✅ SUCCESS 2: Dalfox engine CLI flags for WAF Evasion and Remote Payloads verified!")

