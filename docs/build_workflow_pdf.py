#!/usr/bin/env python3
"""API Sentinel — polished Apps Workflow PDF (content + design)."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, KeepTogether,
    ListFlowable, ListItem, HRFlowable, Table, TableStyle, Flowable,
)

ROOT = Path(__file__).resolve().parents[1]
SHOT_DIR = ROOT / "docs" / "workflow_screenshots"
PDF_PATH = ROOT / "docs" / "API_Sentinel_Apps_Workflow.pdf"
UI_URL = "http://127.0.0.1:8760/index.html"

# Brand palette (flat, no purple/glow)
C_INK = colors.HexColor("#0f172a")
C_MUTED = colors.HexColor("#64748b")
C_BODY = colors.HexColor("#1e293b")
C_LINE = colors.HexColor("#e2e8f0")
C_BG = colors.HexColor("#f8fafc")
C_ACCENT = colors.HexColor("#0f766e")       # teal
C_ACCENT_SOFT = colors.HexColor("#ccfbf1")
C_WARN_SOFT = colors.HexColor("#fff7ed")
C_WARN = colors.HexColor("#c2410c")
C_BLUE_SOFT = colors.HexColor("#eff6ff")
C_BLUE = colors.HexColor("#1d4ed8")
C_WHITE = colors.white

MODULES = [
    {
        "id": "av",
        "name": "API Validator Pro",
        "tagline": "Live capture + parameter fuzzing",
        "use": (
            "Use when you need to discover real APIs from a running web/mobile flow and "
            "check whether parameters accept invalid, boundary, or type-wrong values."
        ),
        "owasp": "API4:2023 Unrestricted Resource Consumption · API8:2023 Security Misconfiguration · input-validation / injection surface",
        "features": [
            "Live capture via mitmproxy + system proxy",
            "HAR / cURL import",
            "Auto param detection (body + query) with types",
            "Positive / negative datasets + unique formats",
            "Results by HTTP status · CSV/HTML export",
        ],
        "keys": [
            "Best starting point for unknown APIs — capture first, then test.",
            "Prefer one high-value API + key params over “select all”.",
            "POS ≈ expected 2xx; NEG ≈ expected 4xx — APIs that return 200 on bad input still look like FAIL.",
        ],
        "steps": [
            "Open API Validator Pro from the top tool bar.",
            "Click Start Capture, then use the target app normally in the browser.",
            "When needed APIs appear, Stop Capture (or keep capturing).",
            "Select request(s) — or Import HAR / paste cURL.",
            "Click Analyze Selected API → review detected params and types.",
            "Tick params to test; set unique formats / custom cases if needed.",
            "Click Run Tests → open Results and review Pass / Fail / status.",
            "Export CSV or HTML report.",
        ],
    },
    {
        "id": "har",
        "name": "Auth Validator Pro",
        "tagline": "Valid vs invalid vs missing token replay",
        "use": (
            "Use to verify APIs actually enforce authentication — replay the same calls "
            "with a good token, a bad/expired token, or no Authorization header."
        ),
        "owasp": "API2:2023 Broken Authentication · API5:2023 Broken Function Level Authorization",
        "features": [
            "Capture / HAR / cURL intake",
            "Modes: Authorized · Unauthorized · No auth",
            "Batch replay with live progress",
            "Status summary (2xx / 4xx / 5xx / errors)",
            "CSV / HTML export",
        ],
        "keys": [
            "Unauthorized (or No auth) + HTTP 2xx on a protected API = high-signal finding.",
            "Use the Results filters to isolate 2xx under unauth modes.",
            "Paste Bearer token without the word “Bearer” if the UI adds it.",
        ],
        "steps": [
            "Open Auth Validator Pro.",
            "Capture traffic or Import HAR / cURL; select APIs.",
            "Click Next → Configure Token.",
            "Pick mode: Authorized / Unauthorized / No auth.",
            "Paste the required token(s).",
            "Click Run Tests; watch the summary cards.",
            "Filter for suspicious 2xx on unauth runs.",
            "Export CSV / HTML.",
        ],
    },
    {
        "id": "apisphere",
        "name": "APISphere",
        "tagline": "Manual API client (Postman-style)",
        "use": (
            "Use for manual verification, crafting requests, collections, and inspecting "
            "responses (JSON, images, PDF preview) after an automated tool finds a lead."
        ),
        "owasp": "Supporting / manual verification tool — not an automated OWASP scanner",
        "features": [
            "Method + URL with Params sync",
            "Headers · Auth · Body · Scripts tabs",
            "Collections & environment variables",
            "Response Preview (PDF / image)",
            "Codegen / collection export",
        ],
        "keys": [
            "Ideal follow-up after API Scan / IDOR / Auth Validator findings.",
            "Query string stays editable in URL and Params (no silent strip).",
            "Use Scripts for token extract / assert patterns.",
        ],
        "steps": [
            "Open APISphere.",
            "Set HTTP method and full URL (including ?query if any).",
            "Fill Headers, Auth, Body, or Params.",
            "Optional: save to Collection; set folder/env variables; add Scripts.",
            "Click Send.",
            "Inspect Status, Headers, Body, and Preview.",
            "Export / codegen as needed.",
        ],
    },
    {
        "id": "mt",
        "name": "Method Tampering",
        "tagline": "Alternate HTTP verbs on the same endpoint",
        "use": (
            "Use when an API is locked to one method (e.g. POST only) and you want to see "
            "if GET/PUT/DELETE/PATCH still work without proper authorization."
        ),
        "owasp": "API5:2023 Broken Function Level Authorization · HTTP verb tampering",
        "features": [
            "HAR / OpenAPI / AV Capture import",
            "Selectable alternate methods",
            "Side-by-side original vs tampered results",
            "Export support",
        ],
        "keys": [
            "Unexpected 2xx on a forbidden method is the finding.",
            "OpenAPI import helps when you have a catalog but no traffic yet.",
            "Compare body/status against the original method baseline.",
        ],
        "steps": [
            "Open Method Tampering.",
            "Import HAR, OpenAPI/Swagger, or load From Capture.",
            "Select endpoints to test.",
            "Choose which alternate methods to fire.",
            "Run the scan.",
            "Review methods that unexpectedly succeed (2xx).",
            "Export results.",
        ],
    },
    {
        "id": "sd",
        "name": "Soft Delete",
        "tagline": "Delete then re-read resource checks",
        "use": (
            "Use on delete/archive flows to check whether “deleted” objects remain "
            "readable, listed, or restorable via ID."
        ),
        "owasp": "API1:2023 BOLA · API3:2023 Excessive Data Exposure · soft-delete / inventory gaps",
        "features": [
            "HAR / capture import",
            "Delete + follow-up read/list sequencing",
            "Status / body comparison after delete",
            "Export findings",
        ],
        "keys": [
            "Map both the DELETE (or soft-delete) call and a GET-by-id / list call.",
            "200 + data after delete = soft-delete / authorization issue.",
            "Confirm with the same auth context the app uses in production.",
        ],
        "steps": [
            "Open Soft Delete.",
            "Import HAR or load from Capture (delete + get/list APIs).",
            "Identify delete request and follow-up read/list requests.",
            "Run the soft-delete sequence.",
            "Check whether deleted IDs still return data (2xx).",
            "Export findings.",
        ],
    },
    {
        "id": "idor",
        "name": "IDOR Tester",
        "tagline": "Cross-user object ID swap",
        "use": (
            "Use when APIs take resource IDs (path/query/body) and you have two user "
            "contexts — swap IDs/tokens to detect Broken Object Level Authorization."
        ),
        "owasp": "API1:2023 Broken Object Level Authorization (BOLA / IDOR)",
        "features": [
            "HAR / cURL / tool handoff",
            "User A vs User B tokens",
            "ID swap in path, query, and body",
            "Highlighted cross-access hits",
            "CSV / HTML export",
        ],
        "keys": [
            "Need two real accounts (or tokens) for meaningful tests.",
            "User A token + User B object ID returning B’s data = classic IDOR.",
            "Focus on /users/{id}, /orders/{id}, account, document IDs — not static catalog IDs.",
        ],
        "steps": [
            "Open IDOR Tester.",
            "Import HAR / cURL or receive handoff from another tool.",
            "Select requests that contain resource IDs.",
            "Paste User A and User B tokens; set IDs to swap.",
            "Run IDOR tests.",
            "Review cross-user data access cases.",
            "Export the report.",
        ],
    },
    {
        "id": "pt",
        "name": "Params Tamper",
        "tagline": "Targeted parameter mutation",
        "use": (
            "Use for deep testing of selected parameters with attack/edge datasets when "
            "you already know which fields matter."
        ),
        "owasp": "API4:2023 · injection / mass-assignment style abuse · input validation",
        "features": [
            "Capture / HAR / cURL load",
            "Param detection + multi-select",
            "Attack / edge datasets + custom values",
            "Response diff oriented results",
            "CSV / HTML export",
        ],
        "keys": [
            "Narrower than API Validator — pick fewer params, richer payloads.",
            "Watch for 500s, stack traces, or unexpected 2xx on hostile values.",
            "Good bridge before launching full API Scan on the same request.",
        ],
        "steps": [
            "Open Params Tamper.",
            "Load a request from Capture, HAR, or cURL.",
            "Detect parameters; select which to mutate.",
            "Choose dataset / add custom values.",
            "Run tamper tests.",
            "Compare responses and export.",
        ],
    },
    {
        "id": "oos",
        "name": "Swagger Scan",
        "tagline": "Static OpenAPI / Swagger audit",
        "use": (
            "Use when you have an OpenAPI/Swagger file and want a fast inventory of "
            "unsecured operations, dangerous-by-name endpoints, and schema/security leads — "
            "before live testing."
        ),
        "owasp": "API8:2023 Misconfiguration · API9:2023 Improper Inventory · API3/API6 schema leads · auth gaps in the spec",
        "features": [
            "JSON / YAML upload (OAS2 + OAS3)",
            "Unsecured · Dangerous · Sensitive · Mass-assign · Refs · Secrets…",
            "Strict unsecured (OOScope parity) toggle",
            "Optional live probe (safe methods)",
            "Health score · CSV / HTML export",
        ],
        "keys": [
            "Strict unsecured ON = OOScope-style list (no public allowlist).",
            "Findings are from the document — confirm sensitive ones with live tools.",
            "Live probe needs Base URL; mutating methods use OPTIONS only.",
        ],
        "steps": [
            "Open Swagger Scan.",
            "Upload OpenAPI .json / .yaml / .yml.",
            "Leave Strict unsecured ON for OOScope parity (or OFF to allowlist health/login/docs).",
            "Optional: enable Live probe + Base URL + auth.",
            "Click Start Scan.",
            "Walk result sections (Unsecured, Dangerous, Sensitive, …).",
            "Export CSV / HTML.",
        ],
    },
    {
        "id": "rsql",
        "name": "RSQL Tester",
        "tagline": "RSQL / FIQL filter injection",
        "use": (
            "Use on search/list APIs that accept RSQL or FIQL-style filter query parameters "
            "to probe injection and filter bypass."
        ),
        "owasp": "Injection via query filters · excessive data exposure / resource abuse",
        "features": [
            "HAR / AV Capture import",
            "RSQL-oriented payload set",
            "Param targeting for filter fields",
            "Export results",
        ],
        "keys": [
            "Look for query params like filter, search, query, rsql, q.",
            "Unexpected wide result sets or 500s after payloads are leads.",
            "Confirm sensitive data leakage manually in APISphere.",
        ],
        "steps": [
            "Open RSQL Tester.",
            "Import HAR or AV Capture; select filter-style APIs.",
            "Confirm / select the filter parameter(s).",
            "Run RSQL payloads.",
            "Review anomalous 2xx / errors / oversized responses.",
            "Export results.",
        ],
    },
    {
        "id": "apiscan",
        "name": "API Scan",
        "tagline": "Active multi-module vulnerability scan",
        "use": (
            "Use for broad active testing of one or more real requests — SQLi, XSS, SSRF, "
            "JWT, IDOR heuristics, SSTI, and more — with live probe streaming."
        ),
        "owasp": "OWASP API Top 10–aligned active probes (module-dependent: API1–API8 style vectors)",
        "features": [
            "Capture / HAR / Parse cURL intake",
            "Module / profile selection",
            "Live probes + issues stream",
            "Auth pause / resume / skip on 401–403 streaks",
            "Stop · CSV / HTML export",
        ],
        "keys": [
            "Heaviest tool — start with a few high-value APIs, not the whole HAR.",
            "If paused for auth, paste a fresh token or Skip.",
            "Treat CRITICAL/HIGH as leads; confirm in APISphere before reporting.",
        ],
        "steps": [
            "Open API Scan.",
            "Add targets (Capture handoff, HAR, or Parse cURL).",
            "Select modules / profile; keep threads moderate.",
            "Click Start Scan.",
            "If Auth pause appears → Update token or Skip.",
            "Watch live probes/issues; Stop if needed.",
            "Open Results → export CSV / HTML.",
        ],
    },
    {
        "id": "upload",
        "name": "File Upload",
        "tagline": "Malicious & edge-case upload suite",
        "use": (
            "Use against multipart upload APIs to test type checks, content sniffing, "
            "extension tricks, and document-specific attacks (e.g. Excel/OOXML)."
        ),
        "owasp": "API8:2023 Misconfiguration · unrestricted / weakly validated file upload",
        "features": [
            "cURL / HAR / Capture import",
            "Auto file-field + profile detection",
            "Polyglot / MIME / extension / path payloads",
            "Verdicts: Accepted · Rejected · Server error",
            "CSV / HTML export",
        ],
        "keys": [
            "Baseline valid file should succeed first — then attack suite.",
            "Accepted malicious type = finding; clean Rejected = control working.",
            "Match profile to the API (image vs Excel vs generic).",
        ],
        "steps": [
            "Open File Upload.",
            "Import the upload request (cURL / HAR / Capture).",
            "Confirm detected file field and profile.",
            "Run the upload test suite.",
            "Review Accepted / Rejected / Server Error per case.",
            "Export CSV / HTML.",
        ],
    },
    {
        "id": "xss",
        "name": "XSS Test",
        "tagline": "Reflected XSS payload probing",
        "use": (
            "Use when API responses feed HTML/JS UIs — inject XSS payloads into parameters "
            "and check for reflection / unsafe sinks."
        ),
        "owasp": "XSS (CWE-79) · API8:2023 Security Misconfiguration (output encoding)",
        "features": [
            "Capture / HAR / cURL load",
            "Param multi-select",
            "Quick / Full / Reflected profiles",
            "Reflection highlighting",
            "CSV / HTML export",
        ],
        "keys": [
            "JSON APIs may reflect strings safely — still check if a web UI renders them raw.",
            "Reflected profile focuses on echo detection.",
            "Confirm in browser when the API feeds an HTML page.",
        ],
        "steps": [
            "Open XSS Test.",
            "Load API from Capture / HAR / cURL.",
            "Select parameters to inject.",
            "Choose Quick, Full, or Reflected profile.",
            "Run tests and review reflections.",
            "Export findings.",
        ],
    },
    {
        "id": "jsa",
        "name": "JS Analyser",
        "tagline": "Secrets · PII · infra in API traffic",
        "use": (
            "Use to mine captured responses and bodies for leaked secrets, PII, and "
            "optional internal infrastructure indicators."
        ),
        "owasp": "API3:2023 Excessive Data Exposure · secret leakage · sensitive data in responses",
        "features": [
            "HAR import · live Capture · cURL",
            "Always-on secret rules; optional PII + infra",
            "Continuous Start mode or Run selected",
            "Filterable results table",
            "HTML export",
        ],
        "keys": [
            "Secrets scan is always on; enable PII / Infra only when needed (noise control).",
            "Use Search in expanded request/response to jump matches.",
            "Treat placeholders / examples carefully — validate before filing.",
        ],
        "steps": [
            "Open JS Analyser → Capture tab.",
            "Import HAR or use live Capture; optional cURL paste.",
            "Optional: tick PII and/or Infra.",
            "Select endpoints → Run JS Analyser (or Start for continuous).",
            "Watch Scanning; open Results.",
            "Filter by type / severity; Export HTML.",
        ],
    },
    {
        "id": "llmcmd",
        "name": "LLM / Command Injection",
        "tagline": "OS command + LLM prompt injection fuzzing",
        "use": (
            "Use on parameters that may reach a shell or an LLM/prompt pipeline — "
            "detect command injection and jailbreak / prompt-injection signals."
        ),
        "owasp": "OS Command Injection (CWE-77/78) · LLM prompt injection / insecure AI handling",
        "features": [
            "Capture / HAR / cURL intake",
            "Param selection",
            "CMDi + LLM jailbreak payload packs",
            "Baseline-aware confirmation (reduces echo FPs)",
            "HTML export",
        ],
        "keys": [
            "Prefer params named cmd, exec, query, prompt, message, input.",
            "Confirmed hits > heuristic — re-check in APISphere.",
            "LLM findings often need multi-turn manual follow-up.",
        ],
        "steps": [
            "Open LLM/Command Injection.",
            "Load target request (Capture / HAR / cURL).",
            "Select parameters to fuzz.",
            "Run the scan.",
            "Review confirmed vs heuristic findings.",
            "Export HTML report.",
        ],
    },
]


class AccentBar(Flowable):
    def __init__(self, width, height=3, color=C_ACCENT):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.color = color

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


def _styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=26, textColor=C_INK, alignment=TA_CENTER, spaceAfter=6, leading=30,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", parent=base["Normal"], fontName="Helvetica",
            fontSize=11, textColor=C_MUTED, alignment=TA_CENTER, leading=15, spaceAfter=4,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", parent=base["Normal"], fontSize=9, textColor=C_MUTED,
            alignment=TA_CENTER, leading=12,
        ),
        "h_mod": ParagraphStyle(
            "h_mod", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=16, textColor=C_INK, spaceBefore=0, spaceAfter=2, leading=20,
        ),
        "tagline": ParagraphStyle(
            "tagline", parent=base["Normal"], fontName="Helvetica-Oblique",
            fontSize=9, textColor=C_ACCENT, spaceAfter=6, leading=12,
        ),
        "sec": ParagraphStyle(
            "sec", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, textColor=C_WHITE, leading=10,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, textColor=C_BODY, leading=12, alignment=TA_JUSTIFY, spaceAfter=2,
        ),
        "bullet": ParagraphStyle(
            "bullet", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, textColor=C_BODY, leading=11,
        ),
        "step": ParagraphStyle(
            "step", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, textColor=C_INK, leading=12,
        ),
        "toc": ParagraphStyle(
            "toc", parent=base["Normal"], fontName="Helvetica",
            fontSize=10, textColor=C_BODY, leading=16,
        ),
        "toc_num": ParagraphStyle(
            "toc_num", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=10, textColor=C_ACCENT, leading=16,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"], fontSize=8, textColor=C_MUTED, alignment=TA_CENTER,
        ),
    }


def _section_header(label: str, bg, styles):
    t = Table([[Paragraph(label, styles["sec"])]], colWidths=[50 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _card(flowables, width=178 * mm):
    """Soft bordered card around a vertical stack of flowables."""
    # Stack into a single-column table of rows (avoids KeepTogether height bugs)
    rows = [[f] for f in flowables]
    t = Table(rows, colWidths=[width - 4 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (0, 0), 7),
        ("BOTTOMPADDING", (-1, -1), (-1, -1), 7),
        ("TOPPADDING", (0, 1), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -2), 2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _bullets(items, styles):
    return ListFlowable(
        [ListItem(Paragraph(x, styles["bullet"]), leftIndent=2, bulletColor=C_ACCENT)
         for x in items],
        bulletType="bullet",
        start="•",
        leftIndent=10,
        bulletFontSize=8,
        spaceBefore=0,
        spaceAfter=0,
    )


def _steps(items, styles):
    return ListFlowable(
        [ListItem(Paragraph(x, styles["step"]), leftIndent=4, bulletColor=C_INK)
         for x in items],
        bulletType="1",
        start=1,
        leftIndent=14,
        spaceBefore=0,
        spaceAfter=0,
    )


def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    # top rule
    canvas.setStrokeColor(C_LINE)
    canvas.setLineWidth(0.6)
    canvas.line(16 * mm, h - 10 * mm, w - 16 * mm, h - 10 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(16 * mm, h - 8.5 * mm, "API Sentinel · Apps Workflow Guide")
    canvas.drawRightString(w - 16 * mm, h - 8.5 * mm, "Confidential · Internal use")
    # bottom
    canvas.line(16 * mm, 12 * mm, w - 16 * mm, 12 * mm)
    canvas.drawCentredString(w / 2, 7 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _cover_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, 0, w, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(w / 2, 8 * mm, "API Sentinel Desktop Suite")
    canvas.restoreState()


def build_pdf():
    styles = _styles()
    page_w = A4[0] - 32 * mm

    doc = SimpleDocTemplate(
        str(PDF_PATH),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="API Sentinel — Apps Workflow Guide",
        author="API Sentinel",
    )

    story = []

    # ── Cover ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 28 * mm))
    story.append(AccentBar(page_w, 4, C_ACCENT))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("API Sentinel", styles["cover_title"]))
    story.append(Paragraph("Apps Workflow Guide", styles["cover_sub"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        f"{len(MODULES)} applications · End-user steps · Features · Key points · OWASP mapping",
        styles["cover_meta"],
    ))
    story.append(Spacer(1, 10 * mm))

    # TOC card
    toc_rows = []
    for i, m in enumerate(MODULES, 1):
        toc_rows.append([
            Paragraph(f"{i:02d}", styles["toc_num"]),
            Paragraph(m["name"], styles["toc"]),
            Paragraph(m["tagline"], ParagraphStyle(
                "tl", parent=styles["toc"], fontSize=8, textColor=C_MUTED,
            )),
        ])
    toc = Table(toc_rows, colWidths=[12 * mm, 55 * mm, 100 * mm])
    toc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, C_LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(toc)
    story.append(PageBreak())

    # ── Modules ────────────────────────────────────────────────────────────
    for i, m in enumerate(MODULES, 1):
        block = []
        block.append(Paragraph(f"{i}. {m['name']}", styles["h_mod"]))
        block.append(Paragraph(m["tagline"], styles["tagline"]))
        block.append(AccentBar(page_w, 2, C_ACCENT))
        block.append(Spacer(1, 4 * mm))

        # Usage
        block.append(_card([
            _section_header("USAGE", C_ACCENT, styles),
            Spacer(1, 2 * mm),
            Paragraph(m["use"], styles["body"]),
        ]))
        block.append(Spacer(1, 2.5 * mm))

        # OWASP
        block.append(_card([
            _section_header("OWASP / SECURITY", C_WARN, styles),
            Spacer(1, 2 * mm),
            Paragraph(m["owasp"], styles["body"]),
        ]))
        block.append(Spacer(1, 2.5 * mm))

        # Features + Key points side by side
        feat_card = _card([
            _section_header("FEATURES", C_BLUE, styles),
            Spacer(1, 2 * mm),
            _bullets(m["features"], styles),
        ], width=87 * mm)
        key_card = _card([
            _section_header("KEY POINTS", C_INK, styles),
            Spacer(1, 2 * mm),
            _bullets(m["keys"], styles),
        ], width=87 * mm)
        twin = Table([[feat_card, key_card]], colWidths=[89 * mm, 89 * mm])
        twin.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (0, 0), 2 * mm),
            ("LEFTPADDING", (1, 0), (1, 0), 2 * mm),
            ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ]))
        block.append(twin)
        block.append(Spacer(1, 2.5 * mm))

        # Workflow — primary focus
        block.append(_card([
            _section_header("USER WORKFLOW  (follow in order)", C_ACCENT, styles),
            Spacer(1, 2 * mm),
            _steps(m["steps"], styles),
        ]))
        block.append(Spacer(1, 2.5 * mm))

        # Screenshot
        shot = SHOT_DIR / f"{m['id']}.png"
        shot_bits = [
            _section_header("LANDING PAGE", C_MUTED, styles),
            Spacer(1, 2 * mm),
            Paragraph(
                "Tool UI as shown in API Sentinel",
                ParagraphStyle("cap", parent=styles["body"], fontSize=8, textColor=C_MUTED),
            ),
        ]
        if shot.is_file():
            img = Image(str(shot))
            max_w, max_h = page_w - 8 * mm, 68 * mm
            scale = min(max_w / img.imageWidth, max_h / img.imageHeight)
            img.drawWidth = img.imageWidth * scale
            img.drawHeight = img.imageHeight * scale
            shot_bits.append(Spacer(1, 2 * mm))
            shot_bits.append(img)
        else:
            shot_bits.append(Paragraph(f"Missing: {shot.name}", styles["body"]))
        block.append(_card(shot_bits))

        # Don't KeepTogether whole module (screenshot makes it too tall) —
        # allow natural page split after workflow if needed.
        for part in block:
            story.append(part)
        if i < len(MODULES):
            story.append(PageBreak())

    def first_page(canvas, doc):
        _cover_footer(canvas, doc)

    def later_pages(canvas, doc):
        _header_footer(canvas, doc)

    doc.build(story, onFirstPage=first_page, onLaterPages=later_pages)
    print(f"PDF -> {PDF_PATH}")


def capture_screenshots():
    """Optional — only if UI server is up."""
    from playwright.sync_api import sync_playwright
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        page.goto(UI_URL, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(600)
        for m in MODULES:
            page.evaluate(f"typeof switchTool==='function' && switchTool('{m['id']}')")
            page.wait_for_timeout(350)
            page.screenshot(path=str(SHOT_DIR / f"{m['id']}.png"), full_page=False)
            print(f"  shot {m['id']}")
        browser.close()


if __name__ == "__main__":
    import sys
    if "--shots" in sys.argv:
        print("Capturing screenshots…")
        capture_screenshots()
    print("Building PDF…")
    build_pdf()
    print("Done.")
