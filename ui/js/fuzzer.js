// ── API Fuzzer — Intelligent Auto-Fuzzing & Vulnerability Engine ──
"use strict";

(function () {
  const FUZZ_BASE = "http://127.0.0.1:8796";
  let _fuzzJobId = null;
  let _fuzzPollTimer = null;
  let _fuzzIsRunning = false;
  let _fuzzCurrentIssues = [];

  let _fuzzInited = false;
  let _fuzzActiveTab = "setup";
  let _fuzzActiveCatSubtab = "payloads";
  let _fuzzCategoriesSel = {};
  let _fuzzEndpointPacksSel = {};
  let _fuzzServicesPacksSel = {};
  let _fuzzCurrentModalPack = null;
  let _fuzzCurrentModalPayloads = [];
  let _fuzzSelectedResultIdx = 0;
  let _fuzzSelectedResultId = null;
  let _fuzzDetectedPoints = [];
  let _fuzzLastMethod = "GET";
  let _fuzzLastHost = "";
  let _fuzzTargetsCollapsed = false;
  let _fuzzCurrentResults = [];
  let _fuzzVisibleResults = [];
  let _fuzzCurrentStatusFilter = "all";
  let _fuzzCurrentLengthFilter = "all";
  let _fuzzCurrentTextFilter = "";
  let _fuzzSort = { key: "id", dir: 1 };
  let _fuzzManualPayloads = [];
  let _fuzzArjunJobId = null;
  let _fuzzArjunPollTimer = null;
  let _fuzzArjunLogsCount = 0;
  let _fuzzArjunDiscovered = [];

  // Category Metadata Descriptions for Attack Payloads
  const _FUZZ_CAT_DESCRIPTIONS = {
    sql: "Injects classic and blind SQL injection payloads into query, body, and header parameters to detect DBMS syntax errors and time-based sleep delays.",
    xss: "Reflected & context-breaking Cross-Site Scripting vectors testing for HTML, attribute, and script context execution.",
    blind_xss: "Out-of-band & blind stored XSS probes designed to trigger callback alerts inside internal admin panels.",
    dom_xss: "Source/sink injection strings targeting client-side redirect and DOM sinks like location.href, eval, innerHTML.",
    path: "Directory traversal and Local File Inclusion (LFI) paths attempting to read sensitive configuration and OS files (e.g., /etc/passwd).",
    cmd: "OS Command Injection delimiters and chaining operators (; id, | whoami, `id`) to detect remote code execution.",
    ssti: "Server-Side Template Injection & SpEL/OGNL expressions to detect expression evaluation engines (Jinja, FreeMarker, SpEL).",
    nosql: "NoSQL operator injection payloads ({\" $gt \": \"\"}) targeting MongoDB, CouchDB and unescaped BSON parsers.",
    ssrf: "Internal network, localhost, and cloud metadata (169.254.169.254) endpoints to probe for server-side request forgery.",
    crlf: "CRLF injection sequences (%0d%0a) testing for HTTP Response Splitting and arbitrary header injection.",
    ldap: "LDAP query filter bypass and wildcard injection sequences targeting Active Directory and LDAP auth.",
    log4j: "Log4Shell & JNDI lookup strings (${jndi:ldap://...}) probing for JNDI injection vulnerabilities.",
    xpath: "XPath syntax injection strings targeting XML query parsers and authentication bypasses.",
    cache_deception: "Static extension path confusion (;.css, /.js) designed to induce intermediate caches into caching sensitive user data.",
    header_bypass: "IP & Host spoofing headers (X-Forwarded-For, X-Real-IP) testing for IP-based ACL bypasses.",
    x_rewrite: "URL rewrite headers (X-Original-URL, X-Rewrite-URL) probing for reverse proxy authentication bypasses.",
    accept_headers: "Content-Type and Accept header fuzzing to test MIME confusion, parser switching, and unexpected media types.",
    prototype_pollution: "Client query and server-side JSON Prototype Pollution payloads targeting Object.prototype.",
    cve_rsc: "React Server Components (RSC) flight protocol and suspense prototype injection vectors (CVE-2025-55182).",
    cve_http2: "HTTP version pollution, malformed version strings, and HTTP/2 pseudo-header manipulations (:method, :path).",
    mass_assignment: "JSON body mass assignment payloads adding privileged role, admin, and permission attributes.",
    cache_poisoning: "Unkeyed header and path traversal payloads testing for Web Cache Poisoning & Host Header Injection.",
    samesite_cors: "Cross-Origin headers (Origin: null, Origin: evil.com) and method override (_method=POST) bypasses.",
    websocket_cswsh: "Cross-Site WebSocket Hijacking origin tests, WS message injection, and Server-Sent Event (SSE) injections.",
    csp_bypass: "Content Security Policy (CSP) nonce leakage via CSS selectors, dangling markup, and base href redirection.",
    soap_saml: "SOAP envelopes, XML Billion Laughs entity bombs, and SAML response token tampering.",
    jsonp: "JSONP callback hijacking parameters exfiltrating sensitive session and user data.",
    grpc_webdav: "gRPC reflection & metadata headers alongside WebDAV methods (PROPFIND, MKCOL).",
    pw_reset: "Host header poisoning and domain confusion vectors targeting password reset mechanisms.",
    mixed_payloads_1: "Curated collection of high-impact core injection vectors (SQLi, XSS, SSRF, Command Injection, LFI).",
    mixed_payloads_2: "Curated collection of modern API & protocol attack vectors (Prototype Pollution, SpEL, Mass Assignment, RSC)."
  };

  // Sample Demo Results for Visual Inspection
  const _SAMPLE_FUZZ_RESULTS = [
    {
      id: 1,
      method: "POST",
      location: "Body JSON: id",
      payload: "1' UNION SELECT null,version()--",
      status: 500,
      statusClass: "fuzz-status-5xx",
      length: 1428,
      time: 215,
      anomaly: "SQL Error / 500 Spike",
      isAnomaly: true,
      req: "POST /api/v1/users/profile HTTP/1.1\nHost: api.target.com\nContent-Type: application/json\nAuthorization: Bearer eyJhbGciOi...\n\n{\n  \"id\": \"1' UNION SELECT null,version()--\",\n  \"role\": \"user\",\n  \"status\": \"active\"\n}",
      resp: "HTTP/1.1 500 Internal Server Error\nServer: nginx/1.18.0\nContent-Type: application/json\nContent-Length: 1428\n\n{\n  \"error\": \"Database execution failed\",\n  \"driver_error\": \"syntax error at or near 'UNION' in query: SELECT * FROM users WHERE id = '1' UNION SELECT null,version()--'\",\n  \"code\": \"DB_500_SYNTAX\"\n}"
    },
    {
      id: 2,
      method: "POST",
      location: "Body JSON: role",
      payload: "admin",
      status: 200,
      statusClass: "fuzz-status-2xx",
      length: 894,
      time: 68,
      anomaly: "Role Changed to Admin",
      isAnomaly: true,
      req: "POST /api/v1/users/profile HTTP/1.1\nHost: api.target.com\nContent-Type: application/json\nAuthorization: Bearer eyJhbGciOi...\n\n{\n  \"id\": 42,\n  \"role\": \"admin\",\n  \"status\": \"active\"\n}",
      resp: "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 894\n\n{\n  \"id\": 42,\n  \"name\": \"Dev User\",\n  \"role\": \"admin\",\n  \"permissions\": [\"read\", \"write\", \"delete\", \"manage_users\"],\n  \"is_superuser\": true\n}"
    },
    {
      id: 3,
      method: "POST",
      location: "Query: filter",
      payload: "${7*7}",
      status: 200,
      statusClass: "fuzz-status-2xx",
      length: 412,
      time: 55,
      anomaly: "Evaluated: '49' reflected",
      isAnomaly: true,
      req: "POST /api/v1/users/profile?filter=${7*7} HTTP/1.1\nHost: api.target.com\nContent-Type: application/json\nAuthorization: Bearer eyJhbGciOi...\n\n{\n  \"id\": 42,\n  \"role\": \"user\"\n}",
      resp: "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 412\n\n{\n  \"status\": \"success\",\n  \"applied_filter\": \"49\",\n  \"total_matches\": 49\n}"
    },
    {
      id: 4,
      method: "GET",
      location: "Endpoint: Spring Boot Actuator",
      payload: "/actuator/env",
      status: 200,
      statusClass: "fuzz-status-2xx",
      length: 8432,
      time: 42,
      anomaly: "Exposed Actuator / Environment Secrets",
      isAnomaly: true,
      req: "GET /actuator/env HTTP/1.1\nHost: api.target.com\nUser-Agent: Mozilla/5.0 API-Sentinel-Fuzzer\nAccept: application/json\n\n",
      resp: "HTTP/1.1 200 OK\nContent-Type: application/vnd.spring-boot.actuator.v3+json\nContent-Length: 8432\n\n{\n  \"activeProfiles\": [\"prod\"],\n  \"propertySources\": [\n    {\n      \"name\": \"systemEnvironment\",\n      \"properties\": {\n        \"SPRING_DATASOURCE_PASSWORD\": { \"value\": \"******\" },\n        \"AWS_SECRET_ACCESS_KEY\": { \"value\": \"******\" },\n        \"JWT_SECRET\": { \"value\": \"s3cr3t-k3y-12345\" }\n      }\n    }\n  ]\n}"
    },
    {
      id: 5,
      method: "POST",
      location: "Header: X-Forwarded-For",
      payload: "127.0.0.1",
      status: 200,
      statusClass: "fuzz-status-2xx",
      length: 405,
      time: 62,
      anomaly: "",
      isAnomaly: false,
      req: "POST /api/v1/users/profile HTTP/1.1\nHost: api.target.com\nX-Forwarded-For: 127.0.0.1\nAuthorization: Bearer eyJhbGciOi...\n\n{\n  \"id\": 42,\n  \"role\": \"user\"\n}",
      resp: "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 405\n\n{\n  \"status\": \"ok\",\n  \"id\": 42\n}"
    },
    {
      id: 6,
      method: "POST",
      location: "Body JSON: id",
      payload: "http://169.254.169.254/latest/meta-data/",
      status: 504,
      statusClass: "fuzz-status-5xx",
      length: 532,
      time: 5020,
      anomaly: "Time Delay (5,020ms) / SSRF Probe",
      isAnomaly: true,
      req: "POST /api/v1/users/profile HTTP/1.1\nHost: api.target.com\nContent-Type: application/json\n\n{\n  \"id\": \"http://169.254.169.254/latest/meta-data/\",\n  \"role\": \"user\"\n}",
      resp: "HTTP/1.1 504 Gateway Timeout\nContent-Type: application/json\nContent-Length: 532\n\n{\n  \"error\": \"Upstream connection timed out to 169.254.169.254:80 after 5000ms\"\n}"
    }
  ];

  // Sample Detected Issues
  const _SAMPLE_ISSUES = [
    {
      sev: "critical",
      title: "Potential SQL Injection & Verbose DBMS Error Leakage",
      location: "Body JSON parameter: id",
      payload: "1' UNION SELECT null,version()--",
      endpoint: "POST /api/v1/users/profile",
      evidence: "Status code spiked from baseline 200 -> 500. Response body explicitly leaked backend PostgreSQL syntax: 'syntax error at or near UNION'.",
      resultIdx: 0
    },
    {
      sev: "critical",
      title: "Exposed Spring Boot Actuator Endpoint (/actuator/env)",
      location: "Path: /actuator/env",
      payload: "/actuator/env",
      endpoint: "GET /actuator/env",
      evidence: "Sensitive administrative actuator endpoint is publicly accessible without authentication. Leaked application environment configuration & properties.",
      resultIdx: 3
    },
    {
      sev: "critical",
      title: "API Mass Assignment & Privilege Escalation (Role Fuzzing)",
      location: "Body JSON parameter: role",
      payload: "\"role\": \"admin\"",
      endpoint: "POST /api/v1/users/profile",
      evidence: "Endpoint accepted injected 'role: admin' and returned upgraded permissions: ['read', 'write', 'delete', 'manage_users'] and is_superuser: true.",
      resultIdx: 1
    },
    {
      sev: "high",
      title: "Server-Side Template / Expression Injection (SSTI Evaluated)",
      location: "Query parameter: filter",
      payload: "${7*7}",
      endpoint: "POST /api/v1/users/profile?filter=${7*7}",
      evidence: "The injected mathematical expression '${7*7}' was evaluated server-side and reflected back as 'applied_filter: 49'.",
      resultIdx: 2
    },
    {
      sev: "high",
      title: "Blind Server-Side Request Forgery (SSRF) / Cloud Timeout Delay",
      location: "Body JSON parameter: id",
      payload: "http://169.254.169.254/latest/meta-data/",
      endpoint: "POST /api/v1/users/profile",
      evidence: "Target server attempted connection to internal AWS metadata IP 169.254.169.254 and hung for 5,020ms before returning 504 Gateway Timeout.",
      resultIdx: 5
    }
  ];

  function fuzzEl(id) {
    return document.getElementById(id);
  }

  function fuzzToast(msg) {
    if (typeof _asShowToast === "function") {
      _asShowToast(msg);
      return;
    }
    const t = document.createElement("div");
    t.textContent = msg;
    t.style.cssText =
      "position:fixed;bottom:24px;right:24px;background:#1f6feb;color:#fff;padding:8px 16px;border-radius:6px;font-size:12px;font-weight:600;box-shadow:0 8px 24px rgba(0,0,0,0.5);z-index:9999;transition:opacity 0.2s ease;";
    document.body.appendChild(t);
    setTimeout(() => {
      t.style.opacity = "0";
      setTimeout(() => t.remove(), 250);
    }, 2200);
  }

  // ── 1. INITIALIZATION ───────────────────────────────────────────────────
  function fuzzInit() {
    if (_fuzzInited) return;
    _fuzzInited = true;

    _fuzzCurrentResults = [];
    _fuzzVisibleResults = [];
    _fuzzCurrentIssues = [];
    _fuzzCurrentLengthFilter = "all";
    _fuzzSelectedResultIdx = null;
    _fuzzSelectedResultId = null;

    _fuzzInitCategories();
    _fuzzInitEvents();
    _fuzzManualPayloads = [];
    fuzzRenderManualPayloadList();
    _fuzzUpdateLengthFilterDropdown();
    _fuzzRenderResultsTable([]);
    _fuzzPaintSortHeaders();
    _fuzzRenderIssuesList([]);
    _fuzzApplyEmptyInspector();

    // Initial parsing of cURL
    fuzzParseCurrentCurl();
    fuzzRefreshCurlHighlight();

    // Ensure Setup tab is initially active
    fuzzSwitchTab("setup");
  }

  function _fuzzApplyEmptyInspector() {
    const reqEl = fuzzEl("fuzz-inspect-req-body");
    const respEl = fuzzEl("fuzz-inspect-resp-body");
    const renderFrame = fuzzEl("fuzz-inspect-render-frame");
    const emptyHtml = `<div class="fuzz-inspect-empty-state"><span style="font-size:22px;opacity:0.6">🔍</span><span style="font-size:11.5px;color:var(--text3);margin-top:6px;">Select a request row on the left to inspect HTTP details</span></div>`;
    if (reqEl) reqEl.innerHTML = emptyHtml;
    if (respEl) respEl.innerHTML = emptyHtml;
    if (renderFrame) renderFrame.srcdoc = "";
  }

  function _fuzzInitCategories() {
    const payloadPacks = (window.INTR_VALUE_LISTS || []).filter(
      (p) => Array.isArray(p.payloads) && p.group !== "Values"
    );
    payloadPacks.forEach((p) => {
      _fuzzCategoriesSel[p.id] = true;
    });

    const endpointPacks = window.INTR_ENDPOINT_PACKS || [];
    endpointPacks.forEach((p) => {
      _fuzzEndpointPacksSel[p.id] = true;
    });

    const servicesPacks = window.SERVICES_ENDPOINT_PACKS || [];
    servicesPacks.forEach((p) => {
      _fuzzServicesPacksSel[p.id] = true;
    });

    _fuzzRenderCategoriesGrid();
    _fuzzRenderEndpointsGrid();
    _fuzzRenderServicesGrid();
    _fuzzUpdateSummaryCounts();
  }

  function _fuzzUpdateSummaryCounts() {
    const summaryBadge = fuzzEl("fuzz-cats-summary-badge");
    const countPayloads = fuzzEl("fuzz-subtab-count-payloads");
    const countEndpoints = fuzzEl("fuzz-subtab-count-endpoints");
    const countServices = fuzzEl("fuzz-subtab-count-services");
    const infoPayloads = fuzzEl("fuzz-payloads-count-info");
    const infoEndpoints = fuzzEl("fuzz-endpoints-count-info");
    const infoServices = fuzzEl("fuzz-services-count-info");

    const payloadPacks = (window.INTR_VALUE_LISTS || []).filter(
      (p) => Array.isArray(p.payloads) && p.group !== "Values"
    );
    const endpointPacks = window.INTR_ENDPOINT_PACKS || [];
    const servicesPacks = window.SERVICES_ENDPOINT_PACKS || [];

    const activePayloads = payloadPacks.filter((p) => _fuzzCategoriesSel[p.id]).length;
    let totalPayloadCount = 0;
    payloadPacks.forEach((p) => {
      if (_fuzzCategoriesSel[p.id]) totalPayloadCount += p.payloads.length;
    });

    const activeEndpoints = endpointPacks.filter((p) => _fuzzEndpointPacksSel[p.id]).length;
    let totalEndpointCount = 0;
    endpointPacks.forEach((p) => {
      if (_fuzzEndpointPacksSel[p.id] && Array.isArray(p.paths)) {
        totalEndpointCount += p.paths.length;
      }
    });

    const activeServices = servicesPacks.filter((p) => _fuzzServicesPacksSel[p.id]).length;
    let totalServicesCount = 0;
    servicesPacks.forEach((p) => {
      if (_fuzzServicesPacksSel[p.id] && Array.isArray(p.paths)) {
        totalServicesCount += p.paths.length;
      }
    });

    const totalSelected = totalPayloadCount + totalEndpointCount + totalServicesCount;
    if (summaryBadge) {
      summaryBadge.textContent = `${totalSelected.toLocaleString()} Active`;
      summaryBadge.style.display = totalSelected > 0 ? "inline-flex" : "none";
    }

    if (countPayloads) {
      countPayloads.textContent = `${activePayloads}/${payloadPacks.length}`;
    }
    if (countEndpoints) {
      countEndpoints.textContent = `${activeEndpoints}/${endpointPacks.length}`;
    }
    if (countServices) {
      countServices.textContent = `${activeServices}/${servicesPacks.length}`;
    }

    if (infoPayloads) {
      infoPayloads.innerHTML = `<b>${totalPayloadCount.toLocaleString()}</b> active test vectors in <b>${activePayloads}/${payloadPacks.length}</b> packs`;
    }
    if (infoEndpoints) {
      infoEndpoints.innerHTML = `<b>${totalEndpointCount.toLocaleString()}</b> active route discovery probes in <b>${activeEndpoints}/${endpointPacks.length}</b> packs`;
    }
    if (infoServices) {
      infoServices.innerHTML = `<b>${totalServicesCount.toLocaleString()}</b> active service routes in <b>${activeServices}/${servicesPacks.length}</b> tools`;
    }
  }

  function _fuzzRenderCategoriesGrid() {
    const grid = fuzzEl("fuzz-categories-grid");
    if (!grid) return;

    const packs = (window.INTR_VALUE_LISTS || []).filter(
      (p) => Array.isArray(p.payloads) && p.group !== "Values"
    );

    grid.innerHTML = packs
      .map((p) => {
        const on = !!_fuzzCategoriesSel[p.id];
        const n = p.payloads.length;
        return `<div class="fuzz-mod-chip${on ? "" : " is-off"}" title="${_fuzzEscapeAttr(p.label)} (${n} payloads)">
          <label class="fuzz-mod-chip-main">
            <input type="checkbox" data-cat="${p.id}" ${on ? "checked" : ""}
                   onchange="fuzzToggleCategory('${p.id}', this.checked)">
            <span class="fuzz-mod-label">${_fuzzEscapeHtml(p.label)}</span>
            <span class="fuzz-mod-count">(${n})</span>
          </label>
          <button type="button" class="fuzz-mod-eye-btn" title="View ${p.label} Payloads"
                  onclick="fuzzOpenPayloadModal('${p.id}', false, event)">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        </div>`;
      })
      .join("");
  }

  function _fuzzRenderEndpointsGrid() {
    const grid = fuzzEl("fuzz-endpoints-grid");
    if (!grid) return;

    const packs = window.INTR_ENDPOINT_PACKS || [];
    grid.innerHTML = packs
      .map((p) => {
        const on = !!_fuzzEndpointPacksSel[p.id];
        const n = Array.isArray(p.paths) ? p.paths.length : 0;
        return `<div class="fuzz-mod-chip endpoint-chip${on ? "" : " is-off"}" title="${_fuzzEscapeAttr(p.label)} (${n} paths - ${p.group || "Services"})">
          <label class="fuzz-mod-chip-main">
            <input type="checkbox" data-endpoint="${p.id}" ${on ? "checked" : ""}
                   onchange="fuzzToggleEndpointPack('${p.id}', this.checked)">
            <span class="fuzz-mod-label">${_fuzzEscapeHtml(p.label)}</span>
            <span class="fuzz-mod-count">(${n})</span>
          </label>
          <button type="button" class="fuzz-mod-eye-btn" title="View ${p.label} Endpoints"
                  onclick="fuzzOpenPayloadModal('${p.id}', true, event)">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        </div>`;
      })
      .join("");
  }

  function _fuzzRenderServicesGrid() {
    const grid = fuzzEl("fuzz-services-grid");
    if (!grid) return;

    const packs = window.SERVICES_ENDPOINT_PACKS || [];
    grid.innerHTML = packs
      .map((p) => {
        const on = !!_fuzzServicesPacksSel[p.id];
        const n = Array.isArray(p.paths) ? p.paths.length : 0;
        return `<div class="fuzz-mod-chip service-chip${on ? "" : " is-off"}" title="${_fuzzEscapeAttr(p.label)} (${n} paths - ${p.group || "Services"})">
          <label class="fuzz-mod-chip-main">
            <input type="checkbox" data-service="${p.id}" ${on ? "checked" : ""}
                   onchange="fuzzToggleServicesPack('${p.id}', this.checked)">
            <span class="fuzz-mod-label">${_fuzzEscapeHtml(p.label)}</span>
            <span class="fuzz-mod-count">(${n})</span>
          </label>
          <button type="button" class="fuzz-mod-eye-btn" title="View ${p.label} Endpoints"
                  onclick="fuzzOpenPayloadModal('${p.id}', 'services', event)">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        </div>`;
      })
      .join("");
  }

  function fuzzToggleCategory(id, on) {
    _fuzzCategoriesSel[id] = !!on;
    _fuzzRenderCategoriesGrid();
    _fuzzUpdateSummaryCounts();
  }

  function fuzzToggleEndpointPack(id, on) {
    _fuzzEndpointPacksSel[id] = !!on;
    _fuzzRenderEndpointsGrid();
    _fuzzUpdateSummaryCounts();
  }

  function fuzzToggleServicesPack(id, on) {
    _fuzzServicesPacksSel[id] = !!on;
    _fuzzRenderServicesGrid();
    _fuzzUpdateSummaryCounts();
  }

  function fuzzSelectAllCategories(mode) {
    const payloadPacks = (window.INTR_VALUE_LISTS || []).filter(
      (p) => Array.isArray(p.payloads) && p.group !== "Values"
    );
    const endpointPacks = window.INTR_ENDPOINT_PACKS || [];
    const servicesPacks = window.SERVICES_ENDPOINT_PACKS || [];

    if (mode === "all") {
      payloadPacks.forEach((p) => (_fuzzCategoriesSel[p.id] = true));
      endpointPacks.forEach((p) => (_fuzzEndpointPacksSel[p.id] = true));
      servicesPacks.forEach((p) => (_fuzzServicesPacksSel[p.id] = true));
    } else if (mode === "none") {
      payloadPacks.forEach((p) => (_fuzzCategoriesSel[p.id] = false));
      endpointPacks.forEach((p) => (_fuzzEndpointPacksSel[p.id] = false));
      servicesPacks.forEach((p) => (_fuzzServicesPacksSel[p.id] = false));
    } else if (mode === "injections") {
      payloadPacks.forEach((p) => (_fuzzCategoriesSel[p.id] = true));
    } else if (mode === "none-injections") {
      payloadPacks.forEach((p) => (_fuzzCategoriesSel[p.id] = false));
    } else if (mode === "endpoints") {
      endpointPacks.forEach((p) => (_fuzzEndpointPacksSel[p.id] = true));
    } else if (mode === "none-endpoints") {
      endpointPacks.forEach((p) => (_fuzzEndpointPacksSel[p.id] = false));
    } else if (mode === "services") {
      servicesPacks.forEach((p) => (_fuzzServicesPacksSel[p.id] = true));
    } else if (mode === "none-services") {
      servicesPacks.forEach((p) => (_fuzzServicesPacksSel[p.id] = false));
    }

    _fuzzRenderCategoriesGrid();
    _fuzzRenderEndpointsGrid();
    _fuzzRenderServicesGrid();
    _fuzzUpdateSummaryCounts();
  }

  // ── Expand / Collapse Categories Card ───────────────────────────────────
  function fuzzToggleCatsCollapse() {
    const body = fuzzEl("fuzz-cats-collapsible-body");
    const btn = fuzzEl("fuzz-cats-collapse-btn");
    if (!body) return;

    const isCollapsed = body.classList.toggle("is-collapsed");
    if (btn) {
      btn.innerHTML = isCollapsed ? "▼ Expand" : "▲ Collapse";
    }
  }

  // ── Switch Category Sub-Tab (Payloads vs Endpoints vs Services) ──────────
  function fuzzSwitchCatSubtab(tabName) {
    _fuzzActiveCatSubtab = tabName;
    const btnPayloads = fuzzEl("fuzz-subtab-btn-payloads");
    const btnEndpoints = fuzzEl("fuzz-subtab-btn-endpoints");
    const btnServices = fuzzEl("fuzz-subtab-btn-services");
    const gridPayloads = fuzzEl("fuzz-categories-grid");
    const gridEndpoints = fuzzEl("fuzz-endpoints-grid");
    const gridServices = fuzzEl("fuzz-services-grid");
    const barPayloads = fuzzEl("fuzz-sec-bar-payloads");
    const barEndpoints = fuzzEl("fuzz-sec-bar-endpoints");
    const barServices = fuzzEl("fuzz-sec-bar-services");

    if (btnPayloads) btnPayloads.classList.toggle("active", tabName === "payloads");
    if (btnEndpoints) btnEndpoints.classList.toggle("active", tabName === "endpoints");
    if (btnServices) btnServices.classList.toggle("active", tabName === "services");

    if (gridPayloads) gridPayloads.style.display = tabName === "payloads" ? "flex" : "none";
    if (gridEndpoints) gridEndpoints.style.display = tabName === "endpoints" ? "flex" : "none";
    if (gridServices) gridServices.style.display = tabName === "services" ? "flex" : "none";

    if (barPayloads) barPayloads.style.display = tabName === "payloads" ? "flex" : "none";
    if (barEndpoints) barEndpoints.style.display = tabName === "endpoints" ? "flex" : "none";
    if (barServices) barServices.style.display = tabName === "services" ? "flex" : "none";
  }

  // ── 1c. MANUAL / CUSTOM PAYLOADS (Intruder Style) ────────────────────────
  function fuzzToggleManualCollapse() {
    const body = fuzzEl("fuzz-manual-collapsible-body");
    const btn = fuzzEl("fuzz-manual-collapse-btn");
    const title = document.querySelector("#fuzz-manual-card .fuzz-card-title");
    if (!body) return;

    const isCollapsed = body.classList.toggle("is-collapsed");
    if (btn) {
      btn.innerHTML = isCollapsed ? "▼ Expand" : "▲ Collapse";
    }
    if (title) {
      title.textContent = isCollapsed ? "▸ Payload configuration" : "▾ Payload configuration";
    }
  }

  function fuzzToggleEncCollapse() {
    const body = fuzzEl("fuzz-enc-collapsible-body");
    const btn = fuzzEl("fuzz-enc-collapse-btn");
    const title = document.querySelector("#fuzz-enc-card .fuzz-card-title");
    if (!body) return;

    const isCollapsed = body.classList.toggle("is-collapsed");
    if (btn) {
      btn.innerHTML = isCollapsed ? "▼ Expand" : "▲ Collapse";
    }
    if (title) {
      title.textContent = isCollapsed ? "▸ Payload encoding" : "▾ Payload encoding";
    }
  }

  function fuzzRenderManualPayloadList() {
    const box = fuzzEl("fuzz-manual-list");
    if (!box) return;

    const picked = new Set();
    box.querySelectorAll(".fuzz-manual-row.selected").forEach((r) => {
      const i = parseInt(r.getAttribute("data-i"), 10);
      if (!isNaN(i)) picked.add(i);
    });

    const items = _fuzzManualPayloads || [];
    if (!items.length) {
      box.innerHTML = '<div class="fuzz-manual-empty">No payloads — Add, Paste, or Load</div>';
    } else {
      box.innerHTML = items.map((p, i) => {
        const vis = p === "" ? "(empty)" : String(p);
        const sel = picked.has(i) ? " selected" : "";
        return `<div class="fuzz-manual-row${sel}" data-i="${i}" role="option" aria-selected="${picked.has(i) ? "true" : "false"}"><span class="fuzz-manual-row-num">${i + 1}</span><span class="fuzz-manual-row-text">${_fuzzEscapeHtml(vis)}</span></div>`;
      }).join("");
    }
    fuzzUpdateManualCount();
  }

  function fuzzUpdateManualCount() {
    const badge = fuzzEl("fuzz-manual-count-badge");
    const count = (_fuzzManualPayloads || []).length;
    if (badge) {
      badge.textContent = `${count.toLocaleString()} Payload${count === 1 ? "" : "s"}`;
      badge.style.display = count > 0 ? "inline-flex" : "none";
    }
  }

  function _fuzzBindManualListEvents() {
    const box = fuzzEl("fuzz-manual-list");
    if (!box || box._fuzzBound) return;
    box._fuzzBound = true;
    box.addEventListener("click", (e) => {
      const row = e.target.closest(".fuzz-manual-row");
      if (!row || !box.contains(row)) return;
      const rows = [].slice.call(box.querySelectorAll(".fuzz-manual-row"));
      if (e.metaKey || e.ctrlKey) {
        row.classList.toggle("selected");
      } else {
        rows.forEach((r) => r.classList.remove("selected"));
        row.classList.add("selected");
      }
      rows.forEach((r) => r.setAttribute("aria-selected", r.classList.contains("selected") ? "true" : "false"));
    });
  }

  async function fuzzManualPaste() {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text && text.trim()) {
          const lines = _fuzzSplitLines(text).filter((l) => l.trim() !== "");
          if (lines.length > 0) {
            _fuzzAppendManualPayloads(lines);
            fuzzToast(`📋 Added ${lines.length} manual payload(s) from clipboard`);
            return;
          }
        }
      }
    } catch (_) {}
    fuzzOpenManualPasteModal();
  }

  async function fuzzOpenManualPasteModal() {
    const modal = fuzzEl("fuzz-manual-paste-modal");
    const inp = fuzzEl("fuzz-manual-paste-input");
    if (inp && !inp.value.trim()) {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const t = await navigator.clipboard.readText();
          if (t && t.trim()) inp.value = t.trim();
        }
      } catch (_) {}
    }
    if (modal) modal.style.display = "flex";
    setTimeout(() => {
      if (inp) {
        inp.focus();
        if (inp.value) inp.select();
      }
    }, 40);
  }

  function fuzzCloseManualPasteModal() {
    const modal = fuzzEl("fuzz-manual-paste-modal");
    if (modal) modal.style.display = "none";
  }

  function fuzzConfirmManualPaste() {
    const inp = fuzzEl("fuzz-manual-paste-input");
    const val = inp ? inp.value.trim() : "";
    if (!val) {
      fuzzToast("⚠️ Please enter or paste at least one payload");
      if (inp) inp.focus();
      return;
    }
    const lines = _fuzzSplitLines(val).filter((l) => l.trim() !== "");
    if (lines.length > 0) {
      _fuzzAppendManualPayloads(lines);
      fuzzToast(`📋 Added ${lines.length} manual payload(s)`);
      if (inp) inp.value = "";
      fuzzCloseManualPasteModal();
    } else {
      fuzzToast("⚠️ No valid payloads found in input");
    }
  }

  function fuzzManualLoad() {
    const f = fuzzEl("fuzz-manual-file");
    if (f) {
      f.value = "";
      f.click();
    }
  }

  function fuzzManualFilePicked(ev) {
    const file = ev && ev.target && ev.target.files && ev.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || "");
      const lines = _fuzzSplitLines(text).filter((l) => l.trim() !== "");
      _fuzzAppendManualPayloads(lines);
      fuzzToast(`📁 Loaded ${lines.length} payload(s) from file "${file.name}"`);
    };
    reader.onerror = () => fuzzToast("❌ Could not read payload file.");
    reader.readAsText(file);
  }

  function fuzzManualRemove() {
    const box = fuzzEl("fuzz-manual-list");
    if (!box) return;
    const selectedRows = box.querySelectorAll(".fuzz-manual-row.selected");
    const idx = [].map.call(selectedRows, (r) => parseInt(r.getAttribute("data-i"), 10))
      .filter((n) => !isNaN(n))
      .sort((a, b) => b - a);

    if (!idx.length) {
      if (_fuzzManualPayloads.length > 0) {
        _fuzzManualPayloads.pop();
        fuzzRenderManualPayloadList();
        fuzzToast("Removed last payload");
      } else {
        fuzzToast("Select one or more payloads to remove.");
      }
      return;
    }
    idx.forEach((i) => _fuzzManualPayloads.splice(i, 1));
    fuzzRenderManualPayloadList();
    fuzzToast(`Removed ${idx.length} payload(s)`);
  }

  function fuzzManualClear() {
    const prevCount = _fuzzManualPayloads.length;
    _fuzzManualPayloads = [];
    fuzzRenderManualPayloadList();
    if (prevCount > 0) {
      fuzzToast("Cleared all manual payloads");
    }
  }

  function fuzzManualDedup() {
    const beforeCount = _fuzzManualPayloads.length;
    const seen = new Set();
    const out = [];
    _fuzzManualPayloads.forEach((p) => {
      if (!seen.has(p)) {
        seen.add(p);
        out.push(p);
      }
    });
    const removed = beforeCount - out.length;
    _fuzzManualPayloads = out;
    fuzzRenderManualPayloadList();
    fuzzToast(`Deduplicated: removed ${removed} duplicate payload(s), ${out.length} unique remaining`);
  }

  function fuzzManualAdd() {
    const inp = fuzzEl("fuzz-manual-add-input");
    const val = inp ? inp.value.trim() : "";
    if (!val) {
      fuzzToast("⚠️ Please enter a payload to add");
      if (inp) inp.focus();
      return;
    }
    if (val.includes("\n")) {
      const lines = _fuzzSplitLines(val).filter((l) => l.trim() !== "");
      _fuzzAppendManualPayloads(lines);
      fuzzToast(`Added ${lines.length} payload(s)`);
    } else {
      _fuzzManualPayloads.push(val);
      fuzzRenderManualPayloadList();
      fuzzToast(`Added payload: "${val}"`);
    }
    if (inp) {
      inp.value = "";
      inp.focus();
    }
  }

  function _fuzzSplitLines(text) {
    return String(text || "")
      .replace(/\r\n/g, "\n")
      .replace(/\r/g, "\n")
      .split("\n");
  }

  function _fuzzAppendManualPayloads(lines) {
    (lines || []).forEach((l) => {
      const s = typeof l === "string" ? l.trim() : String(l).trim();
      if (s) {
        _fuzzManualPayloads.push(s);
      }
    });
    if (_fuzzManualPayloads.length > 10000) {
      _fuzzManualPayloads = _fuzzManualPayloads.slice(0, 10000);
      fuzzToast("⚠️ Payloads limited to maximum 10,000 items");
    }
    fuzzRenderManualPayloadList();
  }

  // ── 1d. ARJUN HIDDEN PARAMETER DISCOVERY ──────────────────────────────
  function fuzzOpenArjunModal() {
    fuzzSwitchTab("arjun");
  }

  function fuzzCloseArjunModal() {
    fuzzSwitchTab("setup");
  }

  function fuzzUpdateArjunTargetDisplay() {
    const rawReq = (fuzzEl("fuzz-curl-input") && fuzzEl("fuzz-curl-input").value) || "";
    const targetCode = fuzzEl("fuzz-arjun-target-url");
    if (!targetCode) return;
    if (!rawReq.trim()) {
      targetCode.textContent = "— (Enter target in Fuzz Setup)";
      return;
    }
    let displayMethod = _fuzzLastMethod || "GET";
    let displayUrl = _fuzzLastHost || "";
    try {
      const payloadCurl = fuzzHttpTemplateToCurl(rawReq);
      const mMatch = payloadCurl.match(/-X\s+([A-Za-z]+)/i);
      if (mMatch) displayMethod = mMatch[1].toUpperCase();
      const uMatch = payloadCurl.match(/['"](https?:\/\/[^'"]+)['"]/i);
      if (uMatch) displayUrl = uMatch[1];
    } catch (_) {}
    targetCode.textContent = `${displayMethod} ${displayUrl || _fuzzLastHost || 'Target URL'}`;
  }

  function fuzzArjunWordlistChanged(val) {
    const box = fuzzEl("fuzz-arjun-custom-box");
    if (box) {
      box.style.display = val === "custom" ? "block" : "none";
    }
  }

  async function fuzzStartArjunScan() {
    const rawReq = (fuzzEl("fuzz-curl-input") && fuzzEl("fuzz-curl-input").value) || "";
    if (!rawReq.trim()) {
      fuzzToast("⚠️ Target request is empty. Please paste a cURL or URL in '🎯 Fuzz Setup' first");
      return;
    }

    const payloadCurl = fuzzHttpTemplateToCurl(rawReq);
    const paramType = (fuzzEl("fuzz-arjun-type") && fuzzEl("fuzz-arjun-type").value) || "query";
    const wordlistType = (fuzzEl("fuzz-arjun-wordlist") && fuzzEl("fuzz-arjun-wordlist").value) || "standard";
    const batchSize = parseInt((fuzzEl("fuzz-arjun-batch") && fuzzEl("fuzz-arjun-batch").value) || "25", 10) || 25;

    let customWordlist = [];
    if (wordlistType === "custom") {
      const customText = (fuzzEl("fuzz-arjun-custom-input") && fuzzEl("fuzz-arjun-custom-input").value) || "";
      customWordlist = customText.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
      if (!customWordlist.length) {
        fuzzToast("⚠️ Please enter at least one parameter name in the custom wordlist");
        return;
      }
    }

    // Reset UI state
    _fuzzArjunLogsCount = 0;
    _fuzzArjunDiscovered = [];
    _fuzzArjunRenderFoundParams([]);

    const terminal = fuzzEl("fuzz-arjun-terminal");
    if (terminal) {
      terminal.innerHTML = `<div class="fuzz-term-line term-dim">[system] Initializing Arjun discovery job for ${paramType.toUpperCase()} parameters...</div>`;
    }

    const statStatus = fuzzEl("fuzz-arjun-stat-status");
    const statBaseline = fuzzEl("fuzz-arjun-stat-baseline");
    const statProgress = fuzzEl("fuzz-arjun-stat-progress");
    const statFound = fuzzEl("fuzz-arjun-stat-found");
    const progressFill = fuzzEl("fuzz-arjun-progress-fill");

    if (statStatus) {
      statStatus.textContent = "Scanning...";
      statStatus.style.color = "#58a6ff";
    }
    if (statBaseline) statBaseline.textContent = "Baseline: Establishing...";
    if (statProgress) statProgress.textContent = "Tested: 0 (0%)";
    if (statFound) statFound.textContent = "✨ 0 Found";
    if (progressFill) progressFill.style.width = "0%";

    const startBtn = fuzzEl("fuzz-arjun-start-btn");
    const stopBtn = fuzzEl("fuzz-arjun-stop-btn");
    if (startBtn) {
      startBtn.disabled = true;
      startBtn.textContent = "⏳ Scanning...";
    }
    if (stopBtn) stopBtn.disabled = false;

    try {
      const res = await fetch(`${FUZZ_BASE}/fuzzer/arjun/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          curl: payloadCurl,
          param_type: paramType,
          wordlist_type: wordlistType,
          custom_wordlist: customWordlist.length ? customWordlist : null,
          batch_size: batchSize,
          threads: 5
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server responded with ${res.status}`);
      }

      const data = await res.json();
      _fuzzArjunJobId = data.job_id;
      _fuzzArjunStartPolling();
      fuzzToast(`🚀 Arjun parameter discovery started (${paramType.toUpperCase()} mode)...`);
    } catch (err) {
      _fuzzArjunSetRunningUi(false);
      fuzzToast(`❌ Failed to start Arjun: ${err.message}`);
      if (terminal) {
        terminal.innerHTML += `<div class="fuzz-term-line term-error">[error] Failed to start scan: ${err.message}</div>`;
      }
    }
  }

  async function fuzzStopArjunScan() {
    if (_fuzzArjunJobId) {
      fetch(`${FUZZ_BASE}/fuzzer/arjun/stop/${_fuzzArjunJobId}`, { method: "POST" }).catch(() => {});
    }
    _fuzzArjunStopPolling();
    _fuzzArjunSetRunningUi(false);
    fuzzToast("⏹ Arjun discovery scan stopped.");
  }

  function _fuzzArjunStartPolling() {
    _fuzzArjunStopPolling();
    _fuzzArjunPollTimer = setInterval(async () => {
      if (!_fuzzArjunJobId) return;

      try {
        const res = await fetch(`${FUZZ_BASE}/fuzzer/arjun/status/${_fuzzArjunJobId}?since=${_fuzzArjunLogsCount}`);
        if (!res.ok) return;
        const data = await res.json();

        // 1. Process New Logs
        if (data.new_logs && data.new_logs.length > 0) {
          const terminal = fuzzEl("fuzz-arjun-terminal");
          if (terminal) {
            data.new_logs.forEach(log => {
              const cls = log.level === "success" ? "term-success" : (log.level === "warn" ? "term-warn" : (log.level === "error" ? "term-error" : "term-info"));
              terminal.innerHTML += `<div class="fuzz-term-line ${cls}">[${log.time}] ${_fuzzEscapeHtml(log.msg)}</div>`;
            });
            terminal.scrollTop = terminal.scrollHeight;
          }
          _fuzzArjunLogsCount += data.new_logs.length;
        }

        // 2. Update Stats & Progress Bar
        const statStatus = fuzzEl("fuzz-arjun-stat-status");
        const statBaseline = fuzzEl("fuzz-arjun-stat-baseline");
        const statProgress = fuzzEl("fuzz-arjun-stat-progress");
        const statFound = fuzzEl("fuzz-arjun-stat-found");
        const progressFill = fuzzEl("fuzz-arjun-progress-fill");

        if (progressFill) progressFill.style.width = `${data.percent || 0}%`;
        if (statProgress) statProgress.textContent = `Tested: ${data.tested} / ${data.total} (${data.percent || 0}%)`;
        if (statFound) statFound.textContent = `✨ ${data.discovered_count || 0} Found`;

        if (data.baseline && data.baseline.status) {
          if (statBaseline) statBaseline.textContent = `Base: ${data.baseline.status} (${data.baseline.len} bytes)`;
        }

        // 3. Render Discovered Parameters
        if (data.discovered_params && data.discovered_params.length > _fuzzArjunDiscovered.length) {
          _fuzzArjunDiscovered = data.discovered_params;
          _fuzzArjunRenderFoundParams(_fuzzArjunDiscovered);
        }

        // 4. Job Complete Check
        if (data.status === "finished" || data.status === "stopped" || data.status === "error") {
          _fuzzArjunStopPolling();
          _fuzzArjunSetRunningUi(false);
          if (statStatus) {
            statStatus.textContent = data.status === "finished" ? "✓ Finished" : (data.status === "error" ? "❌ Error" : "⏹ Stopped");
            statStatus.style.color = data.status === "finished" ? "#3fb950" : (data.status === "error" ? "#f85149" : "#d29922");
          }
          if (data.status === "finished") {
            fuzzToast(`🎉 Arjun scan finished! Discovered ${data.discovered_count} parameter(s).`);
          }
        }
      } catch (_) {}
    }, 500);
  }

  function _fuzzArjunStopPolling() {
    if (_fuzzArjunPollTimer) {
      clearInterval(_fuzzArjunPollTimer);
      _fuzzArjunPollTimer = null;
    }
  }

  function _fuzzArjunSetRunningUi(isRunning) {
    const startBtn = fuzzEl("fuzz-arjun-start-btn");
    const stopBtn = fuzzEl("fuzz-arjun-stop-btn");
    if (startBtn) {
      startBtn.disabled = isRunning;
      startBtn.textContent = isRunning ? "⏳ Scanning..." : "▶ Start Discovery";
    }
    if (stopBtn) stopBtn.disabled = !isRunning;
  }

  function _fuzzArjunRenderFoundParams(list) {
    const box = fuzzEl("fuzz-arjun-found-list");
    const countEl = fuzzEl("fuzz-arjun-found-count");
    const addAllBtn = fuzzEl("fuzz-arjun-add-all-btn");
    const badge = fuzzEl("fuzz-arjun-tab-badge");
    if (!box) return;

    if (countEl) countEl.textContent = list.length;
    if (addAllBtn) addAllBtn.disabled = !list.length;
    if (badge) {
      if (list.length > 0) {
        badge.textContent = list.length;
        badge.style.display = "inline-flex";
      } else {
        badge.style.display = "none";
      }
    }

    if (!list.length) {
      box.innerHTML = `<div class="fuzz-arjun-empty-hint"><span>🎯</span><div>No hidden parameters discovered yet.</div><div style="font-size:10.5px;color:var(--text3);margin-top:3px;">Parameters identified via differential analysis will appear here.</div></div>`;
      return;
    }

    box.innerHTML = list.map((item) => {
      const isAlreadyAdded = _fuzzDetectedPoints.some(p => (p.key === item.name || p.name === item.name) && p.type === item.type);
      return `
        <div class="fuzz-arjun-param-item">
          <div class="fuzz-arjun-param-left">
            <div class="fuzz-arjun-param-pill">
              <span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(88,166,255,0.15);">${item.type.toUpperCase()}</span>
              <b>${_fuzzEscapeHtml(item.name)}</b>
            </div>
            <div class="fuzz-arjun-param-reason" title="${_fuzzEscapeAttr(item.evidence)}">
              ${_fuzzEscapeHtml(item.reason)}
            </div>
          </div>
          <div class="fuzz-arjun-param-actions">
            <button type="button" class="fuzz-arjun-param-curl-btn" onclick="fuzzArjunCopyCurl('${_fuzzEscapeAttr(item.name)}', '${_fuzzEscapeAttr(item.type)}', '${_fuzzEscapeAttr(item.sample_val || '')}')" title="Copy ready-to-test cURL command to clipboard">
              📋 cURL
            </button>
            ${isAlreadyAdded
              ? `<button type="button" class="fuzz-arjun-param-add-btn is-added" disabled style="opacity:0.65;cursor:default;background:rgba(46,160,67,0.15);color:#3fb950;border-color:rgba(46,160,67,0.4);">✓ Added</button>`
              : `<button type="button" class="fuzz-arjun-param-add-btn" onclick="fuzzArjunAddSingleTarget('${_fuzzEscapeAttr(item.name)}', '${_fuzzEscapeAttr(item.type)}')">+ Add Target</button>`
            }
          </div>
        </div>
      `;
    }).join("");
  }

  function _fuzzBuildArjunCurl(name, type, sampleVal) {
    const rawReq = (fuzzEl("fuzz-curl-input") && fuzzEl("fuzz-curl-input").value) || "";
    let baseCurl = "";
    if (rawReq.trim()) {
      baseCurl = fuzzHttpTemplateToCurl(rawReq);
    }
    
    // Fallback if no rawReq in setup: construct basic curl from Arjun target display or current URL
    if (!baseCurl) {
      const targetCode = fuzzEl("fuzz-arjun-target-url");
      let url = "https://example.com";
      if (targetCode && targetCode.textContent && targetCode.textContent !== "—") {
        const parts = targetCode.textContent.trim().split(/\s+/);
        url = parts.length > 1 ? parts[1] : parts[0];
      }
      baseCurl = `curl -X GET '${url}'`;
    }

    // Ensure -i -k flags for manual testing (include headers & ignore self-signed certs)
    if (!/\b-i\b/.test(baseCurl)) {
      baseCurl = baseCurl.replace(/^curl\b/i, "curl -i");
    }
    if (!/\b-k\b/.test(baseCurl)) {
      baseCurl = baseCurl.replace(/^curl\b/i, "curl -k");
    }

    // Determine value to test
    let testVal = sampleVal || "test";
    const pType = (type || "query").toLowerCase();

    if (pType === "header") {
      const lower = name.toLowerCase();
      if (lower === "host") testVal = "evil.com";
      else if (lower === "upgrade") testVal = "websocket";
      else if (lower === "connection") testVal = "upgrade";
      else if (!sampleVal || sampleVal === "test") testVal = "test-value";
      
      // If header already exists in baseCurl, replace it; else append it
      const headerRegex = new RegExp(`(-H\\s+['"])${name}:\\s*[^'"]+(['"])`, "i");
      if (headerRegex.test(baseCurl)) {
        baseCurl = baseCurl.replace(headerRegex, `$1${name}: ${testVal}$2`);
      } else {
        baseCurl += ` \\\n  -H '${name}: ${testVal.replace(/'/g, "'\\''")}'`;
      }
    } else if (pType === "query") {
      if (!sampleVal || sampleVal === "test") testVal = "1";
      // Find URL in curl command
      const urlMatch = baseCurl.match(/(['"])(https?:\/\/[^'"]+)\1/i);
      if (urlMatch) {
        const fullMatch = urlMatch[0];
        const quote = urlMatch[1];
        let originalUrl = urlMatch[2];
        const sep = originalUrl.includes("?") ? "&" : "?";
        const newUrl = `${originalUrl}${sep}${encodeURIComponent(name)}=${encodeURIComponent(testVal)}`;
        baseCurl = baseCurl.replace(fullMatch, `${quote}${newUrl}${quote}`);
      } else {
        baseCurl += ` \\\n  --data-urlencode '${name}=${testVal}'`;
      }
    } else if (pType === "json") {
      if (!sampleVal || sampleVal === "test") testVal = "true";
      // If JSON body exists in --data-raw '...'
      const dataMatch = baseCurl.match(/--data-raw\s+'([^']*)'/);
      if (dataMatch) {
        try {
          const parsed = JSON.parse(dataMatch[1]);
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            parsed[name] = testVal;
            const updated = JSON.stringify(parsed);
            baseCurl = baseCurl.replace(dataMatch[0], `--data-raw '${updated}'`);
          } else {
            baseCurl += ` \\\n  --data-raw '{"${name}": "${testVal}"}'`;
          }
        } catch (_) {
          baseCurl += ` \\\n  --data-raw '{"${name}": "${testVal}"}'`;
        }
      } else {
        if (!/-H\s+['"]Content-Type:/i.test(baseCurl)) {
          baseCurl += ` \\\n  -H 'Content-Type: application/json'`;
        }
        if (baseCurl.includes("-X GET")) {
          baseCurl = baseCurl.replace("-X GET", "-X POST");
        }
        baseCurl += ` \\\n  --data-raw '{"${name}": "${testVal}"}'`;
      }
    }

    return baseCurl;
  }

  function fuzzArjunCopyCurl(name, type, sampleVal) {
    const cmd = _fuzzBuildArjunCurl(name, type, sampleVal);
    if (!cmd) {
      fuzzToast("⚠️ Could not format cURL command");
      return;
    }
    _fuzzCopyToClipboard(cmd, `📋 Copied cURL command for '${name}' (${(type || "").toUpperCase()}) to clipboard!`);
  }

  function fuzzArjunAddSingleTarget(name, type) {
    if (!name) return;
    const exists = _fuzzDetectedPoints.some(p => (p.key === name || p.name === name) && p.type === type);
    if (!exists) {
      _fuzzDetectedPoints.push({
        id: `param_${type}_${name}_${Date.now()}`,
        type: type,
        key: name,
        name: name,
        value: "test",
        label: `${type.toUpperCase()}: ${name}`,
        enabled: true
      });
      _fuzzRenderPointsBar();
      _fuzzArjunRenderFoundParams(_fuzzArjunDiscovered);
      fuzzToast(`🎯 Added '${name}' to Injection Targets!`);
    } else {
      fuzzToast(`ℹ Target '${name}' is already in Injection Targets`);
    }
  }

  function fuzzArjunAddAllToTargets() {
    if (!_fuzzArjunDiscovered.length) return;
    let addedCount = 0;
    _fuzzArjunDiscovered.forEach(item => {
      const exists = _fuzzDetectedPoints.some(p => (p.key === item.name || p.name === item.name) && p.type === item.type);
      if (!exists) {
        _fuzzDetectedPoints.push({
          id: `param_${item.type}_${item.name}_${Date.now()}_${addedCount}`,
          type: item.type,
          key: item.name,
          name: item.name,
          value: item.sample_val || "test",
          label: `${item.type.toUpperCase()}: ${item.name}`,
          enabled: true
        });
        addedCount++;
      }
    });

    _fuzzRenderPointsBar();
    _fuzzArjunRenderFoundParams(_fuzzArjunDiscovered);
    fuzzSwitchTab("setup");
    fuzzToast(`🎯 Added ${addedCount} discovered parameter(s) to Fuzzer Targets!`);
  }

  function fuzzArjunClearLogs() {
    const term = fuzzEl("fuzz-arjun-terminal");
    if (term) term.innerHTML = `<div class="fuzz-term-line term-dim">[system] Logs cleared.</div>`;
  }

  function fuzzArjunCopyLogs() {
    const term = fuzzEl("fuzz-arjun-terminal");
    if (!term) return;
    const text = term.innerText;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        fuzzToast("📋 Copied Arjun logs to clipboard");
      });
    } else {
      fuzzToast("Logs selected — use Ctrl+C / Cmd+C to copy");
    }
  }

  function fuzzArjunResetData() {
    // 1. Stop any in-progress job & polling
    if (_fuzzArjunJobId) {
      fetch(`${FUZZ_BASE}/fuzzer/arjun/stop/${_fuzzArjunJobId}`, { method: "POST" }).catch(() => {});
      _fuzzArjunJobId = null;
    }
    _fuzzArjunStopPolling();
    _fuzzArjunSetRunningUi(false);

    // 2. Clear state variables
    _fuzzArjunLogsCount = 0;
    _fuzzArjunDiscovered = [];

    // 3. Clear stats pills & progress
    const statStatus = fuzzEl("fuzz-arjun-stat-status");
    const statBaseline = fuzzEl("fuzz-arjun-stat-baseline");
    const statProgress = fuzzEl("fuzz-arjun-stat-progress");
    const statFound = fuzzEl("fuzz-arjun-stat-found");
    const progressFill = fuzzEl("fuzz-arjun-progress-fill");

    if (statStatus) {
      statStatus.textContent = "Idle";
      statStatus.style.color = "var(--text2)";
    }
    if (statBaseline) statBaseline.textContent = "Baseline: —";
    if (statProgress) statProgress.textContent = "Tested: 0 / 0 (0%)";
    if (statFound) statFound.textContent = "✨ 0 Found";
    if (progressFill) progressFill.style.width = "0%";

    // 4. Clear discovered parameters list & tab badge
    _fuzzArjunRenderFoundParams([]);

    // 5. Reset terminal logs
    const term = fuzzEl("fuzz-arjun-terminal");
    if (term) {
      term.innerHTML = `<div class="fuzz-term-line term-dim">[system] Arjun parameter discovery engine initialized. Ready to scan.</div>`;
    }

    // 6. Update target display from setup
    fuzzUpdateArjunTargetDisplay();

    fuzzToast("🔄 Arjun scan data reset successfully");
  }

  // ── 2. PAYLOADS & ENDPOINTS VIEWER MODAL (Eye Button Popup) ────────────
  function fuzzOpenPayloadModal(catId, isEndpoint, ev) {
    if (ev) ev.stopPropagation();
    const modal = fuzzEl("fuzz-payloads-modal");
    if (!modal) return;

    let pack = null;
    let items = [];
    let isEp = !!isEndpoint;

    if (isEndpoint === "services") {
      pack = (window.SERVICES_ENDPOINT_PACKS || []).find((p) => p.id === catId);
      if (pack) {
        isEp = true;
        items = Array.isArray(pack.paths) ? pack.paths : [];
      }
    } else if (isEp) {
      pack = (window.INTR_ENDPOINT_PACKS || []).find((p) => p.id === catId) ||
             (window.SERVICES_ENDPOINT_PACKS || []).find((p) => p.id === catId);
      if (pack) {
        items = Array.isArray(pack.paths) ? pack.paths : [];
      }
    } else {
      pack = (window.INTR_VALUE_LISTS || []).find((p) => p.id === catId);
      if (pack) {
        items = Array.isArray(pack.payloads) ? pack.payloads : [];
      } else {
        // Fallback check in endpoint and services packs
        pack = (window.INTR_ENDPOINT_PACKS || []).find((p) => p.id === catId) ||
               (window.SERVICES_ENDPOINT_PACKS || []).find((p) => p.id === catId);
        if (pack) {
          isEp = true;
          items = Array.isArray(pack.paths) ? pack.paths : [];
        }
      }
    }

    if (!pack) return;

    _fuzzCurrentModalPack = { ...pack, isEndpoint: isEp, items: items };
    _fuzzCurrentModalPayloads = [...items];

    fuzzEl("fuzz-modal-title").textContent = pack.label + (isEp ? " Endpoints" : " Payloads");
    fuzzEl("fuzz-modal-sub").textContent = `ID: ${pack.id} • Group: ${pack.group || (isEp ? "Services" : "Injection")}`;
    fuzzEl("fuzz-modal-desc").textContent = isEp
      ? `Curated sensitive routes and discovery endpoints for ${pack.label}. The fuzzer probes these paths on the target service to uncover hidden administrative interfaces, configs, and debug APIs.`
      : (_FUZZ_CAT_DESCRIPTIONS[pack.id] ||
        `Clean functional test vectors targeting ${pack.label}. These strings will be auto-injected into detected parameters and headers.`);

    const searchInp = fuzzEl("fuzz-modal-search");
    if (searchInp) {
      searchInp.value = "";
      searchInp.placeholder = isEp ? `Search paths in ${pack.label}…` : `Search payloads in ${pack.label}…`;
    }

    _fuzzRenderModalPayloadList(_fuzzCurrentModalPayloads);

    modal.style.display = "flex";
    if (searchInp && typeof searchInp.focus === "function") {
      setTimeout(() => {
        try {
          searchInp.focus();
        } catch (_) {}
      }, 60);
    }
  }

  function fuzzCloseModal() {
    const modal = fuzzEl("fuzz-payloads-modal");
    if (modal) modal.style.display = "none";
  }

  function _fuzzRenderModalPayloadList(list) {
    const listEl = fuzzEl("fuzz-modal-list");
    const countEl = fuzzEl("fuzz-modal-count");
    if (!listEl) return;

    const total = _fuzzCurrentModalPack && _fuzzCurrentModalPack.items ? _fuzzCurrentModalPack.items.length : 0;
    const itemLabel = _fuzzCurrentModalPack && _fuzzCurrentModalPack.isEndpoint ? "paths" : "payloads";

    if (countEl) {
      countEl.textContent = `${list.length} / ${total} ${itemLabel}`;
    }

    if (!list.length) {
      listEl.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text3);font-size:11px;">No matching ${itemLabel} found</div>`;
      return;
    }

    listEl.innerHTML = list
      .map(
        (val, i) => `<div class="fuzz-modal-row">
        <span style="color:var(--text3);width:28px;font-size:10px;">#${i + 1}</span>
        <span class="fuzz-modal-row-val">${_fuzzEscapeHtml(val)}</span>
        <button type="button" class="fuzz-modal-copy-btn" onclick="fuzzCopyRow('${_fuzzEscapeAttr(val)}', this)">Copy</button>
      </div>`
      )
      .join("");
  }

  function fuzzFilterModal(query) {
    if (!_fuzzCurrentModalPack || !_fuzzCurrentModalPack.items) return;
    const q = (query || "").trim().toLowerCase();
    const filtered = q
      ? _fuzzCurrentModalPack.items.filter((p) => String(p).toLowerCase().includes(q))
      : _fuzzCurrentModalPack.items;
    _fuzzRenderModalPayloadList(filtered);
  }

  function _fuzzCopyToClipboard(text, successMsg, btn) {
    if (typeof navigator !== "undefined" && navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard
        .writeText(text)
        .then(() => {
          if (btn) _fuzzMarkBtnCopied(btn);
          if (successMsg) fuzzToast(successMsg);
        })
        .catch(() => {
          _fuzzFallbackCopy(text, successMsg, btn);
        });
    } else {
      _fuzzFallbackCopy(text, successMsg, btn);
    }
  }

  function _fuzzFallbackCopy(text, successMsg, btn) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      if (btn) _fuzzMarkBtnCopied(btn);
      if (successMsg) fuzzToast(successMsg);
    } catch (_) {
      fuzzToast("Failed to copy to clipboard");
    }
  }

  function _fuzzMarkBtnCopied(btn) {
    if (!btn) return;
    const old = btn.textContent;
    btn.textContent = "Copied!";
    btn.style.color = "#3fb950";
    setTimeout(() => {
      btn.textContent = old;
      btn.style.color = "";
    }, 1200);
  }

  function fuzzCopyAllModal() {
    if (!_fuzzCurrentModalPayloads || !_fuzzCurrentModalPayloads.length) return;
    const text = _fuzzCurrentModalPayloads.join("\n");
    const itemLabel = _fuzzCurrentModalPack && _fuzzCurrentModalPack.isEndpoint ? "endpoints" : "payloads";
    _fuzzCopyToClipboard(text, `Copied ${_fuzzCurrentModalPayloads.length} ${itemLabel} to clipboard!`);
  }

  function fuzzCopyRow(val, btn) {
    _fuzzCopyToClipboard(val, "", btn);
  }

  // ── 3. SMART CURL AUTO-DETECTOR & INTERACTIVE INJECTION TARGETS ──────────
  function fuzzLooksLikeCurl(text) {
    const t = String(text || "").trim();
    if (!t) return false;
    if (/^curl(?:\.exe)?\b/i.test(t)) return true;
    return /\n\s*-H\s+['"]/.test(t) || /\n\s*--header\s+['"]/.test(t) || /\n\s*--url\s+['"]/.test(t) || /\b--url\s+['"]/.test(t);
  }

  function fuzzParseCurlToHttpTemplate(curl) {
    let s = String(curl || "").trim();
    if (!s) return "";
    s = s.replace(/^[ \t]*```[a-z]*\s*\n?/i, "").replace(/\n?```[ \t]*$/, "");
    s = s.replace(/[ \t]*\\[ \t]*\r?\n[ \t]*/g, " ");
    s = s.replace(/[ \t]*`[ \t]*\r?\n[ \t]*/g, " ");
    s = s.replace(/[ \t]*\^[ \t]*\r?\n[ \t]*/g, " ");

    let method = "GET";
    let url = "";
    const headers = [];
    let body = "";

    // Method
    const mMatch = s.match(/(?:-X|--request)\s+['"]?([A-Za-z]+)['"]?/i);
    if (mMatch) method = mMatch[1].toUpperCase();

    // URL
    const urlFlagMatch = s.match(/--url\s+['"]([^'"]+)['"]/i) || s.match(/--url\s+([^\s'"]+)/i);
    if (urlFlagMatch) {
      url = urlFlagMatch[1];
    } else {
      const rawUrlMatch = s.match(/['"](https?:\/\/[^'"]+)['"]/i) || s.match(/\b(https?:\/\/[^\s'"]+)/i);
      if (rawUrlMatch) url = rawUrlMatch[1];
    }

    // Headers: -H 'key: value' or -H "key: value"
    const hRegex = /(?:-H|--header)\s+(?:'([^']*)'|"([^"]*)"|([^\s'"]+))/g;
    let hm;
    while ((hm = hRegex.exec(s)) !== null) {
      const h = (hm[1] !== undefined ? hm[1] : (hm[2] !== undefined ? hm[2] : hm[3] || "")).trim();
      if (h) {
        const ci = h.indexOf(":");
        if (ci > 0) {
          headers.push({ key: h.slice(0, ci).trim(), val: h.slice(ci + 1).trim() });
        } else if (h.endsWith(";")) {
          headers.push({ key: h.slice(0, -1).trim(), val: "" });
        }
      }
    }

    // Body
    const dRegex = /(?:-d|--data|--data-raw|--data-binary)\s+(?:'([\s\S]*?)'(?=\s+-[a-zA-Z]|\s*$)|"([\s\S]*?)"(?=\s+-[a-zA-Z]|\s*)|([^\s'"]+))/;
    const dm = s.match(dRegex);
    if (dm) {
      body = dm[1] !== undefined ? dm[1] : (dm[2] !== undefined ? dm[2] : dm[3]);
      if (!mMatch) method = "POST";
    }

    const lines = [`${method} ${url}`];
    headers.forEach((h) => {
      lines.push(`${h.key}: ${h.val}`);
    });
    if (body) {
      lines.push("");
      lines.push(body);
    }
    return lines.join("\n");
  }

  function fuzzEnsureHttpTemplate(opts) {
    const silent = !!(opts && opts.silent);
    const ta = fuzzEl("fuzz-curl-input");
    if (!ta) return false;
    const raw = ta.value || "";
    if (!fuzzLooksLikeCurl(raw)) return false;

    const tpl = fuzzParseCurlToHttpTemplate(raw);
    if (tpl && !fuzzLooksLikeCurl(tpl)) {
      ta.value = tpl;
      fuzzParseCurrentCurl();
      fuzzRefreshCurlHighlight();
      if (!silent) fuzzToast("Parsed cURL into raw HTTP details");
      return true;
    }
    return false;
  }

  function fuzzHttpTemplateToCurl(text) {
    const raw = String(text || "").trim();
    if (!raw) return "";
    if (fuzzLooksLikeCurl(raw)) return raw;

    const lines = raw.split(/\r?\n/);
    const firstLine = (lines[0] || "").trim();
    
    let method = "GET";
    let url = "";

    if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/i.test(firstLine)) {
      const parts = firstLine.split(/\s+/);
      method = (parts[0] || "GET").toUpperCase();
      url = (parts[1] || "").trim();
    } else {
      // Plain URL or host entered directly (e.g. https://dev.visionwaves.com)
      method = "GET";
      url = firstLine.split(/\s+/)[0].trim();
    }

    // Strip HTTP/1.1 or HTTP/2 protocol trailer if present
    url = url.replace(/\s+HTTP\/[0-9.]+$/i, "").trim();

    // Ensure valid URL scheme
    if (url && !url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
    }

    let curl = `curl -X ${method} '${url}'`;
    let inBody = false;
    const bodyLines = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!inBody && !line.trim()) {
        inBody = true;
        continue;
      }
      if (!inBody) {
        const ci = line.indexOf(":");
        if (ci > 0) {
          const k = line.slice(0, ci).trim();
          const v = line.slice(ci + 1).trim();
          curl += ` \\\n  -H '${k}: ${v.replace(/'/g, "'\\''")}'`;
        }
      } else {
        bodyLines.push(line);
      }
    }

    const body = bodyLines.join("\n").trim();
    if (body) {
      curl += ` \\\n  --data-raw '${body.replace(/'/g, "'\\''")}'`;
    }
    return curl;
  }

  function fuzzShowImportCurlModal() {
    const modal = fuzzEl("fuzz-curl-modal");
    const inp = fuzzEl("fuzz-curl-modal-input");
    const err = fuzzEl("fuzz-curl-modal-error");
    if (err) { err.textContent = ""; err.style.display = "none"; }
    if (inp) { inp.value = ""; }
    if (modal) {
      modal.style.display = "flex";
      setTimeout(() => { if (inp) inp.focus(); }, 50);
    }
  }

  function fuzzCloseCurlModal() {
    const modal = fuzzEl("fuzz-curl-modal");
    if (modal) modal.style.display = "none";
  }

  function fuzzImportCurlFromModal() {
    const inp = fuzzEl("fuzz-curl-modal-input");
    const err = fuzzEl("fuzz-curl-modal-error");
    const curl = (inp ? inp.value : "").trim();
    if (!curl) {
      if (err) {
        err.textContent = "Please paste a cURL command first.";
        err.style.display = "block";
      }
      return;
    }

    try {
      const tpl = fuzzParseCurlToHttpTemplate(curl);
      if (!tpl || fuzzLooksLikeCurl(tpl)) {
        throw new Error("Could not extract HTTP details from cURL");
      }
      const ta = fuzzEl("fuzz-curl-input");
      if (ta) {
        ta.value = tpl;
        fuzzParseCurrentCurl();
        fuzzRefreshCurlHighlight();
      }
      fuzzCloseCurlModal();
      fuzzToast("Imported and parsed cURL into HTTP details!");
    } catch (e) {
      if (err) {
        err.textContent = "Parse error: " + e.message;
        err.style.display = "block";
      }
    }
  }

  function fuzzMarkSelectionPosition() {
    const ta = fuzzEl("fuzz-curl-input");
    if (!ta) return;
    if (fuzzLooksLikeCurl(ta.value)) {
      fuzzEnsureHttpTemplate({ silent: true });
    }
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const val = ta.value;

    if (start === end) {
      fuzzToast("💡 Select any text in request first (e.g. endpoint path, param value), then click 'Mark § §'");
      return;
    }

    const selected = val.substring(start, end);
    const wrapped = selected.startsWith("§") && selected.endsWith("§")
      ? selected.slice(1, -1)
      : ("§" + selected + "§");

    ta.value = val.substring(0, start) + wrapped + val.substring(end);
    ta.focus();
    ta.setSelectionRange(start, start + wrapped.length);
    fuzzParseCurrentCurl();
    fuzzToast("🎯 Marked custom fuzz position: " + wrapped);
  }

  function fuzzMarkUrlEndpoint() {
    const ta = fuzzEl("fuzz-curl-input");
    if (!ta) return;
    if (fuzzLooksLikeCurl(ta.value)) {
      fuzzEnsureHttpTemplate({ silent: true });
    }
    let val = ta.value;
    if (!val.trim()) {
      fuzzToast("Paste a target request or cURL first");
      return;
    }

    // Match URL
    const urlMatch = val.match(/https?:\/\/[^\s'"?#]+/i);
    if (!urlMatch) {
      fuzzToast("No HTTP/HTTPS URL detected in cURL");
      return;
    }

    const fullUrl = urlMatch[0];
    try {
      const cleanUrl = fullUrl.replace(/§/g, "");
      const u = new URL(cleanUrl);
      const parts = u.pathname.split("/").filter(Boolean);

      if (!parts.length) {
        // Root path, append §FUZZ§
        const markedUrl = fullUrl.endsWith("/") ? `${fullUrl}§FUZZ§` : `${fullUrl}/§FUZZ§`;
        ta.value = val.replace(fullUrl, markedUrl);
        fuzzParseCurrentCurl();
        fuzzToast("Marked URL endpoint: §FUZZ§");
        return;
      }

      const lastSegment = parts[parts.length - 1];
      if (val.includes(`§${lastSegment}§`)) {
        // Already marked, un-mark it
        ta.value = val.replace(`§${lastSegment}§`, lastSegment);
        fuzzParseCurrentCurl();
        fuzzToast(`Unmarked URL endpoint '${lastSegment}'`);
        return;
      }

      // Mark the last endpoint segment
      const lastIndex = fullUrl.lastIndexOf(lastSegment);
      if (lastIndex !== -1) {
        const markedUrl = fullUrl.substring(0, lastIndex) + "§" + lastSegment + "§" + fullUrl.substring(lastIndex + lastSegment.length);
        ta.value = val.replace(fullUrl, markedUrl);
        fuzzParseCurrentCurl();
        fuzzToast(`🌐 Marked URL endpoint: §${lastSegment}§`);
      }
    } catch (_) {
      fuzzToast("Could not parse URL path");
    }
  }

  function fuzzClearPositions() {
    const ta = fuzzEl("fuzz-curl-input");
    if (!ta) return;
    if (!ta.value.includes("§")) {
      fuzzToast("No § position markers found in request");
      return;
    }
    ta.value = ta.value.replace(/§/g, "");
    fuzzParseCurrentCurl();
    fuzzToast("Cleared all § position markers (reverted to auto-detection)");
  }

  function fuzzParseCurrentCurl() {
    const raw = (fuzzEl("fuzz-curl-input") && fuzzEl("fuzz-curl-input").value) || "";
    const box = fuzzEl("fuzz-points-list");
    if (!box) return;

    if (!raw.trim()) {
      _fuzzDetectedPoints = [];
      box.innerHTML = `<span style="font-size:11px;color:var(--text3);">Paste a target request or cURL command above to auto-detect injection points</span>`;
      fuzzRefreshCurlHighlight();
      return;
    }

    // Preserve previously set enabled states for identical target keys
    const prevStates = {};
    _fuzzDetectedPoints.forEach((pt) => {
      prevStates[pt.id] = pt.enabled;
    });

    const newPoints = [];

    // 1. Check for manual §...§ position markers (Intruder Style)
    const markerMatches = [];
    const markerRegex = /§([^§]+)§/g;
    let mm;
    while ((mm = markerRegex.exec(raw)) !== null) {
      markerMatches.push({
        val: mm[1],
        index: mm.index
      });
    }

    if (markerMatches.length > 0) {
      markerMatches.forEach((m, idx) => {
        const id = `marker:${idx}:${m.val}`;
        newPoints.push({
          id: id,
          type: "marker",
          key: m.val,
          label: `§ Custom: ${m.val} §`,
          enabled: prevStates[id] !== undefined ? prevStates[id] : true
        });
      });
    }

    // Extraction: Check whether raw HTTP or cURL
    let method = "GET";
    let url = "";
    const headers = [];
    let bodyStr = "";

    const lines = raw.split(/\r?\n/);
    const firstLine = (lines[0] || "").trim();
    const httpFirstLineMatch = firstLine.match(/^([A-Za-z]+)\s+(https?:\/\/[^\s]+)/i);

    if (httpFirstLineMatch) {
      // ── Burp / Intruder Raw HTTP format ──
      method = httpFirstLineMatch[1].toUpperCase();
      url = httpFirstLineMatch[2];

      let inBody = false;
      const bodyLines = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (!inBody && !line.trim()) {
          inBody = true;
          continue;
        }
        if (!inBody) {
          const ci = line.indexOf(":");
          if (ci > 0) {
            const h = line.slice(0, ci).trim().replace(/§/g, "");
            if (h && !headers.includes(h) && !["Accept-Encoding", "Connection"].includes(h)) {
              headers.push(h);
            }
          }
        } else {
          bodyLines.push(line);
        }
      }
      bodyStr = bodyLines.join("\n").trim();
    } else {
      // ── cURL command format fallback ──
      if (/-X\s+([A-Z]+)/i.test(raw)) method = RegExp.$1.toUpperCase();
      else if (/--request\s+([A-Z]+)/i.test(raw)) method = RegExp.$1.toUpperCase();
      else if (/-d\s+|--data/i.test(raw)) method = "POST";

      const urlMatch = raw.match(/--url\s+['"]([^'"]+)['"]/i) || raw.match(/['"](https?:\/\/[^'"]+)['"]/i) || raw.match(/\bhttps?:\/\/[^\s'"]+/i);
      if (urlMatch) url = urlMatch[1] || urlMatch[0];

      const headerRegex = /(?:-H|--header)\s+['"]([^:]+):/gi;
      let hm;
      while ((hm = headerRegex.exec(raw)) !== null) {
        const h = hm[1].trim().replace(/§/g, "");
        if (!headers.includes(h) && !["Accept-Encoding", "Connection"].includes(h)) {
          headers.push(h);
        }
      }

      const dm1 = raw.match(/(?:-d|--data|--data-raw|--data-binary)\s+['"]([\s\S]*?)['"](?:\s|\\|$)/i);
      const dm2 = raw.match(/(?:-d|--data|--data-raw|--data-binary)\s+(\{[^\n\r]+\})/i);
      if (dm1) bodyStr = dm1[1];
      else if (dm2) bodyStr = dm2[1];
    }

    // 2. URL Path & Endpoint Target Extraction
    let host = "";
    if (url) {
      try {
        const cleanUrl = url.replace(/§/g, "");
        const u = new URL(cleanUrl);
        host = u.hostname;
        const parts = u.pathname.split("/").filter(Boolean);

        // Entire URL Endpoint Route Target
        if (parts.length > 0) {
          const epId = `endpoint:${u.pathname}`;
          newPoints.push({
            id: epId,
            type: "endpoint",
            key: u.pathname,
            label: `URL Path: ${u.pathname}`,
            enabled: prevStates[epId] !== undefined ? prevStates[epId] : true
          });
        }

        // Individual Path Segments
        parts.forEach((p) => {
          const pathId = `path:${p}`;
          newPoints.push({
            id: pathId,
            type: "path",
            key: p,
            label: `Path: /${p}`,
            enabled: prevStates[pathId] !== undefined ? prevStates[pathId] : false
          });
        });
      } catch (_) {}
    }

    // 3. Query Parameters
    const queryParams = [];
    if (url && url.includes("?")) {
      const qs = url.split("?")[1].split("#")[0].replace(/§/g, "");
      qs.split("&").forEach((pair) => {
        const k = pair.split("=")[0];
        if (k && !queryParams.includes(k)) queryParams.push(k);
      });
    }

    queryParams.forEach((q) => {
      const id = `query:${q}`;
      newPoints.push({
        id: id,
        type: "query",
        key: q,
        label: `Query: ?${q}`,
        enabled: prevStates[id] !== undefined ? prevStates[id] : true
      });
    });

    // 4. Body JSON / Form Keys
    const jsonKeys = [];
    if (bodyStr) {
      try {
        const parsed = JSON.parse(bodyStr.replace(/§/g, ""));
        if (typeof parsed === "object" && parsed !== null) {
          Object.keys(parsed).forEach((k) => jsonKeys.push(k));
        }
      } catch (_) {
        bodyStr.replace(/§/g, "").split("&").forEach((p) => {
          const k = p.split("=")[0].trim();
          if (k && !jsonKeys.includes(k) && !k.startsWith("{")) jsonKeys.push(k);
        });
      }
    }

    jsonKeys.forEach((k) => {
      const id = `json:${k}`;
      newPoints.push({
        id: id,
        type: "json",
        key: k,
        label: `Body JSON: ${k}`,
        enabled: prevStates[id] !== undefined ? prevStates[id] : true
      });
    });

    // 5. Custom Headers
    headers.forEach((h) => {
      const id = `header:${h}`;
      newPoints.push({
        id: id,
        type: "header",
        key: h,
        label: `Header: ${h}`,
        enabled: prevStates[id] !== undefined ? prevStates[id] : true
      });
    });

    // Preserve any dynamically discovered Arjun parameter targets
    const preservedArjunPoints = _fuzzDetectedPoints.filter((pt) => pt.id && pt.id.startsWith("param_"));
    preservedArjunPoints.forEach((apt) => {
      if (!newPoints.some((np) => (np.key === apt.key || np.name === apt.key) && np.type === apt.type)) {
        newPoints.push(apt);
      }
    });

    _fuzzDetectedPoints = newPoints;
    _fuzzRenderPointsBar(method, host);
    fuzzRefreshCurlHighlight();
    fuzzUpdateArjunTargetDisplay();
  }

  function _fuzzRenderPointsBar(method, host) {
    if (method) _fuzzLastMethod = method;
    if (host) _fuzzLastHost = host;
    const box = fuzzEl("fuzz-points-list");
    const summaryBadge = fuzzEl("fuzz-targets-summary");
    const quickActions = fuzzEl("fuzz-points-quick-actions");
    if (!box) return;

    if (!_fuzzDetectedPoints.length) {
      if (summaryBadge) {
        summaryBadge.textContent = "0 Targets Detected";
        summaryBadge.style.display = "inline-flex";
      }
      if (quickActions) quickActions.style.display = "none";
      box.innerHTML = `<div class="fuzz-targets-empty-hint"><span class="fuzz-targets-hint-icon">🎯</span><span>Paste a cURL command on the left to auto-detect query, body, headers, and endpoint paths</span></div>`;
      return;
    }

    const total = _fuzzDetectedPoints.length;
    const active = _fuzzDetectedPoints.filter((p) => p.enabled).length;
    const hasMarkers = _fuzzDetectedPoints.some((p) => p.type === "marker");

    if (summaryBadge) {
      summaryBadge.textContent = `${active}/${total} Active`;
      summaryBadge.style.display = "inline-flex";
    }
    if (quickActions) quickActions.style.display = "flex";

    let html = `<div class="fuzz-points-pills-row" id="fuzz-points-pills-container" style="${_fuzzTargetsCollapsed ? 'display:none;' : ''}">`;

    // Informational non-toggleable badges (Method, Host)
    html += `<span class="fuzz-point-pill fuzz-pill-info method-${_fuzzLastMethod.toLowerCase()}" title="Detected HTTP Method"><b>METHOD:</b> ${_fuzzLastMethod}</span>`;
    if (_fuzzLastHost) {
      html += `<span class="fuzz-point-pill fuzz-pill-info" title="Detected Target Host"><b>HOST:</b> ${_fuzzEscapeHtml(_fuzzLastHost)}</span>`;
    }

    // Render Target Pills
    _fuzzDetectedPoints.forEach((pt) => {
      const isOff = !pt.enabled;
      const statusIcon = pt.enabled
        ? `<span class="fuzz-pill-dot on" title="Active"></span>`
        : `<span class="fuzz-pill-dot off" title="Disabled"></span>`;
      html += `<span class="fuzz-point-pill is-interactive type-${pt.type}${isOff ? " is-disabled" : ""}"
                     id="fuzz-pt-${_fuzzEscapeAttr(pt.id)}"
                     onclick="fuzzTogglePoint('${_fuzzEscapeAttr(pt.id)}')"
                     title="${pt.enabled ? 'Active target: Click to exclude from fuzzing' : 'Disabled target: Click to enable for fuzzing'}">
        ${statusIcon}
        <span class="fuzz-pill-text">${_fuzzEscapeHtml(pt.label)}</span>
      </span>`;
    });

    html += `</div>`;
    box.innerHTML = html;
  }

  function fuzzToggleTargetsCollapse() {
    _fuzzTargetsCollapsed = !_fuzzTargetsCollapsed;
    const container = fuzzEl("fuzz-points-pills-container");
    const btn = fuzzEl("fuzz-targets-collapse-btn");
    if (container) {
      container.style.display = _fuzzTargetsCollapsed ? "none" : "flex";
    }
    if (btn) {
      btn.textContent = _fuzzTargetsCollapsed ? "▼ Expand" : "▲ Collapse";
    }
  }

  function fuzzTogglePoint(pointId) {
    const pt = _fuzzDetectedPoints.find((p) => p.id === pointId);
    if (!pt) return;
    pt.enabled = !pt.enabled;
    _fuzzRenderPointsBar();
    fuzzToast(`${pt.enabled ? "✅ Enabled" : "⏸️ Disabled"} target: ${pt.label}`);
  }

  function fuzzSelectAllPoints(enable) {
    _fuzzDetectedPoints.forEach((p) => (p.enabled = !!enable));
    _fuzzRenderPointsBar();
    fuzzToast(enable ? "All injection points enabled" : "All injection points disabled");
  }

  function fuzzSelectPointsByType(type) {
    _fuzzDetectedPoints.forEach((p) => {
      if (type === "endpoint") {
        p.enabled = p.type === "endpoint" || p.type === "path";
      } else if (type === "marker") {
        p.enabled = p.type === "marker";
      } else {
        p.enabled = p.type === type;
      }
    });
    _fuzzRenderPointsBar();
    const typeLabel = type === "endpoint" ? "URL Endpoint / Path" : (type === "marker" ? "Custom §marked§" : type.toUpperCase());
    fuzzToast(`Enabled only ${typeLabel} targets`);
  }

  function fuzzLoadSampleCurl() {
    const sample = `POST https://api.target.com/api/v1/users/profile?filter=active&debug=1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZGV2X3VzZXIiLCJyb2xlIjoidXNlciJ9.signature
X-Forwarded-For: 192.168.1.50
Content-Type: application/json

{"id": 42, "role": "user", "email": "test@target.com", "status": "active"}`;

    const inp = fuzzEl("fuzz-curl-input");
    if (inp) {
      inp.value = sample;
      fuzzParseCurrentCurl();
      fuzzRefreshCurlHighlight();
      fuzzToast("Sample request details loaded and analyzed!");
    }
  }

  function fuzzClearCurl() {
    const inp = fuzzEl("fuzz-curl-input");
    if (inp) inp.value = "";
    fuzzParseCurrentCurl();
  }

  // ── 4. SUB-TABS SWITCHING ───────────────────────────────────────────────
  function fuzzSwitchTab(tabName) {
    _fuzzActiveTab = tabName;
    ["setup", "results", "issues", "arjun"].forEach((t) => {
      const btn = fuzzEl(`fuzz-tab-btn-${t}`);
      const pane = fuzzEl(`fuzz-tab-${t}-content`);
      if (btn) btn.classList.toggle("active", t === tabName);
      if (pane) {
        pane.classList.toggle("active", t === tabName);
        pane.style.display = t === tabName ? "flex" : "none";
      }
    });
    if (tabName === "arjun") {
      fuzzUpdateArjunTargetDisplay();
    }
  }

  // ── 5. RESULTS TABLE RENDERING & FILTERING ──────────────────────────────
  function fuzzSetStatusFilter(filter, btn) {
    _fuzzCurrentStatusFilter = filter;
    document.querySelectorAll(".fuzz-filter-pill").forEach((b) => b.classList.remove("active"));
    if (btn) btn.classList.add("active");
    _fuzzApplyTableFilters();
  }

  function fuzzSetLengthFilter(val) {
    _fuzzCurrentLengthFilter = val == null ? "all" : String(val);
    const sel = fuzzEl("fuzz-filter-length");
    if (sel) {
      sel.value = _fuzzCurrentLengthFilter;
      sel.classList.toggle("has-filter", _fuzzCurrentLengthFilter !== "all");
    }
    _fuzzApplyTableFilters();
  }

  function _fuzzUpdateLengthFilterDropdown() {
    const sel = fuzzEl("fuzz-filter-length");
    if (!sel) return;

    const counts = {};
    (_fuzzCurrentResults || []).forEach((r) => {
      const len = r.length != null ? r.length : 0;
      counts[len] = (counts[len] || 0) + 1;
    });

    const sortedLens = Object.keys(counts).map(Number).sort((a, b) => a - b);
    const currVal = _fuzzCurrentLengthFilter;

    let html = '<option value="all">📏 Length: All</option>';
    sortedLens.forEach((len) => {
      const cnt = counts[len];
      const isSel = String(len) === String(currVal);
      html += `<option value="${len}"${isSel ? " selected" : ""}>${len} B (${cnt} hit${cnt === 1 ? "" : "s"})</option>`;
    });

    sel.innerHTML = html;
    if (currVal !== "all" && sortedLens.includes(Number(currVal))) {
      sel.value = currVal;
      sel.classList.add("has-filter");
    } else {
      sel.value = "all";
      sel.classList.remove("has-filter");
      _fuzzCurrentLengthFilter = "all";
    }
  }

  function fuzzFilterResultsTable(query) {
    _fuzzCurrentTextFilter = (query || "").trim();
    _fuzzApplyTableFilters();
  }

  function _fuzzApplyTableFilters() {
    let list = _fuzzCurrentResults.slice();
    if (_fuzzCurrentStatusFilter === "2xx") {
      list = list.filter((r) => r.status >= 200 && r.status < 300);
    } else if (_fuzzCurrentStatusFilter === "3xx") {
      list = list.filter((r) => r.status >= 300 && r.status < 400);
    } else if (_fuzzCurrentStatusFilter === "4xx") {
      list = list.filter((r) => r.status >= 400 && r.status < 500);
    } else if (_fuzzCurrentStatusFilter === "5xx") {
      list = list.filter((r) => r.status >= 500 && r.status < 600);
    } else if (_fuzzCurrentStatusFilter === "anomalies") {
      list = list.filter((r) => r.isAnomaly);
    }

    if (_fuzzCurrentLengthFilter && _fuzzCurrentLengthFilter !== "all") {
      const targetLen = Number(_fuzzCurrentLengthFilter);
      list = list.filter((r) => Number(r.length) === targetLen);
    }

    if (_fuzzCurrentTextFilter) {
      const q = _fuzzCurrentTextFilter.toLowerCase();
      list = list.filter((r) =>
        (r.method && r.method.toLowerCase().includes(q)) ||
        (r.location && r.location.toLowerCase().includes(q)) ||
        (r.payload && r.payload.toLowerCase().includes(q)) ||
        (r.anomaly && r.anomaly.toLowerCase().includes(q)) ||
        String(r.status).includes(q)
      );
    }

    // Column Sorting
    const k = _fuzzSort.key;
    const d = _fuzzSort.dir;
    list.sort((a, b) => {
      if (k === "id" || k === "status" || k === "length" || k === "time") {
        const na = Number(a[k]) || 0;
        const nb = Number(b[k]) || 0;
        return (na - nb) * d;
      }
      const sa = String(a[k] || "");
      const sb = String(b[k] || "");
      return sa.localeCompare(sb) * d;
    });

    _fuzzVisibleResults = list;

    // Preserve the user's selected row across incoming updates & filter changes
    let targetIdx = null;
    if (_fuzzSelectedResultId !== null && list.length > 0) {
      const foundIdx = list.findIndex(r => r.id === _fuzzSelectedResultId);
      if (foundIdx !== -1) targetIdx = foundIdx;
    }
    if (targetIdx === null && typeof _fuzzSelectedResultIdx === "number" && _fuzzSelectedResultIdx >= 0 && _fuzzSelectedResultIdx < list.length) {
      targetIdx = _fuzzSelectedResultIdx;
    }
    if (targetIdx === null && list.length > 0) {
      targetIdx = 0;
    }

    _fuzzSelectedResultIdx = targetIdx;
    if (targetIdx !== null && list[targetIdx]) {
      _fuzzSelectedResultId = list[targetIdx].id;
    }

    _fuzzRenderResultsTable(list);
    _fuzzPaintSortHeaders();

    if (targetIdx !== null && list[targetIdx]) {
      _fuzzRenderInspector(list[targetIdx]);
    } else {
      const reqEl = fuzzEl("fuzz-inspect-req-body");
      const respEl = fuzzEl("fuzz-inspect-resp-body");
      if (reqEl) reqEl.innerHTML = `<span style="color:var(--text3);font-size:11px;">No matching results for current filter</span>`;
      if (respEl) respEl.innerHTML = `<span style="color:var(--text3);font-size:11px;">No matching results for current filter</span>`;
    }
  }

  function fuzzSetSort(key) {
    if (_fuzzSort.key === key) {
      _fuzzSort.dir *= -1;
    } else {
      _fuzzSort.key = key;
      _fuzzSort.dir = 1;
    }
    _fuzzApplyTableFilters();
  }

  function _fuzzPaintSortHeaders() {
    const table = fuzzEl("fuzz-results-table");
    if (!table) return;
    table.querySelectorAll("th[data-sort]").forEach((el) => {
      const key = el.getAttribute("data-sort");
      const active = key === _fuzzSort.key;
      el.classList.toggle("sorted", active);
      let ico = el.querySelector(".fuzz-sort-ico");
      if (!ico) {
        ico = document.createElement("span");
        ico.className = "fuzz-sort-ico";
        el.appendChild(ico);
      }
      ico.textContent = active ? (_fuzzSort.dir > 0 ? " ▲" : " ▼") : " ⇅";
    });
  }

  // ── SYNTAX HIGHLIGHTING (Intruder Palette) ─────────────────────────────
  function fuzzColorizeEscaped(h) {
    if (!h) return "";
    // HTTP methods at line starts
    h = h.replace(/(^|\n)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\b/g,
      '$1<span class="intr-tok-method">$2</span>');
    // Header names at line start: Name:
    h = h.replace(/(^|\n)([A-Za-z][\w\-]*)(:)/g, '$1<span class="intr-tok-hk">$2</span>$3');
    // URLs
    h = h.replace(/(https?:\/\/[^\s"'\\]+)/g, '<span class="intr-tok-url">$1</span>');
    // Single-quoted strings
    h = h.replace(/('[^'\\]*(?:\\.[^'\\]*)*')/g, '<span class="intr-tok-str">$1</span>');
    // Double-quoted strings (&quot;…&quot;)
    h = h.replace(/(&quot;[^&]*(?:&(?!quot;)[^&]*)*&quot;)/g, '<span class="intr-tok-str">$1</span>');
    // JSON keys: "key":
    h = h.replace(/(<span class="intr-tok-str">&quot;[^&]+&quot;<\/span>)(\s*:)/g,
      (m, a, b) => a.replace('intr-tok-str', 'intr-tok-key') + b);
    // Bools / null
    h = h.replace(/\b(true|false)\b/g, '<span class="intr-tok-bool">$1</span>');
    h = h.replace(/\b(null)\b/g, '<span class="intr-tok-null">$1</span>');
    // Numbers
    h = h.replace(/\b(-?\d+(?:\.\d+)?)\b/g, '<span class="intr-tok-num">$1</span>');
    // Leftover curl
    h = h.replace(/\b(curl(?:\.exe)?)\b/gi, '<span class="intr-tok-curl">$1</span>');
    h = h.replace(/(^|[\s\\])(--?[A-Za-z][\w-]*)/g, '$1<span class="intr-tok-flag">$2</span>');
    return h;
  }

  function fuzzBuildHighlightHtml(text, opts) {
    const hideDelimiters = !!(opts && opts.hideDelimiters);
    const raw = String(text || "");
    if (!raw) return "";
    let out = "";
    const re = /§([\s\S]*?)§/g;
    let last = 0;
    let m;
    while ((m = re.exec(raw))) {
      if (m.index > last) {
        out += fuzzColorizeEscaped(_fuzzEscapeHtml(raw.slice(last, m.index)));
      }
      const shown = hideDelimiters ? m[1] : m[0];
      out += `<mark class="intr-mark">${_fuzzEscapeHtml(shown)}</mark>`;
      last = m.index + m[0].length;
    }
    if (last < raw.length) out += fuzzColorizeEscaped(_fuzzEscapeHtml(raw.slice(last)));
    return out;
  }

  function fuzzRefreshCurlHighlight() {
    const ta = fuzzEl("fuzz-curl-input");
    const hl = fuzzEl("fuzz-curl-input-hl");
    if (!ta || !hl) return;
    const text = ta.value || "";
    hl.innerHTML = fuzzBuildHighlightHtml(text) + (text.endsWith("\n") ? " " : "");
    hl.scrollTop = ta.scrollTop;
    hl.scrollLeft = ta.scrollLeft;
  }

  function fuzzHighlightPayloadsHtml(raw, payloads) {
    const text = String(raw || "");
    const needles = [];
    const seen = {};
    (payloads || []).forEach((p) => {
      const s = p == null ? "" : String(p).trim();
      if (!s || seen[s]) return;
      seen[s] = true;
      needles.push(s);
      try {
        const enc = encodeURIComponent(s);
        if (enc && enc !== s && !seen[enc]) { seen[enc] = true; needles.push(enc); }
      } catch (_) {}
      try {
        const dec = decodeURIComponent(s);
        if (dec && dec !== s && !seen[dec]) { seen[dec] = true; needles.push(dec); }
      } catch (_) {}
    });
    needles.sort((a, b) => b.length - a.length);
    if (!needles.length) return fuzzColorizeEscaped(_fuzzEscapeHtml(text));

    const ranges = [];
    needles.forEach((n) => {
      let from = 0;
      while (from <= text.length - n.length) {
        const i = text.indexOf(n, from);
        if (i < 0) break;
        const end = i + n.length;
        const overlap = ranges.some((r) => i < r.end && end > r.start);
        if (!overlap) ranges.push({ start: i, end, value: n });
        from = i + Math.max(n.length, 1);
      }
    });
    ranges.sort((a, b) => a.start - b.start);
    if (!ranges.length) return fuzzColorizeEscaped(_fuzzEscapeHtml(text));

    let out = "";
    let last = 0;
    ranges.forEach((r) => {
      if (r.start > last) out += fuzzColorizeEscaped(_fuzzEscapeHtml(text.slice(last, r.start)));
      out += `<span class="fuzz-highlight-payload">${_fuzzEscapeHtml(r.value)}</span>`;
      last = r.end;
    });
    if (last < text.length) out += fuzzColorizeEscaped(_fuzzEscapeHtml(text.slice(last)));
    return out;
  }

  function _fuzzRenderResultsTable(results) {
    const tbody = fuzzEl("fuzz-results-tbody");
    const countEl = fuzzEl("fuzz-results-total-count");
    if (!tbody) return;

    if (countEl) countEl.textContent = `${results.length} hits`;

    if (!results.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="fuzz-table-empty"><div class="fuzz-empty-box"><span style="font-size:22px;opacity:0.7">⚡</span><span style="font-weight:600;font-size:12px;color:var(--text2);margin-top:6px;">No Fuzzing Results Yet</span><span style="font-size:11px;color:var(--text3);margin-top:2px;">Configure target request on Setup and click "Start Auto-Fuzzing"</span></div></td></tr>`;
      _fuzzApplyEmptyInspector();
      return;
    }

    const wrap = tbody.closest ? tbody.closest(".fuzz-table-wrap") : null;
    const prevScrollTop = wrap ? wrap.scrollTop : 0;

    tbody.innerHTML = results
      .map(
        (r, idx) => `<tr id="fuzz-res-row-${idx}" class="${r.id === 0 ? 'fuzz-row-baseline' : ''} ${idx === _fuzzSelectedResultIdx ? 'selected' : ''}" onclick="fuzzSelectResultRow(${idx}, true)">
        <td style="color:var(--text3);">${r.id}</td>
        <td><b>${r.method}</b></td>
        <td style="color:var(--text2);">${r.id === 0 ? '<span style="color:#58a6ff;font-weight:600;">🎯 [Baseline]</span>' : _fuzzEscapeHtml(r.location)}</td>
        <td style="color:var(--blue);font-weight:600;">${_fuzzEscapeHtml(r.payload)}</td>
        <td><span class="fuzz-status-badge ${r.statusClass}">${r.status}</span></td>
        <td style="color:var(--text3);">${r.length}</td>
        <td style="color:var(--text3);">${r.time}ms</td>
        <td>${r.isAnomaly ? `<span class="fuzz-anomaly-tag">🚨 ${_fuzzEscapeHtml(r.anomaly)}</span>` : `<span style="color:var(--text3);">-</span>`}</td>
      </tr>`
      )
      .join("");

    if (wrap && prevScrollTop > 0) {
      wrap.scrollTop = prevScrollTop;
    }
  }

  function fuzzSelectResultRow(idx, shouldScroll = true) {
    const list = _fuzzVisibleResults && _fuzzVisibleResults.length ? _fuzzVisibleResults : _fuzzCurrentResults;
    if (idx < 0 || idx >= list.length) return;
    const r = list[idx];
    if (!r) return;

    _fuzzSelectedResultIdx = idx;
    _fuzzSelectedResultId = r.id;

    document.querySelectorAll(".fuzz-table tr").forEach((row) => row.classList.remove("selected"));
    const targetRow = fuzzEl(`fuzz-res-row-${idx}`);
    if (targetRow) {
      targetRow.classList.add("selected");
      if (shouldScroll && typeof targetRow.scrollIntoView === "function") {
        targetRow.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
    }

    _fuzzRenderInspector(r);
  }

  function _fuzzRenderInspector(r) {
    const reqEl = fuzzEl("fuzz-inspect-req-body");
    const respEl = fuzzEl("fuzz-inspect-resp-body");
    const renderFrame = fuzzEl("fuzz-inspect-render-frame");

    if (!r) {
      _fuzzApplyEmptyInspector();
      return;
    }

    if (reqEl) {
      reqEl.innerHTML = fuzzHighlightPayloadsHtml(r.req, [r.payload]);
    }
    if (respEl) {
      respEl.innerHTML = fuzzColorizeEscaped(_fuzzEscapeHtml(r.resp || ""));
    }
    if (renderFrame && renderFrame.style.display !== "none") {
      _fuzzRenderHtmlFrame(renderFrame, r);
    }
  }

  function _fuzzRenderHtmlFrame(frame, r) {
    if (!frame) return;
    if (!r || !r.resp) {
      frame.srcdoc = `<!doctype html><body style="margin:16px;font:13px system-ui;color:#888;background:#161b22;">No response body to render</body>`;
      return;
    }
    let body = r.resp;
    const headerSep = r.resp.indexOf("\r\n\r\n");
    if (headerSep !== -1) {
      body = r.resp.slice(headerSep + 4);
    } else {
      const headerSepN = r.resp.indexOf("\n\n");
      if (headerSepN !== -1) {
        body = r.resp.slice(headerSepN + 2);
      }
    }

    const looksHtml = /^\s*</.test(body) || /<html/i.test(body);
    if (looksHtml && body.trim()) {
      frame.srcdoc = body;
    } else if (body.trim()) {
      const esc = _fuzzEscapeHtml(body);
      frame.srcdoc = `<!doctype html><meta charset="utf-8"><body style="margin:14px;font:12px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap;background:#0d1117;color:#c9d1d9;">${esc}</body>`;
    } else {
      frame.srcdoc = `<!doctype html><body style="margin:16px;font:13px system-ui;color:#888;background:#161b22;">(Empty response body)</body>`;
    }
  }

  function fuzzInspectSwitchTab(pane) {
    const reqTab = fuzzEl("fuzz-inspect-tab-req");
    const respTab = fuzzEl("fuzz-inspect-tab-resp");
    const renderTab = fuzzEl("fuzz-inspect-tab-render");
    const reqBody = fuzzEl("fuzz-inspect-req-body");
    const respBody = fuzzEl("fuzz-inspect-resp-body");
    const renderFrame = fuzzEl("fuzz-inspect-render-frame");

    [reqTab, respTab, renderTab].forEach((t) => t && t.classList.remove("active"));
    if (reqBody) reqBody.style.display = "none";
    if (respBody) respBody.style.display = "none";
    if (renderFrame) renderFrame.style.display = "none";

    const list = _fuzzVisibleResults.length ? _fuzzVisibleResults : _fuzzCurrentResults;
    const r = _fuzzSelectedResultIdx !== null ? list[_fuzzSelectedResultIdx] : null;

    if (pane === "req") {
      if (reqTab) reqTab.classList.add("active");
      if (reqBody) reqBody.style.display = "block";
    } else if (pane === "resp") {
      if (respTab) respTab.classList.add("active");
      if (respBody) respBody.style.display = "block";
    } else if (pane === "render") {
      if (renderTab) renderTab.classList.add("active");
      if (renderFrame) {
        renderFrame.style.display = "block";
        _fuzzRenderHtmlFrame(renderFrame, r);
      }
    }
  }

  // ── 6. CURL EXPORT & REPEATER HELPERS ──────────────────────────────────
  function _fuzzRequestToCurl(rawReq) {
    if (!rawReq || !rawReq.trim()) return "";
    const lines = rawReq.split(/\r?\n/);
    const firstLine = (lines[0] || "").trim();
    const parts = firstLine.split(/\s+/);
    const method = parts[0] || "GET";
    const target = parts[1] || "";

    let host = "";
    const headers = [];
    let i = 1;
    for (; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) {
        i++;
        break;
      }
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        const hName = line.slice(0, colonIdx).trim();
        const hVal = line.slice(colonIdx + 1).trim();
        if (hName.toLowerCase() === "host") {
          host = hVal;
        }
        headers.push({ name: hName, value: hVal });
      }
    }

    const body = lines.slice(i).join("\n").trim();
    let fullUrl = target;
    if (!fullUrl.startsWith("http://") && !fullUrl.startsWith("https://")) {
      const scheme = host.includes("localhost") || host.startsWith("127.0.0.1") ? "http" : "https";
      fullUrl = `${scheme}://${host || "api.target.com"}${target.startsWith("/") ? "" : "/"}${target}`;
    }

    let cmd = `curl -i -s -k -X ${method} '${fullUrl}'`;
    headers.forEach((h) => {
      cmd += ` \\\n  -H '${h.name}: ${h.value.replace(/'/g, "'\\''")}'`;
    });

    if (body && !["GET", "HEAD"].includes(method.toUpperCase())) {
      cmd += ` \\\n  --data-raw '${body.replace(/'/g, "'\\''")}'`;
    }

    return cmd;
  }

  function _fuzzExtractUrlFromReq(rawReq) {
    if (!rawReq || !rawReq.trim()) return "";
    const lines = rawReq.split(/\r?\n/);
    const firstLine = (lines[0] || "").trim();
    const parts = firstLine.split(/\s+/);
    const target = parts[1] || "";
    let host = "";
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) break;
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0 && line.slice(0, colonIdx).trim().toLowerCase() === "host") {
        host = line.slice(colonIdx + 1).trim();
        break;
      }
    }
    if (target.startsWith("http://") || target.startsWith("https://")) return target;
    const scheme = host.includes("localhost") || host.startsWith("127.0.0.1") ? "http" : "https";
    return `${scheme}://${host || (_fuzzLastHost || "api.target.com")}${target.startsWith("/") ? "" : "/"}${target}`;
  }

  function fuzzCopyCurrentUrl() {
    const list = _fuzzVisibleResults.length ? _fuzzVisibleResults : _fuzzCurrentResults;
    if (_fuzzSelectedResultIdx === null || !list[_fuzzSelectedResultIdx]) {
      fuzzToast("No request selected in results table");
      return;
    }
    const r = list[_fuzzSelectedResultIdx];
    const url = r.url || _fuzzExtractUrlFromReq(r.req) || "";
    if (!url) {
      fuzzToast("Could not extract URL from request");
      return;
    }
    _fuzzCopyToClipboard(url, "🔗 Request URL copied to clipboard!");
  }

  function fuzzCopyCurrentCurl() {
    const list = _fuzzVisibleResults.length ? _fuzzVisibleResults : _fuzzCurrentResults;
    if (_fuzzSelectedResultIdx === null || !list[_fuzzSelectedResultIdx]) {
      fuzzToast("No request selected in results table");
      return;
    }
    const r = list[_fuzzSelectedResultIdx];
    const curl = _fuzzRequestToCurl(r.req);
    if (!curl) {
      fuzzToast("Could not format request into cURL");
      return;
    }
    _fuzzCopyToClipboard(curl, "📋 Request copied to clipboard as cURL!");
  }

  function fuzzCopyIssueCurl(resultIdx) {
    const r = _fuzzCurrentResults[resultIdx];
    if (!r) return;
    const curl = _fuzzRequestToCurl(r.req);
    _fuzzCopyToClipboard(curl, "📋 Issue request copied to clipboard as cURL!");
  }

  function fuzzSendIssueToRepeater(resultIdx) {
    const list = _fuzzVisibleResults.length ? _fuzzVisibleResults : _fuzzCurrentResults;
    const idx = typeof resultIdx === "number" ? resultIdx : (_fuzzSelectedResultIdx !== null ? _fuzzSelectedResultIdx : 0);
    const r = typeof resultIdx === "number" ? _fuzzCurrentResults[resultIdx] : list[idx];
    if (!r) {
      fuzzToast("⚠️ No request selected to send to Repeater");
      return;
    }

    const curl = _fuzzRequestToCurl(r.req);
    if (!curl) {
      fuzzToast("❌ Could not extract cURL from request");
      return;
    }

    // Do NOT switch tool! Silently populate APISphere in background
    try {
      if (typeof aspNewTab === "function") {
        aspNewTab();
      }
      if (typeof aspImportCurl === "function") {
        aspImportCurl(curl);
      }
      // Give tab a descriptive name
      const tabs = typeof _aspGetTabs === "function" ? _aspGetTabs() : null;
      const activeId = typeof _aspActiveTabId === "function" ? _aspActiveTabId() : null;
      if (tabs && activeId) {
        const t = tabs.find((x) => x.id === activeId);
        if (t) {
          t.name = `Fuzz #${r.id} (${r.method})`;
          if (typeof _aspSaveTabs === "function") _aspSaveTabs(tabs);
          if (typeof _aspRenderTabsBar === "function") _aspRenderTabsBar();
        }
      }
      if (typeof _aspFlushTab === "function") {
        _aspFlushTab();
      }
      fuzzToast(`⚡ Request #${r.id} (${r.method}) sent to Repeater! (Open APISphere to view)`);
    } catch (err) {
      console.error("Failed to load in Repeater:", err);
      fuzzToast("⚠️ Failed to send request to Repeater");
    }
  }

  // ── 7. ISSUES / ANOMALIES RENDERING ─────────────────────────────────────
  function _fuzzRenderIssuesList(issues) {
    const container = fuzzEl("fuzz-issues-list");
    const badge = fuzzEl("fuzz-issues-count-badge");
    if (!container) return;

    if (badge) {
      badge.textContent = issues.length;
      badge.classList.toggle("has-issues", issues.length > 0);
    }

    if (!issues.length) {
      container.innerHTML = `<div class="fuzz-empty-box" style="padding:48px 16px;"><span style="font-size:26px;opacity:0.7">🛡️</span><span style="font-weight:600;font-size:13px;color:var(--text2);margin-top:8px;">No Security Anomalies Detected</span><span style="font-size:11.5px;color:var(--text3);margin-top:3px;">Vulnerabilities, DBMS errors, and abnormal behaviors discovered during fuzzing will appear here.</span></div>`;
      return;
    }

    container.innerHTML = issues
      .map(
        (iss) => `<div class="fuzz-issue-card sev-${iss.sev}">
        <div class="fuzz-issue-header">
          <div class="fuzz-issue-title-group">
            <span class="fuzz-sev-badge sev-${iss.sev}">${iss.sev}</span>
            <span class="fuzz-issue-name">${_fuzzEscapeHtml(iss.title)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:6px">
            <button class="btn-sm" onclick="fuzzCopyIssueCurl(${iss.resultIdx})" style="font-size:11px;padding:3px 9px;background:var(--blue);color:#fff;border-color:var(--blue);display:inline-flex;align-items:center;gap:4px;" title="Copy reproducible cURL command">
              📋 Copy cURL
            </button>
            <button class="btn-sm" onclick="fuzzSendIssueToRepeater(${iss.resultIdx})" style="font-size:11px;padding:3px 9px;display:inline-flex;align-items:center;gap:4px;" title="Send request to Repeater for interactive testing">
              ⚡ Repeater
            </button>
          </div>
        </div>
        <div class="fuzz-issue-desc">${_fuzzEscapeHtml(iss.evidence)}</div>
        <div class="fuzz-issue-meta">
          <span><b>Endpoint:</b> ${_fuzzEscapeHtml(iss.endpoint)}</span>
          <span><b>Target Param:</b> ${_fuzzEscapeHtml(iss.location)}</span>
          <span><b>Fuzzed Payload:</b> <code style="color:var(--blue);">${_fuzzEscapeHtml(iss.payload)}</code></span>
        </div>
      </div>`
      )
      .join("");
  }

  // ── 8. START / STOP CONTROLS & POLLING ───────────────────────────────────
  function _fuzzStopPolling() {
    if (_fuzzPollTimer) {
      clearInterval(_fuzzPollTimer);
      _fuzzPollTimer = null;
    }
  }

  function _fuzzStopAttackUi(finalStatus) {
    _fuzzIsRunning = false;
    const startBtn = document.querySelector(".fuzz-btn-start");
    if (startBtn) {
      startBtn.disabled = false;
      startBtn.textContent = "▶ Start Auto-Fuzzing";
    }
    const stopBtn = fuzzEl("fuzz-stop-btn");
    if (stopBtn) {
      stopBtn.disabled = true;
      stopBtn.classList.remove("is-active");
      if (finalStatus === "finished") {
        stopBtn.innerHTML = "✓ Finished";
        stopBtn.classList.add("is-finished");
      } else if (finalStatus === "stopped") {
        stopBtn.innerHTML = "⏹ Stopped";
        stopBtn.classList.remove("is-finished");
      } else {
        stopBtn.innerHTML = "⏹ Stop Attack";
        stopBtn.classList.remove("is-finished");
      }
      setTimeout(() => {
        if (!_fuzzIsRunning && stopBtn) {
          stopBtn.innerHTML = "⏹ Stop Attack";
          stopBtn.classList.remove("is-finished");
        }
      }, 4000);
    }
  }

  function _fuzzStartPolling() {
    _fuzzStopPolling();
    _fuzzPollTimer = setInterval(async () => {
      if (!_fuzzJobId) return;
      try {
        const since = _fuzzCurrentResults.length;
        const res = await fetch(`${FUZZ_BASE}/fuzzer/results/${_fuzzJobId}?since=${since}`);
        if (!res.ok) return;
        const data = await res.json();

        if (data.results && data.results.length > 0) {
          _fuzzCurrentResults = _fuzzCurrentResults.concat(data.results);
          _fuzzUpdateLengthFilterDropdown();
          _fuzzApplyTableFilters();
        }

        if (data.issues) {
          _fuzzCurrentIssues = data.issues;
          _fuzzRenderIssuesList(_fuzzCurrentIssues);
        }

        if (data.status === "finished" || data.status === "stopped" || data.status === "error") {
          _fuzzStopPolling();
          _fuzzStopAttackUi(data.status);
          const anomCount = (_fuzzCurrentIssues && _fuzzCurrentIssues.length) || 0;
          fuzzToast(
            data.status === "stopped"
              ? "⏹ Fuzzing stopped by user."
              : `✅ Fuzzing complete! ${_fuzzCurrentResults.length} requests sent (${anomCount} anomalies).`
          );
        }
      } catch (e) {
        console.warn("Fuzzer poll error:", e);
      }
    }, 350);
  }

  async function fuzzStartAttack() {
    if (_fuzzIsRunning) {
      fuzzToast("Fuzzing is already in progress!");
      return;
    }

    const rawReq = (fuzzEl("fuzz-curl-input") && fuzzEl("fuzz-curl-input").value) || "";
    if (!rawReq.trim()) {
      fuzzToast("⚠️ Please paste a target request or cURL first");
      return;
    }

    const payloadCurl = fuzzHttpTemplateToCurl(rawReq);

    const enabledPoints = _fuzzDetectedPoints.filter((p) => p.enabled);
    if (_fuzzDetectedPoints.length > 0 && enabledPoints.length === 0) {
      fuzzToast("⚠️ No injection points selected! Click on pills to enable targets.");
      return;
    }

    // Collect Injection Payloads from selected categories (Deduplicated)
    const injectionPayloads = [];
    const seenInj = new Set();
    const addInjection = (item) => {
      if (typeof item === "string") {
        const s = item.trim();
        if (s && !seenInj.has(s)) {
          seenInj.add(s);
          injectionPayloads.push(s);
        }
      }
    };

    const payloadPacks = (window.INTR_VALUE_LISTS || []).filter(
      (p) => Array.isArray(p.payloads) && p.group !== "Values"
    );
    payloadPacks.forEach((p) => {
      if (_fuzzCategoriesSel[p.id]) {
        p.payloads.forEach(addInjection);
      }
    });

    // Collect Endpoint Payloads from selected endpoint packs (Deduplicated)
    const endpointPayloads = [];
    const seenEp = new Set();
    const addEndpoint = (item) => {
      if (typeof item === "string") {
        const s = item.trim();
        if (s && !seenEp.has(s)) {
          seenEp.add(s);
          endpointPayloads.push(s);
        }
      }
    };

    const endpointPacks = window.INTR_ENDPOINT_PACKS || [];
    endpointPacks.forEach((p) => {
      if (_fuzzEndpointPacksSel[p.id] && Array.isArray(p.paths)) {
        p.paths.forEach(addEndpoint);
      }
    });

    // Collect Services Endpoints from selected services packs (Deduplicated)
    const servicesPacks = window.SERVICES_ENDPOINT_PACKS || [];
    servicesPacks.forEach((p) => {
      if (_fuzzServicesPacksSel[p.id] && Array.isArray(p.paths)) {
        p.paths.forEach(addEndpoint);
      }
    });

    // Collect Manual / Custom Payloads
    const manualPayloads = (_fuzzManualPayloads || []).filter(
      (p) => typeof p === "string" && p.trim() !== ""
    );
    manualPayloads.forEach(addInjection);

    // If endpoint targets are enabled, also include manual payloads in endpointPayloads
    const hasEndpointTarget = enabledPoints.some((p) => p.type === "endpoint" || p.type === "path");
    if (hasEndpointTarget && manualPayloads.length > 0) {
      manualPayloads.forEach(addEndpoint);
    }

    if (!injectionPayloads.length && !endpointPayloads.length) {
      fuzzToast("⚠️ Please select at least one Attack Category or provide Custom / Manual Payloads!");
      return;
    }

    const delayMs = parseInt(fuzzEl("fuzz-delay") ? fuzzEl("fuzz-delay").value : "0", 10) || 0;
    const threads = parseInt(fuzzEl("fuzz-threads") ? fuzzEl("fuzz-threads").value : "5", 10) || 5;
    const randomize = !!(fuzzEl("fuzz-randomize") && fuzzEl("fuzz-randomize").checked);

    _fuzzIsRunning = true;
    const startBtn = document.querySelector(".fuzz-btn-start");
    if (startBtn) {
      startBtn.disabled = true;
      startBtn.textContent = "⏳ Fuzzing Active...";
    }
    const stopBtn = fuzzEl("fuzz-stop-btn");
    if (stopBtn) {
      stopBtn.disabled = false;
      stopBtn.classList.remove("is-finished");
      stopBtn.classList.add("is-active");
      stopBtn.innerHTML = "⏹ Stop Attack";
    }

    _fuzzCurrentResults = [];
    _fuzzVisibleResults = [];
    _fuzzCurrentIssues = [];
    _fuzzCurrentLengthFilter = "all";
    _fuzzUpdateLengthFilterDropdown();
    _fuzzSelectedResultIdx = null;
    _fuzzSelectedResultId = null;
    _fuzzRenderResultsTable([]);
    _fuzzRenderIssuesList([]);
    fuzzSwitchTab("results");

    const totalCount = injectionPayloads.length + endpointPayloads.length;
    const targetMsg = enabledPoints.length > 0 ? `across ${enabledPoints.length} active target(s)` : "on target";
    fuzzToast(`🚀 Starting Auto-Fuzzer with ${totalCount.toLocaleString()} payload(s) ${targetMsg} (Threads: ${threads}, Delay: ${delayMs}ms)...`);

    const urlEncode = !!(fuzzEl("fuzz-url-encode") && fuzzEl("fuzz-url-encode").checked);
    const urlChars = (fuzzEl("fuzz-url-chars") && fuzzEl("fuzz-url-chars").value) || "";

    try {
      const res = await fetch(`${FUZZ_BASE}/fuzzer/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          curl: payloadCurl,
          targets: enabledPoints.length > 0 ? enabledPoints : _fuzzDetectedPoints,
          injection_payloads: injectionPayloads,
          endpoint_payloads: endpointPayloads,
          threads: threads,
          delay_ms: delayMs,
          randomize: randomize,
          url_encode: urlEncode,
          url_encode_chars: urlChars
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server responded with status ${res.status}`);
      }

      const data = await res.json();
      _fuzzJobId = data.job_id;
      _fuzzStartPolling();
    } catch (err) {
      _fuzzStopAttackUi("error");
      fuzzToast(`❌ Failed to start fuzzer: ${err.message}`);
    }
  }

  function fuzzStopAttack() {
    const stopBtn = fuzzEl("fuzz-stop-btn");
    if (stopBtn) {
      stopBtn.disabled = true;
      stopBtn.innerHTML = "⏹ Stopping...";
    }
    if (_fuzzJobId) {
      fetch(`${FUZZ_BASE}/fuzzer/stop/${_fuzzJobId}`, { method: "POST" }).catch(() => {});
    }
    _fuzzStopPolling();
    _fuzzStopAttackUi("stopped");
    fuzzToast("Fuzzing attack stopped.");
  }

  // ── 9. EVENT LISTENERS & RESIZERS ───────────────────────────────────────
  function _fuzzInitEvents() {
    const curlInput = fuzzEl("fuzz-curl-input");
    if (curlInput) {
      curlInput.addEventListener("paste", () => {
        setTimeout(() => {
          if (fuzzLooksLikeCurl(curlInput.value)) {
            fuzzEnsureHttpTemplate({ silent: false });
          } else {
            fuzzParseCurrentCurl();
            fuzzRefreshCurlHighlight();
          }
        }, 15);
      });
      curlInput.addEventListener("input", () => {
        if (fuzzLooksLikeCurl(curlInput.value)) {
          fuzzEnsureHttpTemplate({ silent: true });
        } else {
          fuzzParseCurrentCurl();
          fuzzRefreshCurlHighlight();
        }
      });
      curlInput.addEventListener("scroll", () => {
        const hl = fuzzEl("fuzz-curl-input-hl");
        if (hl) {
          hl.scrollTop = curlInput.scrollTop;
          hl.scrollLeft = curlInput.scrollLeft;
        }
      });
    }

    // Modal Esc key listener & Results table Arrow navigation
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        const payModal = fuzzEl("fuzz-payloads-modal");
        if (payModal && payModal.style.display === "flex") {
          fuzzCloseModal();
        }
        const curlModal = fuzzEl("fuzz-curl-modal");
        if (curlModal && curlModal.style.display === "flex") {
          fuzzCloseCurlModal();
        }
        const manualModal = fuzzEl("fuzz-manual-paste-modal");
        if (manualModal && manualModal.style.display === "flex") {
          fuzzCloseManualPasteModal();
        }
        const arjunModal = fuzzEl("fuzz-arjun-modal");
        if (arjunModal && arjunModal.style.display === "flex") {
          fuzzCloseArjunModal();
        }
        return;
      }

      if (e.key !== "ArrowUp" && e.key !== "ArrowDown" && e.key !== "PageUp" && e.key !== "PageDown" && e.key !== "Home" && e.key !== "End") return;

      // Ensure Fuzzer tool and Live Results tab are visible
      const tool = fuzzEl("tool-fuzzer");
      const tabContent = fuzzEl("fuzz-tab-results-content");
      const isToolVisible = tool && (tool.classList.contains("active") || tool.style.display === "flex" || (window.getComputedStyle && window.getComputedStyle(tool).display !== "none"));
      const isTabVisible = _fuzzActiveTab === "results" || (tabContent && (tabContent.classList.contains("active") || tabContent.style.display === "flex"));
      if (!isToolVisible || !isTabVisible) return;

      // Ignore when user is typing inside an input/textarea/select/modal
      const t = e.target;
      const tag = t && t.tagName ? t.tagName.toLowerCase() : "";
      if (tag === "input" || tag === "textarea" || tag === "select" || (t && t.isContentEditable)) return;
      if (t && t.closest && t.closest("#fuzz-inspect-req-body, #fuzz-inspect-resp-body, #fuzz-inspect-render-frame, #fuzz-payloads-modal")) return;

      const list = _fuzzVisibleResults.length ? _fuzzVisibleResults : _fuzzCurrentResults;
      if (!list || !list.length) return;

      e.preventDefault();
      e.stopPropagation();

      let cur = typeof _fuzzSelectedResultIdx === "number" ? _fuzzSelectedResultIdx : 0;
      let next = cur;
      if (e.key === "ArrowDown") next = cur + 1;
      else if (e.key === "ArrowUp") next = cur - 1;
      else if (e.key === "PageDown") next = Math.min(list.length - 1, cur + 10);
      else if (e.key === "PageUp") next = Math.max(0, cur - 10);
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = list.length - 1;

      if (next < 0) next = 0;
      if (next >= list.length) next = list.length - 1;

      fuzzSelectResultRow(next, true);
    });

    // Draggable Split Divider Resizers (Intruder Style) - 50-50 fixed split per user request
    // _fuzzBindColResize("fuzz-setup-hresize", "fuzz-pane-request", "fuzz-pane-config", "fuzz-setup-split", 260, 260);
    _fuzzBindRowResize("fuzz-results-vresize", "fuzz-table-pane", "fuzz-inspect-pane", "fuzz-results-split", 130, 130);

    // Bind Manual Payloads Events
    _fuzzBindManualListEvents();
    const addInp = fuzzEl("fuzz-manual-add-input");
    if (addInp && !addInp._fuzzBound) {
      addInp._fuzzBound = true;
      addInp.addEventListener("paste", (pev) => {
        const ptext = (pev.clipboardData || window.clipboardData).getData("text");
        if (ptext && ptext.includes("\n")) {
          pev.preventDefault();
          const lines = _fuzzSplitLines(ptext).filter((l) => l.trim() !== "");
          if (lines.length > 0) {
            _fuzzAppendManualPayloads(lines);
            fuzzToast(`📋 Added ${lines.length} manual payload(s)`);
          }
        }
      });
    }
  }

  function _fuzzBindRowResize(handleId, topId, bottomId, splitId, minTop, minBottom) {
    let handle = fuzzEl(handleId);
    if (!handle && handleId === "fuzz-results-vresize") {
      handle = fuzzEl("fuzz-results-hresize");
    }
    const top = fuzzEl(topId);
    const bottom = fuzzEl(bottomId);
    const split = fuzzEl(splitId);
    if (!handle || !top || !bottom || !split || handle._fuzzBound) return;
    handle._fuzzBound = true;
    let dragging = false;
    let startY = 0;
    let startTop = 0;

    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragging = true;
      handle.classList.add("as-dragging");
      document.body.style.cursor = "row-resize";
      document.body.style.userSelect = "none";
      startY = e.clientY;
      startTop = top.getBoundingClientRect().height;
    });

    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      const totalH = split.getBoundingClientRect().height;
      const handleH = handle.getBoundingClientRect().height || 6;
      let nt = startTop + (e.clientY - startY);
      const minT = minTop || 120;
      const minB = minBottom || 120;
      nt = Math.max(minT, Math.min(totalH - handleH - minB, nt));
      top.style.flex = "none";
      bottom.style.flex = "1 1 0";
      top.style.height = ((nt / totalH) * 100) + "%";
    });

    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    });
  }

  function _fuzzBindColResize(handleId, leftId, rightId, splitId, minLeft, minRight) {
    const handle = fuzzEl(handleId);
    const left = fuzzEl(leftId);
    const right = fuzzEl(rightId);
    const split = fuzzEl(splitId);
    if (!handle || !left || !right || !split || handle._fuzzBound) return;
    handle._fuzzBound = true;
    let dragging = false;
    let startX = 0;
    let startLeft = 0;

    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragging = true;
      handle.classList.add("as-dragging");
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      startX = e.clientX;
      startLeft = left.getBoundingClientRect().width;
    });

    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      const total = split.getBoundingClientRect().width;
      const handleW = handle.getBoundingClientRect().width || 6;
      let nl = startLeft + (e.clientX - startX);
      const minL = minLeft || 240;
      const minR = minRight || 240;
      nl = Math.max(minL, Math.min(total - handleW - minR, nl));
      left.style.flex = "none";
      right.style.flex = "1 1 0";
      left.style.width = ((nl / total) * 100) + "%";
    });

    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    });
  }

  // ── 10. STANDALONE HTML REPORT EXPORTER ──────────────────────────────────
  async function fuzzDownloadHtmlReport() {
    if (!_fuzzCurrentResults || !_fuzzCurrentResults.length) {
      fuzzToast("⚠️ No fuzzing results to export yet. Run an attack first!");
      return;
    }
    const results = _fuzzCurrentResults;
    const issues = _fuzzCurrentIssues || [];
    const html = _fuzzGenHtmlReport(results, issues);
    const ts = new Date().toISOString().replace(/[:.]/g, "").substring(0, 15);
    const filename = `api_fuzzer_report_${ts}.html`;

    if (window.pywebview?.api?.save_file) {
      try {
        await window.pywebview.api.save_file(html, filename);
        fuzzToast(`HTML report saved: ${filename}`);
        return;
      } catch (_) {}
    }

    try {
      const blob = new Blob([html], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        a.remove();
        URL.revokeObjectURL(url);
      }, 1000);
      fuzzToast(`⬇ HTML report exported: ${filename}`);
    } catch (_) {
      fuzzToast("Failed to download HTML report");
    }
  }

  function _fuzzGenHtmlReport(results, issues) {
    const now = new Date().toLocaleString();
    const total = results.length;
    const totalAnomalies = results.filter((r) => r.isAnomaly).length;
    const critCount = issues.filter((i) => i.sev === "critical").length;
    const highCount = issues.filter((i) => i.sev === "high").length;
    const avgTime = Math.round(results.reduce((acc, r) => acc + (r.time || 0), 0) / (total || 1));
    const count2xx = results.filter((r) => r.status >= 200 && r.status < 300).length;
    const count3xx = results.filter((r) => r.status >= 300 && r.status < 400).length;
    const count4xx = results.filter((r) => r.status >= 400 && r.status < 500).length;
    const count5xx = results.filter((r) => r.status >= 500).length;
    const baseTargetUrl = _fuzzLastHost ? ((_fuzzLastHost.startsWith("http://") || _fuzzLastHost.startsWith("https://") ? "" : "https://") + _fuzzLastHost) : "";

    const lengthCounts = {};
    results.forEach((r) => {
      const len = r.length != null ? r.length : 0;
      lengthCounts[len] = (lengthCounts[len] || 0) + 1;
    });
    const sortedLengths = Object.keys(lengthCounts).map(Number).sort((a, b) => a - b);
    const lengthOptionsHtml = [
      '<option value="all">📏 Length: All</option>',
      ...sortedLengths.map(
        (len) => `<option value="${len}">${len} B (${lengthCounts[len]} hit${lengthCounts[len] === 1 ? "" : "s"})</option>`
      )
    ].join("");

    const issuesHtml = issues
      .map((iss, i) => {
        const sevColor = iss.sev === "critical" ? "#f85149" : (iss.sev === "high" ? "#ff7b72" : "#e3b341");
        const issUrl = iss.url || (iss.endpoint ? iss.endpoint.replace(/^[A-Za-z]+\s+/, "") : "") || baseTargetUrl;
        return `<div class="issue-card" style="border-left: 4px solid ${sevColor};">
          <div class="issue-header">
            <span class="sev-badge" style="background:${sevColor}22;color:${sevColor};">${_fuzzEscapeHtml(iss.sev.toUpperCase())}</span>
            <span class="issue-title">#${i + 1} ${_fuzzEscapeHtml(iss.title)}</span>
          </div>
          <div class="issue-meta">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <b>Target Endpoint:</b> <code>${_fuzzEscapeHtml(iss.endpoint || issUrl)}</code>
              ${issUrl ? `<button type="button" class="btn-copy-url" onclick="copyUrl('${_fuzzEscapeAttr(issUrl)}', this)" title="Copy URL">📋 Copy URL</button>` : ""}
            </div>
            <div><b>Target Parameter / Location:</b> <code>${_fuzzEscapeHtml(iss.location)}</code></div>
            <div><b>Injected Payload:</b> <code style="color:#58a6ff">${_fuzzEscapeHtml(iss.payload)}</code></div>
          </div>
          <div class="issue-evidence">${_fuzzEscapeHtml(iss.evidence)}</div>
        </div>`;
      })
      .join("");

    const rowsHtml = results
      .map((r) => {
        const scColor = r.status >= 500 ? "#f85149" : (r.status >= 400 ? "#e3b341" : (r.status >= 300 ? "#d29922" : "#3fb950"));
        const anomalyHtml = r.isAnomaly
          ? `<span class="anomaly-tag">🚨 ${_fuzzEscapeHtml(r.anomaly)}</span>`
          : `<span style="color:#6e7681">-</span>`;
        const rUrl = r.url || _fuzzExtractUrlFromReq(r.req) || baseTargetUrl;
        return `<tr data-status="${r.status}" data-length="${r.length != null ? r.length : 0}" data-anomaly="${r.isAnomaly ? 'true' : 'false'}">
          <td>${r.id}</td>
          <td><b>${_fuzzEscapeHtml(r.method)}</b></td>
          <td style="color:#8b949e">${_fuzzEscapeHtml(r.location)}</td>
          <td style="font-family:monospace;color:#58a6ff">${_fuzzEscapeHtml(r.payload)}</td>
          <td><span class="status-pill" style="color:${scColor};border-color:${scColor}44;background:${scColor}18">${r.status}</span></td>
          <td style="color:#8b949e">${r.length} B</td>
          <td style="color:#8b949e">${r.time}ms</td>
          <td>${anomalyHtml}</td>
          <td style="text-align:center">
            ${rUrl ? `<button type="button" class="btn-copy-url" onclick="copyUrl('${_fuzzEscapeAttr(rUrl)}', this)" title="Copy target URL">📋 Copy URL</button>` : '<span style="color:#6e7681">-</span>'}
          </td>
        </tr>`;
      })
      .join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Sentinel — Auto-Fuzzing & Vulnerability Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --bg2: #161b22;
      --bg3: #21262d;
      --border: #30363d;
      --text: #c9d1d9;
      --text2: #8b949e;
      --text3: #6e7681;
      --blue: #58a6ff;
      --red: #f85149;
      --green: #3fb950;
      --orange: #ffa657;
      --yellow: #e3b341;
      --mono: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 13px;
      line-height: 1.5;
      padding: 24px 32px;
    }
    .header-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 12px;
    }
    .logo-title {
      font-size: 18px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .report-date {
      font-size: 12px;
      color: var(--text2);
      margin-top: 2px;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }
    .stat-val {
      font-size: 24px;
      font-weight: 700;
      font-family: var(--mono);
      color: #fff;
    }
    .stat-lbl {
      font-size: 11.5px;
      color: var(--text2);
      margin-top: 4px;
    }
    .section-title {
      font-size: 15px;
      font-weight: 600;
      color: #fff;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .issue-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 12px;
    }
    .issue-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }
    .sev-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      letter-spacing: 0.5px;
    }
    .issue-title {
      font-size: 13.5px;
      font-weight: 600;
      color: #fff;
    }
    .issue-meta {
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11.5px;
      color: var(--text2);
      background: var(--bg3);
      padding: 8px 12px;
      border-radius: 6px;
      margin-bottom: 8px;
      font-family: var(--mono);
    }
    .issue-evidence {
      font-size: 12px;
      color: var(--text);
    }
    .results-table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg2);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11.5px;
      text-align: left;
    }
    th {
      background: var(--bg3);
      color: var(--text2);
      font-weight: 600;
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    th.sortable {
      cursor: pointer;
      user-select: none;
      transition: background 0.15s ease, color 0.15s ease;
    }
    th.sortable:hover {
      background: var(--border);
      color: #fff;
    }
    th.sortable .sort-ico {
      font-size: 10px;
      margin-left: 4px;
      color: var(--text3);
    }
    th.sortable.sorted .sort-ico {
      color: var(--blue);
      font-weight: 700;
    }
    td {
      padding: 7px 10px;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      white-space: nowrap;
    }
    tr:last-child td { border-bottom: none; }
    .status-pill {
      font-size: 10.5px;
      font-weight: 700;
      padding: 1px 6px;
      border-radius: 4px;
      border: 1px solid transparent;
      font-family: var(--mono);
    }
    .anomaly-tag {
      font-size: 10.5px;
      color: #ff7b72;
      background: rgba(248,81,73,0.15);
      padding: 2px 6px;
      border-radius: 3px;
      font-weight: 600;
    }
    .filter-pills {
      display: flex;
      align-items: center;
      gap: 5px;
      flex-wrap: wrap;
    }
    .filter-pill {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 5px;
      color: var(--text2);
      font-size: 11.5px;
      padding: 4px 10px;
      cursor: pointer;
      transition: all 0.15s ease;
      font-family: var(--sans);
    }
    .filter-pill:hover {
      background: var(--bg3);
      color: var(--text);
    }
    .filter-pill.active {
      background: var(--blue);
      color: #fff;
      border-color: var(--blue);
      font-weight: 600;
    }
    .filter-pill.pill-anom {
      color: #ff7b72;
      border-color: rgba(248,81,73,0.35);
    }
    .filter-pill.pill-anom.active {
      background: #f85149;
      color: #fff;
      border-color: #f85149;
    }
    .btn-copy-url {
      font-size: 11px;
      font-family: var(--sans);
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: var(--bg3);
      color: var(--text);
      cursor: pointer;
      transition: all 0.15s ease;
      white-space: nowrap;
    }
    .btn-copy-url:hover {
      background: var(--blue);
      color: #fff;
      border-color: var(--blue);
    }
    .filter-input {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 12px;
      padding: 6px 12px;
      width: 220px;
      outline: none;
    }
    .filter-input:focus {
      border-color: var(--blue);
    }
    .issues-section-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 24px;
      transition: border-color 0.15s ease;
    }
    .issues-section-card:hover {
      border-color: rgba(255,255,255,0.18);
    }
    .issues-toggle-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
      padding: 2px 0;
    }
    .issues-toggle-header:hover .section-title {
      color: var(--blue);
    }
    .issues-chevron {
      display: inline-block;
      font-size: 11px;
      color: var(--text2);
      transition: transform 0.2s ease;
      margin-right: 4px;
    }
    .issues-chevron.collapsed {
      transform: rotate(-90deg);
    }
    .issues-count-pill {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 12px;
      background: rgba(248,81,73,0.15);
      color: #ff7b72;
      font-weight: 600;
      border: 1px solid rgba(248,81,73,0.3);
      font-family: var(--mono);
    }
    .btn-toggle-issues {
      font-size: 11.5px;
      font-family: var(--sans);
      padding: 3px 10px;
      border-radius: 5px;
      border: 1px solid var(--border);
      background: var(--bg3);
      color: var(--text);
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-weight: 500;
    }
    .btn-toggle-issues:hover {
      background: var(--blue);
      color: #fff;
      border-color: var(--blue);
    }
    .issues-container {
      margin-top: 14px;
      transition: opacity 0.2s ease;
    }
    .issues-container.collapsed {
      display: none;
    }
    @media print {
      body { background: #fff; color: #000; padding: 10px; }
      .header-bar, .stat-card, .issue-card, .results-table-wrap, .issues-section-card { border-color: #ddd; background: #fff; }
      th { background: #eee; color: #333; }
      td { color: #111; }
      .filter-pills, .filter-input, .btn-copy-url, .btn-toggle-issues, .issues-chevron { display: none !important; }
      .issues-container { display: block !important; }
    }
  </style>
</head>
<body>
  <div class="header-bar">
    <div>
      <div class="logo-title">⚡ API Sentinel — Smart Auto-Fuzzer Report</div>
      <div class="report-date">Generated on ${now} • Target: ${_fuzzEscapeHtml(_fuzzLastHost || "api.target.com")} (${_fuzzLastMethod})</div>
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      ${baseTargetUrl ? `<button type="button" class="btn-copy-url" style="font-size:12px;padding:5px 12px;" onclick="copyUrl('${_fuzzEscapeAttr(baseTargetUrl)}', this)">📋 Copy Base Target URL</button>` : ""}
      <div style="font-size:12px;color:var(--text3);text-align:right">
        Automated DAST & Dynamic Fuzzing Scan
      </div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val">${total}</div>
      <div class="stat-lbl">Total Requests Fuzzed</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#f85149">${totalAnomalies}</div>
      <div class="stat-lbl">Anomalies Detected</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#ff7b72">${critCount + highCount}</div>
      <div class="stat-lbl">Critical / High Severity Issues</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#38bdf8">${avgTime} ms</div>
      <div class="stat-lbl">Average Response Latency</div>
    </div>
  </div>

  <div class="issues-section-card">
    <div class="issues-toggle-header" onclick="toggleIssuesSection()" title="Click to Collapse / Expand Detected Issues">
      <div class="section-title" style="margin-bottom:0;cursor:pointer;user-select:none;">
        <span id="issues-chevron" class="issues-chevron">▼</span>
        <span>🚨 Detected Issues & Anomalies (${issues.length})</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="issues-count-pill">${issues.length} Flagged</span>
        <button type="button" class="btn-toggle-issues" id="btn-toggle-issues" onclick="event.stopPropagation(); toggleIssuesSection();" title="Collapse or Expand Issues list">
          <span id="btn-toggle-text">Collapse ▴</span>
        </button>
        <button type="button" class="btn-toggle-issues" onclick="event.stopPropagation(); document.getElementById('results-section').scrollIntoView({behavior:'smooth'});" title="Jump straight down to Fuzzed Results Table">
          Table ↓
        </button>
      </div>
    </div>
    <div id="issues-container" class="issues-container">
      ${issuesHtml || '<div style="color:var(--text3);font-size:12px;padding:8px 0;">No security anomalies flagged during this attack run.</div>'}
    </div>
  </div>

  <div id="results-section">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
      <div class="section-title" style="margin-bottom:0">📊 All Fuzzed Requests & Responses (<span id="visible-count">${results.length}</span> / ${results.length})</div>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <div class="filter-pills">
          <button type="button" class="filter-pill active" onclick="setStatusFilter('all', this)">All (${total})</button>
          <button type="button" class="filter-pill" onclick="setStatusFilter('2xx', this)">2xx OK (${count2xx})</button>
          <button type="button" class="filter-pill" onclick="setStatusFilter('3xx', this)">3xx Redir (${count3xx})</button>
          <button type="button" class="filter-pill" onclick="setStatusFilter('4xx', this)">4xx Client (${count4xx})</button>
          <button type="button" class="filter-pill" onclick="setStatusFilter('5xx', this)">5xx Server Err (${count5xx})</button>
          <button type="button" class="filter-pill pill-anom" onclick="setStatusFilter('anomalies', this)">🚨 Anomalies (${totalAnomalies})</button>
        </div>
        <select id="report-filter-length" class="filter-input" style="width:160px;cursor:pointer;" onchange="setLengthFilter(this.value)" title="Filter results by response Length">
          ${lengthOptionsHtml}
        </select>
        <input type="text" class="filter-input" id="tbl-filter" placeholder="Filter results table…" oninput="filterTable(this.value)">
      </div>
    </div>
    <div class="results-table-wrap">
      <table id="res-table">
        <thead>
          <tr>
            <th class="sortable" style="width:36px" onclick="sortTable(0, 'num')" title="Click to sort by #">#<span class="sort-ico" id="sort-0">▲</span></th>
            <th class="sortable" style="width:60px" onclick="sortTable(1, 'str')" title="Click to sort by Method">Method<span class="sort-ico" id="sort-1">⇅</span></th>
            <th class="sortable" onclick="sortTable(2, 'str')" title="Click to sort by Location / Param">Location / Param<span class="sort-ico" id="sort-2">⇅</span></th>
            <th class="sortable" onclick="sortTable(3, 'str')" title="Click to sort by Payload">Fuzzed Payload<span class="sort-ico" id="sort-3">⇅</span></th>
            <th class="sortable" style="width:65px" onclick="sortTable(4, 'num')" title="Click to sort by Status">Status<span class="sort-ico" id="sort-4">⇅</span></th>
            <th class="sortable" style="width:75px" onclick="sortTable(5, 'num')" title="Click to sort by Length">Length<span class="sort-ico" id="sort-5">⇅</span></th>
            <th class="sortable" style="width:65px" onclick="sortTable(6, 'num')" title="Click to sort by Time">Time<span class="sort-ico" id="sort-6">⇅</span></th>
            <th class="sortable" onclick="sortTable(7, 'str')" title="Click to sort by Anomaly Flag">Anomaly Flag<span class="sort-ico" id="sort-7">⇅</span></th>
            <th style="width:95px;text-align:center">Action</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    var currentStatusFilter = 'all';
    var currentLengthFilter = 'all';
    var currentSearchQuery = '';
    var currentSortCol = 0;
    var currentSortDir = 'asc';

    function toggleIssuesSection() {
      var container = document.getElementById('issues-container');
      var chevron = document.getElementById('issues-chevron');
      var btnText = document.getElementById('btn-toggle-text');
      if (!container) return;
      var isCollapsed = container.classList.contains('collapsed');
      if (isCollapsed) {
        container.classList.remove('collapsed');
        if (chevron) chevron.classList.remove('collapsed');
        if (btnText) btnText.textContent = 'Collapse ▴';
      } else {
        container.classList.add('collapsed');
        if (chevron) chevron.classList.add('collapsed');
        if (btnText) btnText.textContent = 'Expand ▾';
      }
    }

    function setStatusFilter(filterType, btn) {
      currentStatusFilter = filterType;
      document.querySelectorAll('.filter-pill').forEach(function(b) {
        b.classList.remove('active');
      });
      if (btn) btn.classList.add('active');
      applyFilters();
    }

    function setLengthFilter(val) {
      currentLengthFilter = val;
      applyFilters();
    }

    function filterTable(q) {
      currentSearchQuery = (q || '').toLowerCase();
      applyFilters();
    }

    function applyFilters() {
      var rows = document.querySelectorAll('#res-table tbody tr');
      var visible = 0;
      rows.forEach(function(r) {
        var status = parseInt(r.getAttribute('data-status') || '0', 10);
        var length = parseInt(r.getAttribute('data-length') || '0', 10);
        var isAnomaly = r.getAttribute('data-anomaly') === 'true';
        var text = r.innerText.toLowerCase();

        var matchStatus = true;
        if (currentStatusFilter === '2xx') {
          matchStatus = status >= 200 && status < 300;
        } else if (currentStatusFilter === '3xx') {
          matchStatus = status >= 300 && status < 400;
        } else if (currentStatusFilter === '4xx') {
          matchStatus = status >= 400 && status < 500;
        } else if (currentStatusFilter === '5xx') {
          matchStatus = status >= 500;
        } else if (currentStatusFilter === 'anomalies') {
          matchStatus = isAnomaly;
        }

        var matchLength = true;
        if (currentLengthFilter !== 'all') {
          matchLength = (length === parseInt(currentLengthFilter, 10));
        }

        var matchSearch = !currentSearchQuery || text.indexOf(currentSearchQuery) !== -1;
        var show = matchStatus && matchLength && matchSearch;
        r.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      var countEl = document.getElementById('visible-count');
      if (countEl) countEl.innerText = visible;
    }

    function sortTable(colIndex, colType) {
      var tbody = document.querySelector('#res-table tbody');
      if (!tbody) return;
      var rows = Array.from(tbody.querySelectorAll('tr'));
      if (currentSortCol === colIndex) {
        currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
      } else {
        currentSortCol = colIndex;
        currentSortDir = (colType === 'num' && (colIndex === 4 || colIndex === 5 || colIndex === 6)) ? 'desc' : 'asc';
      }

      for (var i = 0; i <= 7; i++) {
        var indicator = document.getElementById('sort-' + i);
        var th = indicator ? indicator.parentElement : null;
        if (indicator) {
          if (i === currentSortCol) {
            indicator.textContent = currentSortDir === 'asc' ? '▲' : '▼';
            if (th) th.classList.add('sorted');
          } else {
            indicator.textContent = '⇅';
            if (th) th.classList.remove('sorted');
          }
        }
      }

      rows.sort(function(a, b) {
        var cellA = a.children[colIndex] ? a.children[colIndex].innerText.trim() : '';
        var cellB = b.children[colIndex] ? b.children[colIndex].innerText.trim() : '';

        var valA, valB;
        if (colType === 'num') {
          valA = parseFloat(cellA.replace(/[^0-9.-]/g, '')) || 0;
          valB = parseFloat(cellB.replace(/[^0-9.-]/g, '')) || 0;
          return currentSortDir === 'asc' ? (valA - valB) : (valB - valA);
        } else {
          valA = cellA.toLowerCase();
          valB = cellB.toLowerCase();
          if (valA < valB) return currentSortDir === 'asc' ? -1 : 1;
          if (valA > valB) return currentSortDir === 'asc' ? 1 : -1;
          return 0;
        }
      });

      rows.forEach(function(r) { tbody.appendChild(r); });
    }

    function copyUrl(url, btn) {
      if (!url) return;
      var orig = btn.innerHTML;
      function showSuccess() {
        btn.innerHTML = '✓ Copied!';
        btn.style.color = '#3fb950';
        btn.style.borderColor = '#3fb950';
        setTimeout(function() {
          btn.innerHTML = orig;
          btn.style.color = '';
          btn.style.borderColor = '';
        }, 1800);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(showSuccess).catch(function() {
          fallbackCopy(url, showSuccess);
        });
      } else {
        fallbackCopy(url, showSuccess);
      }
    }

    function fallbackCopy(text, cb) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        if (cb) cb();
      } catch (e) {
        prompt('Copy URL:', text);
      }
      document.body.removeChild(ta);
    }
  </script>
</body>
</html>`;
  }

  function _fuzzEscapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
  const fuzzEscapeHtml = _fuzzEscapeHtml;

  function _fuzzEscapeAttr(str) {
    return String(str || "")
      .replace(/'/g, "\\'")
      .replace(/"/g, "&quot;");
  }

  // Window Exports
  window.fuzzInit = fuzzInit;
  window.fuzzSwitchTab = fuzzSwitchTab;
  window.fuzzToggleCategory = fuzzToggleCategory;
  window.fuzzToggleEndpointPack = fuzzToggleEndpointPack;
  window.fuzzSelectAllCategories = fuzzSelectAllCategories;
  window.fuzzToggleCatsCollapse = fuzzToggleCatsCollapse;
  window.fuzzToggleTargetsCollapse = fuzzToggleTargetsCollapse;
  window.fuzzSwitchCatSubtab = fuzzSwitchCatSubtab;
  window.fuzzOpenPayloadModal = fuzzOpenPayloadModal;
  window.fuzzCloseModal = fuzzCloseModal;
  window.fuzzFilterModal = fuzzFilterModal;
  window.fuzzCopyAllModal = fuzzCopyAllModal;
  window.fuzzCopyRow = fuzzCopyRow;
  window.fuzzCopyCurrentUrl = fuzzCopyCurrentUrl;
  window.fuzzCopyCurrentCurl = fuzzCopyCurrentCurl;
  window.fuzzCopyIssueCurl = fuzzCopyIssueCurl;
  window.fuzzParseCurrentCurl = fuzzParseCurrentCurl;
  window.fuzzMarkSelectionPosition = fuzzMarkSelectionPosition;
  window.fuzzMarkUrlEndpoint = fuzzMarkUrlEndpoint;
  window.fuzzClearPositions = fuzzClearPositions;
  window.fuzzTogglePoint = fuzzTogglePoint;
  window.fuzzSelectAllPoints = fuzzSelectAllPoints;
  window.fuzzSelectPointsByType = fuzzSelectPointsByType;
  window.fuzzLoadSampleCurl = fuzzLoadSampleCurl;
  window.fuzzClearCurl = fuzzClearCurl;
  window.fuzzSelectResultRow = fuzzSelectResultRow;
  window.fuzzInspectSwitchTab = fuzzInspectSwitchTab;
  window.fuzzSendIssueToRepeater = fuzzSendIssueToRepeater;
  window.fuzzStartAttack = fuzzStartAttack;
  window.fuzzStopAttack = fuzzStopAttack;
  window.fuzzSetStatusFilter = fuzzSetStatusFilter;
  window.fuzzSetLengthFilter = fuzzSetLengthFilter;
  window.fuzzFilterResultsTable = fuzzFilterResultsTable;
  window.fuzzDownloadHtmlReport = fuzzDownloadHtmlReport;
  window.fuzzSetSort = fuzzSetSort;
  window.fuzzRefreshCurlHighlight = fuzzRefreshCurlHighlight;
  window.fuzzShowImportCurlModal = fuzzShowImportCurlModal;
  window.fuzzCloseCurlModal = fuzzCloseCurlModal;
  window.fuzzImportCurlFromModal = fuzzImportCurlFromModal;
  window.fuzzEnsureHttpTemplate = fuzzEnsureHttpTemplate;
  window.fuzzToggleManualCollapse = fuzzToggleManualCollapse;
  window.fuzzManualPaste = fuzzManualPaste;
  window.fuzzManualLoad = fuzzManualLoad;
  window.fuzzManualFilePicked = fuzzManualFilePicked;
  window.fuzzManualRemove = fuzzManualRemove;
  window.fuzzManualClear = fuzzManualClear;
  window.fuzzManualDedup = fuzzManualDedup;
  window.fuzzManualAdd = fuzzManualAdd;
  window.fuzzOpenManualPasteModal = fuzzOpenManualPasteModal;
  window.fuzzCloseManualPasteModal = fuzzCloseManualPasteModal;
  window.fuzzConfirmManualPaste = fuzzConfirmManualPaste;
  window.fuzzOpenArjunModal = fuzzOpenArjunModal;
  window.fuzzCloseArjunModal = fuzzCloseArjunModal;
  window.fuzzArjunWordlistChanged = fuzzArjunWordlistChanged;
  window.fuzzStartArjunScan = fuzzStartArjunScan;
  window.fuzzStopArjunScan = fuzzStopArjunScan;
  window.fuzzArjunAddSingleTarget = fuzzArjunAddSingleTarget;
  window.fuzzArjunAddAllToTargets = fuzzArjunAddAllToTargets;
  window.fuzzArjunClearLogs = fuzzArjunClearLogs;
  window.fuzzArjunCopyLogs = fuzzArjunCopyLogs;
  window.fuzzArjunResetData = fuzzArjunResetData;
  window.fuzzArjunCopyCurl = fuzzArjunCopyCurl;
  window.fuzzToggleServicesPack = fuzzToggleServicesPack;
  window.fuzzToggleEncCollapse = fuzzToggleEncCollapse;
})();
