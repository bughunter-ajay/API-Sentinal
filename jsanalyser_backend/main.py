"""
JS Analyser Backend — Port 8792

Takes captured/imported requests (from AV capture, HAR import, or a pasted
cURL) — including .js files, captured like any other endpoint — and scans
both what was sent and the response for exposed API keys, access tokens,
and other secrets using a curated regex ruleset.

By default each endpoint is fired live (`use_recorded=false`). When
`use_recorded=true`, the backend skips the network call and scans the
HAR-stored response body/headers instead.

    Exposes: /jsa/scan, /jsa/progress/{job_id}, /jsa/abort/{job_id}
"""

import os, sys, shutil, subprocess
_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

try:
    from swagger_helper import parse_swagger_spec, fetch_swagger_from_url, parse_devtools_or_raw_headers
except Exception:
    parse_swagger_spec = None
    fetch_swagger_from_url = None
    parse_devtools_or_raw_headers = None

try:
    from trufflehog_helper import get_trufflehog_info, find_trufflehog_binary
except Exception:
    get_trufflehog_info = None
    find_trufflehog_binary = None

import re, time, uuid, threading, json, math, base64
from collections import Counter
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Any, Callable

import urllib3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import requests as req_lib
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None

app = FastAPI(title="JS Analyser Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── Config ───────────────────────────────────────────────────────────────────
TIMEOUT       = 12
VERIFY_SSL    = False
THREADS       = 6
MAX_SCAN_LEN  = 2_000_000   # chars — guard against pathological regex time on huge blobs
REQUEST_DELAY = 0.15        # seconds — small per-worker pacing so 6 concurrent
                             # threads don't all fire at once and burst the target

# ══════════════════════════ SECRET PATTERNS ══════════════════════════════════
# (name, regex, severity, service_tag, info_url)
PATTERNS: List[tuple] = [
    # ── AI / LLM (prefix-validated where vendors publish stable formats) ──
    ("OpenAI API Key",
     r'(?<![A-Za-z0-9_\-])sk-(?:proj-|org-|svcacct-)[A-Za-z0-9_\-]{32,}|(?<![A-Za-z0-9_\-])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9_\-])',
     "HIGH", "openai", "https://platform.openai.com/account/api-keys"),
    ("Anthropic API Key", r'sk-ant-(?:api\d\d-)?[A-Za-z0-9_\-]{90,}', "HIGH", "anthropic", "https://console.anthropic.com/"),
    ("Hugging Face Token", r'hf_[A-Za-z0-9]{30,}', "HIGH", "huggingface", "https://huggingface.co/settings/tokens"),
    ("Replicate API Token", r'r8_[A-Za-z0-9]{36,}', "HIGH", "replicate", "https://replicate.com/account"),
    ("Cohere API Key", r'(?i)cohere[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]?([A-Za-z0-9]{40,})[\'"]?', "HIGH", "cohere", "https://dashboard.cohere.ai/"),
    ("Groq API Key", r'(?<![A-Za-z0-9_\-])gsk_[A-Za-z0-9]{50,}(?![A-Za-z0-9_\-])', "HIGH", "groq", "https://console.groq.com/keys"),
    ("OpenRouter API Key", r'(?<![A-Za-z0-9_\-])sk-or-v1-[A-Za-z0-9]{64,}(?![A-Za-z0-9_\-])', "HIGH", "openrouter", "https://openrouter.ai/keys"),
    ("Perplexity API Key", r'(?<![A-Za-z0-9_\-])pplx-[A-Za-z0-9]{40,}(?![A-Za-z0-9_\-])', "HIGH", "perplexity", "https://www.perplexity.ai/settings/api"),
    ("xAI / Grok API Key", r'(?<![A-Za-z0-9_\-])xai-[A-Za-z0-9]{40,}(?![A-Za-z0-9_\-])', "HIGH", "xai", "https://console.x.ai/"),
    ("Fireworks AI Key", r'(?<![A-Za-z0-9_\-])fw_[A-Za-z0-9]{20,}(?![A-Za-z0-9_\-])', "HIGH", "fireworks", "https://fireworks.ai/account/api-keys"),
    ("Mistral API Key", r'(?i)(?:mistral[_\-. ]?(?:api[_\-. ]?)?key|MISTRAL_API_KEY)\s*[:=]\s*[\'"]?([A-Za-z0-9]{32,})[\'"]?', "HIGH", "mistral", "https://console.mistral.ai/"),
    ("DeepSeek API Key", r'(?i)(?:deepseek[_\-. ]?(?:api[_\-. ]?)?key|DEEPSEEK_API_KEY)\s*[:=]\s*[\'"]?(sk-[A-Za-z0-9]{32,}|[A-Za-z0-9]{32,})[\'"]?', "HIGH", "deepseek", "https://platform.deepseek.com/"),
    ("Together AI Key", r'(?i)(?:together[_\-. ]?(?:ai[_\-. ]?)?(?:api[_\-. ]?)?key|TOGETHER_API_KEY)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{32,})[\'"]?', "HIGH", "together", "https://api.together.xyz/settings/api-keys"),
    ("Gemini / Google AI Key", r'(?i)(?:gemini[_\-. ]?(?:api[_\-. ]?)?key|GOOGLE_AI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY|generative[_\-. ]?language)\W{0,40}[:=]\s*[\'"]?(AIza[0-9A-Za-z\-_]{35})[\'"]?', "HIGH", "google-ai", "https://aistudio.google.com/app/apikey"),
    ("Stability AI Key", r'(?i)(?:stability[_\-. ]?(?:ai[_\-. ]?)?(?:api[_\-. ]?)?key|STABILITY_API_KEY|STABILITY_KEY)\s*[:=]\s*[\'"]?(sk-[A-Za-z0-9]{32,}|[A-Za-z0-9]{32,})[\'"]?', "HIGH", "stability", "https://platform.stability.ai/account/keys"),
    ("ElevenLabs API Key", r'(?i)(?:elevenlabs|xi[_\-. ]?api[_\-. ]?key|ELEVENLABS_API_KEY)\s*[:=]\s*[\'"]?([A-Za-z0-9]{32})[\'"]?', "HIGH", "elevenlabs", "https://elevenlabs.io/app/settings/api-keys"),
    ("Azure OpenAI Key", r'(?i)(?:azure[_\-. ]?openai[_\-. ]?(?:api[_\-. ]?)?key|AZURE_OPENAI_API_KEY|OPENAI_API_KEY)\s*[:=]\s*[\'"]?([A-Za-z0-9]{32})[\'"]?', "HIGH", "azure-openai", "https://portal.azure.com/"),
    ("HeyGen API Key", r'(?i)(?:heygen[_\-. ]?(?:api[_\-. ]?)?key|HEYGEN_API_KEY)\s*[:=]\s*[\'"]?([A-Za-z0-9+/=_\-]{32,})[\'"]?', "HIGH", "heygen", "https://app.heygen.com/settings"),
    ("ROX CRM API Token", r'(?i)(?:ROX_API_TOKEN|rox[_\-. ]?(?:crm[_\-. ]?)?(?:api[_\-. ]?)?token)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?', "HIGH", "rox", ""),

    # ── Cloud – AWS ──
    ("AWS Access Key ID", r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])', "HIGH", "aws", "https://console.aws.amazon.com/iam/"),
    ("AWS Temporary Access Key ID", r'(?<![A-Z0-9])ASIA[0-9A-Z]{16}(?![A-Z0-9])', "HIGH", "aws", "https://console.aws.amazon.com/iam/"),
    ("AWS Secret Access Key", r'(?i)aws[_\-. ]?secret[_\-. ]?(?:access[_\-. ]?)?key\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?', "HIGH", "aws", "https://console.aws.amazon.com/iam/"),
    ("AWS Session Token", r'(?i)aws[_\-. ]?session[_\-. ]?token\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{100,})[\'"]?', "HIGH", "aws", "https://console.aws.amazon.com/iam/"),
    ("AWS MWS Auth Token", r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "HIGH", "aws", "https://console.aws.amazon.com/"),

    # ── Cloud – GCP ──
    # Browser Firebase/Maps keys (AIza…) are usually public client keys → LOW.
    # Translation / server-side usage nearby upgrades via validator → MEDIUM.
    # Real risk is the service-account JSON below (private_key).
    ("GCP / Firebase API Key", r'AIza[0-9A-Za-z\-_]{35}', "LOW", "google", "https://console.cloud.google.com/apis/credentials"),
    ("Google Translation API Key",
     r'(?i)(?:google[_\-. ]?(?:cloud[_\-. ]?)?translat\w*|translation[_\-. ]?api[_\-. ]?key|TRANSLATE_API_KEY|GOOGLE_TRANSLATE)[^AIza\n]{0,120}(AIza[0-9A-Za-z\-_]{35})',
     "HIGH", "google", "https://console.cloud.google.com/apis/credentials"),
    ("GCP Service Account JSON", r'"type"\s*:\s*"service_account"(?=[^}]{0,500}"project_id"\s*:)(?=[^}]{0,500}"private_key"\s*:)', "HIGH", "google", "https://console.cloud.google.com/iam-admin/serviceaccounts"),

    # ── Cloud – Azure ──
    ("Azure Storage Key", r'(?i)(?:azure|storage)[_\-. ]?(?:account[_\-. ]?)?key\s*[:=]\s*[\'"]?([A-Za-z0-9+/]{86,88}==)[\'"]?', "HIGH", "azure", "https://portal.azure.com/"),
    ("Azure Storage Connection String",
     r'(?i)DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[A-Za-z0-9+/=]+;EndpointSuffix=core\.windows\.net',
     "HIGH", "azure", "https://portal.azure.com/"),
    ("Azure SAS Token", r'(?i)(?:blob|queue|table|file)\.core\.windows\.net[^\s]*sig=[A-Za-z0-9%]{40,}', "HIGH", "azure", "https://portal.azure.com/"),
    ("Azure Client Secret", r'(?i)(?:azure[_\-. ]?(?:client[_\-. ]?)?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*[\'"]([A-Za-z0-9~\-_.]{34,})[\'"]', "HIGH", "azure", "https://portal.azure.com/"),
    ("Firebase Cloud Messaging Key",
     r'(?<![A-Za-z0-9_\-])AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}(?![A-Za-z0-9_\-])',
     "HIGH", "google", "https://console.firebase.google.com/"),

    # ── Source Control ──
    ("GitHub PAT (Classic)", r'ghp_[A-Za-z0-9]{36}', "HIGH", "github", "https://github.com/settings/tokens"),
    ("GitHub Fine-grained PAT", r'github_pat_[A-Za-z0-9_]{22,}', "HIGH", "github", "https://github.com/settings/tokens"),
    ("GitHub OAuth Token", r'gho_[A-Za-z0-9]{36}', "HIGH", "github", "https://github.com/settings/tokens"),
    ("GitHub User-to-Server Token", r'ghu_[A-Za-z0-9]{36}', "HIGH", "github", "https://github.com/settings/tokens"),
    ("GitHub App Token", r'ghs_[A-Za-z0-9]{36}', "HIGH", "github", "https://github.com/settings/tokens"),
    ("GitHub Refresh Token", r'ghr_[A-Za-z0-9_]{36,}', "HIGH", "github", "https://github.com/settings/tokens"),
    ("GitLab PAT", r'glpat-[A-Za-z0-9\-_]{20}', "HIGH", "gitlab", "https://gitlab.com/-/profile/personal_access_tokens"),
    ("GitLab Pipeline Trigger Token", r'glptt-[0-9a-f]{40}', "HIGH", "gitlab", "https://gitlab.com/-/profile/personal_access_tokens"),
    ("GitLab Runner Registration", r'GR1348941[A-Za-z0-9_\-]{20}', "HIGH", "gitlab", "https://gitlab.com/"),
    ("Bitbucket App Password", r'(?i)bitbucket[_\-. ]?(?:app[_\-. ]?)?password\s*[:=]\s*[\'"]([A-Za-z0-9]{16,})[\'"]', "HIGH", "bitbucket", "https://bitbucket.org/account/settings/app-passwords/"),

    # ── Communication ──
    ("Slack Bot Token", r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}', "HIGH", "slack", "https://api.slack.com/apps"),
    ("Slack User Token", r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}', "HIGH", "slack", "https://api.slack.com/apps"),
    ("Slack App Token", r'xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[A-Za-z0-9]{64}', "HIGH", "slack", "https://api.slack.com/apps"),
    ("Slack Legacy Token", r'xoxs-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}', "HIGH", "slack", "https://api.slack.com/apps"),
    ("Slack Config Token", r'xoxe\.xox[bp]-[0-9]-[A-Za-z0-9]{160,}', "HIGH", "slack", "https://api.slack.com/apps"),
    ("Slack Webhook URL", r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}', "HIGH", "slack", "https://api.slack.com/messaging/webhooks"),
    ("Discord Bot Token", r'(?i)discord[_\-. ]?(?:bot[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9._\-]{59,})[\'"]', "HIGH", "discord", "https://discord.com/developers/applications"),
    ("Discord Webhook", r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}', "HIGH", "discord", "https://discord.com/developers/applications"),
    ("Telegram Bot Token", r'(?i)telegram[_\-. ]?(?:bot[_\-. ]?)?token\s*[:=]\s*[\'"]?([0-9]{8,10}:[A-Za-z0-9_\-]{35})[\'"]?', "HIGH", "telegram", "https://t.me/botfather"),
    ("Telegram Bot Token (bare)", r'(?<![A-Za-z0-9])[0-9]{8,10}:AA[A-Za-z0-9_\-]{32,33}(?![A-Za-z0-9])', "HIGH", "telegram", "https://t.me/botfather"),
    ("Twilio API Key", r'(?i)twilio[_\-. ]?(?:api[_\-. ]?)?(?:key|sid)\s*[:=]\s*[\'"]?(SK[A-Za-z0-9]{32})[\'"]?', "HIGH", "twilio", "https://console.twilio.com/"),
    ("Twilio Auth Token", r'(?i)twilio[_\-. ]?(?:auth[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "HIGH", "twilio", "https://console.twilio.com/"),

    # ── Payment / Finance ──
    ("Stripe Secret Key", r'sk_live_[A-Za-z0-9]{24,}', "HIGH", "stripe", "https://dashboard.stripe.com/apikeys"),
    ("Stripe Restricted Key", r'rk_live_[A-Za-z0-9]{24,}', "HIGH", "stripe", "https://dashboard.stripe.com/apikeys"),
    ("Stripe Test Secret Key", r'sk_test_[A-Za-z0-9]{24,}', "MEDIUM", "stripe", "https://dashboard.stripe.com/apikeys"),
    ("Stripe Test Restricted Key", r'rk_test_[A-Za-z0-9]{24,}', "MEDIUM", "stripe", "https://dashboard.stripe.com/apikeys"),
    ("Stripe Publishable Key", r'pk_(?:live|test)_[A-Za-z0-9]{24,}', "LOW", "stripe", "https://dashboard.stripe.com/apikeys"),
    ("Stripe Webhook Secret", r'whsec_[A-Za-z0-9]{32,}', "HIGH", "stripe", "https://dashboard.stripe.com/webhooks"),
    ("PayPal Client Secret", r'(?i)paypal[_\-. ]?(?:client[_\-. ]?)?secret\s*[:=]\s*[\'"]([A-Za-z0-9\-]{32,})[\'"]', "HIGH", "paypal", "https://developer.paypal.com/developer/applications"),
    ("Razorpay Key", r'rzp_(?:live|test)_[A-Za-z0-9]{14}', "HIGH", "razorpay", "https://dashboard.razorpay.com/app/keys"),
    ("Braintree Token", r'(?i)braintree[_\-. ]?(?:access[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', "HIGH", "braintree", "https://sandbox.braintreegateway.com/"),
    ("PayPal Braintree Access Token",
     r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
     "HIGH", "braintree", "https://developer.paypal.com/"),
    ("Coinbase API Key", r'(?i)coinbase[_\-. ]?(?:api[_\-. ]?)?(?:key|secret)\s*[:=]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', "HIGH", "coinbase", "https://www.coinbase.com/settings/api"),

    # ── Email Services ──
    ("SendGrid API Key", r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', "HIGH", "sendgrid", "https://app.sendgrid.com/settings/api_keys"),
    ("Mailgun API Key", r'(?i)mailgun[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]?(key-[A-Za-z0-9]{32})[\'"]?', "HIGH", "mailgun", "https://app.mailgun.com/app/account/security/api_keys"),
    ("Mailchimp API Key", r'(?i)mailchimp[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]?([A-Za-z0-9]{32}-us[0-9]{1,2})[\'"]?', "HIGH", "mailchimp", "https://us1.admin.mailchimp.com/account/api/"),
    ("Postmark Server Token", r'(?i)postmark[_\-. ]?(?:server[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9\-]{36})[\'"]', "HIGH", "postmark", "https://account.postmarkapp.com/servers"),

    # ── Authentication / Identity ──
    ("JWT Token",
     r'eyJ[A-Za-z0-9_\-]{16,}\.eyJ[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}',
     "MEDIUM", "jwt", "https://jwt.io/"),
    ("Basic Auth in URL",
     r'https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|test\.com|user|admin|login|username|password|http|https)(?:[:@/]))[A-Za-z0-9._\-]{4,}:[A-Za-z0-9._\-@#$!]{8,}@(?!localhost)[^\s/]{4,}',
     "HIGH", "basic-auth", ""),
    ("Auth0 Client Secret", r'(?i)auth0[_\-. ]?(?:client[_\-. ]?)?secret\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', "HIGH", "auth0", "https://manage.auth0.com/"),
    ("Okta API Token", r'(?i)okta[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{42})[\'"]', "HIGH", "okta", "https://developer.okta.com/"),
    # OAuth client secrets — value-validated (entropy / placeholders); client_id alone is public.
    ("OAuth Client Secret",
     r'(?i)(?:["\']?client_secret["\']?|oauth[_\-. ]?client[_\-. ]?secret|OAUTH_CLIENT_SECRET|CLIENT_SECRET)\s*[:=]\s*[\'"]([A-Za-z0-9_\-~./+=]{16,256})[\'"]',
     "HIGH", "oauth", ""),
    ("OAuth Refresh Token",
     r'(?i)(?:["\']?refresh_token["\']?|OAUTH_REFRESH_TOKEN)\s*[:=]\s*[\'"]([A-Za-z0-9_\-~./+=]{24,512})[\'"]',
     "HIGH", "oauth", ""),
    ("Microsoft OAuth Client Secret",
     r'(?i)(?:microsoft|azuread|msal|entra)[^\n]{0,80}(?:client[_\-. ]?secret|CLIENT_SECRET)\s*[:=]\s*[\'"]([A-Za-z0-9_\-~.]{16,})[\'"]',
     "HIGH", "oauth", "https://portal.azure.com/"),
    ("Google OAuth Client Secret",
     r'(?i)(?<![A-Za-z0-9_\-])GOCSPX-[A-Za-z0-9_\-]{28,}(?![A-Za-z0-9_\-])|(?:google[_\-. ]?oauth|GOOGLE_CLIENT_SECRET)\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{20,})[\'"]|client_secret\s*[:=]\s*[\'"](GOCSPX-[A-Za-z0-9_\-]{20,})[\'"]',
     "HIGH", "oauth", "https://console.cloud.google.com/apis/credentials"),
    ("Google OAuth Client ID",
     r'(?<![A-Za-z0-9_\-])[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com(?![A-Za-z0-9_\-])',
     "MEDIUM", "oauth", "https://console.cloud.google.com/apis/credentials"),
    ("Google OAuth Refresh Token",
     r'(?<![A-Za-z0-9_/])1//0[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_\-])',
     "HIGH", "oauth", "https://console.cloud.google.com/apis/credentials"),
    ("Slack OAuth Client Secret",
     r'(?i)(?:slack[_\-. ]?(?:client[_\-. ]?)?secret|SLACK_CLIENT_SECRET)\s*[:=]\s*[\'"]([A-Za-z0-9]{24,})[\'"]',
     "HIGH", "oauth", "https://api.slack.com/apps"),

    # ── Databases / Connection Strings ──
    ("MongoDB URI", r'mongodb(?:\+srv)?://(?!.*@localhost)(?!.*@127\.)[^:@\s]{2,}:[^@\s]{8,}@[^\s]{10,}', "HIGH", "mongodb", "https://cloud.mongodb.com/"),
    ("PostgreSQL DSN", r'postgres(?:ql)?://(?!.*@localhost)(?!.*@127\.)[^:@\s]{2,}:[^@\s]{8,}@[^\s]{5,}', "HIGH", "postgres", ""),
    ("MySQL DSN", r'mysql(?:2)?://(?!.*@localhost)(?!.*@127\.)[^:@\s]{2,}:[^@\s]{8,}@[^\s]{5,}', "HIGH", "mysql", ""),
    ("Redis URL with Auth", r'redis://:([^@\s]{6,})@[^\s]{5,}', "HIGH", "redis", ""),
    ("ElasticSearch Creds", r'https?://[^:@\s]{2,}:[^@\s]{2,}@[^\s]*elastic[^\s]{3,}', "HIGH", "elasticsearch", ""),
    ("MSSQL Connection String", r'(?i)(?:server|data\s+source)=[^;]{3,};[^;]*(?:user\s+id|uid)=[^;]+;[^;]*password=[^;]{4,}', "HIGH", "mssql", ""),
    ("Supabase Service Key", r'(?i)supabase[_\-. ]?(?:service[_\-. ]?)?(?:role[_\-. ]?)?key\s*[:=]\s*[\'"]?(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)[\'"]?', "HIGH", "supabase", "https://app.supabase.com/project/_/settings/api"),

    # ── Cryptographic Material ──
    ("RSA Private Key", r'-----BEGIN RSA PRIVATE KEY-----', "HIGH", "crypto", ""),
    ("EC Private Key", r'-----BEGIN EC PRIVATE KEY-----', "HIGH", "crypto", ""),
    ("PGP Private Key", r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "HIGH", "crypto", ""),
    ("SSH Private Key", r'-----BEGIN OPENSSH PRIVATE KEY-----', "HIGH", "crypto", ""),
    ("PKCS8 Private Key", r'-----BEGIN PRIVATE KEY-----', "HIGH", "crypto", ""),
    ("Private Key Header", r'-----BEGIN [A-Z ]+PRIVATE KEY-----', "HIGH", "crypto", ""),
    # Hardcoded AES material — only near explicit aes/encrypt key names; length/entropy validated.
    ("Hardcoded AES Key",
     r'(?i)(?:aes[_\-.]?(?:128|192|256)?[_\-.]?(?:key|secret|iv)|encryption[_\-.]?key|encrypt[_\-.]?key|payload[_\-.]?encrypt[_\-.]?key|crypto[_\-.]?key)\s*[:=]\s*[\'"]([A-Za-z0-9+/=_\-]{16,88})[\'"]',
     "HIGH", "crypto", ""),
    ("Hardcoded AES Payload",
     r'(?i)(?:aes[_\-.]?payload|encrypted[_\-.]?payload|cipher(?:text)?)\s*[:=]\s*[\'"]([A-Za-z0-9+/=]{32,})[\'"]',
     "MEDIUM", "crypto", ""),

    # ── CI/CD & DevOps ──
    ("CircleCI Token", r'(?i)circle(?:ci)?[_\-. ]?token\s*[:=]\s*[\'"]([A-Za-z0-9]{40})[\'"]', "HIGH", "circleci", "https://app.circleci.com/settings/user/tokens"),
    ("Vercel Token", r'(?i)vercel[_\-. ]?token\s*[:=]\s*[\'"]([A-Za-z0-9]{24,})[\'"]', "HIGH", "vercel", "https://vercel.com/account/tokens"),
    ("Netlify Token", r'(?i)netlify[_\-. ]?token\s*[:=]\s*[\'"]([A-Za-z0-9]{40,})[\'"]', "HIGH", "netlify", "https://app.netlify.com/user/applications"),
    ("Heroku API Key", r'(?i)heroku[_\-. ]?(?:api[_\-. ]?)?(?:key|token)\s*[:=]\s*[\'"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'"]?', "HIGH", "heroku", "https://dashboard.heroku.com/account"),
    ("NPM Auth Token", r'npm_[A-Za-z0-9]{36}', "HIGH", "npm", "https://www.npmjs.com/settings/~/tokens"),
    ("PyPI API Token", r'pypi-[A-Za-z0-9_\-]{40,}', "HIGH", "pypi", "https://pypi.org/manage/account/token/"),
    ("HashiCorp Vault Token", r'hvs\.[A-Za-z0-9]{24,}', "HIGH", "vault", "https://developer.hashicorp.com/vault"),
    ("Jenkins API Token", r'(?i)jenkins[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9]{34})[\'"]', "HIGH", "jenkins", ""),
    ("Docker Hub Token", r'(?i)docker[_\-. ]?(?:hub[_\-. ]?)?(?:token|pat)\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', "HIGH", "docker", "https://hub.docker.com/settings/security"),
    ("Terraform Cloud Token", r'(?i)terraform[_\-. ]?(?:cloud[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9.]{40,})[\'"]', "HIGH", "terraform", "https://app.terraform.io/app/settings/tokens"),
    ("DigitalOcean PAT", r'dop_v1_[a-f0-9]{64}', "HIGH", "digitalocean", "https://cloud.digitalocean.com/account/api/tokens"),

    # ── Analytics & Monitoring ──
    ("Sentry DSN", r'https://[A-Za-z0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+', "HIGH", "sentry", "https://sentry.io/settings/"),
    ("Sentry Auth Token", r'(?<![A-Za-z0-9_\-])sntrys_[A-Za-z0-9_\-=]{64,}(?![A-Za-z0-9_\-])', "HIGH", "sentry", "https://sentry.io/settings/account/api/auth-tokens/"),
    ("New Relic License Key", r'(?i)new[_\-. ]?relic[_\-. ]?(?:license[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{40})[\'"]', "HIGH", "newrelic", "https://one.newrelic.com/"),
    ("New Relic API Key", r'(?<![A-Za-z0-9_\-])NRRA-[a-f0-9]{42}(?![A-Za-z0-9_\-])', "HIGH", "newrelic", "https://one.newrelic.com/"),
    ("Datadog API Key", r'(?i)datadog[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "HIGH", "datadog", "https://app.datadoghq.com/organization-settings/api-keys"),
    ("Datadog App Key", r'(?i)datadog[_\-. ]?app(?:lication)?[_\-. ]?key\s*[:=]\s*[\'"]([A-Za-z0-9]{40})[\'"]', "HIGH", "datadog", "https://app.datadoghq.com/organization-settings/application-keys"),
    ("Mixpanel Token", r'(?i)mixpanel[_\-. ]?token\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "MEDIUM", "mixpanel", "https://mixpanel.com/settings/project/"),
    ("Amplitude API Key", r'(?i)amplitude[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "MEDIUM", "amplitude", "https://app.amplitude.com/"),

    # ── Map & Location ──
    # pk.eyJ… is the public (default) token → LOW. sk.eyJ… is secret → HIGH.
    ("Mapbox Public Token", r'pk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{6,}', "LOW", "mapbox", "https://account.mapbox.com/access-tokens/"),
    ("Mapbox Secret Token", r'sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{6,}', "HIGH", "mapbox", "https://account.mapbox.com/access-tokens/"),
    ("HERE Maps API Key", r'(?i)here[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{43})[\'"]', "HIGH", "here", "https://developer.here.com/projects"),

    # ── Media & CDN ──
    ("Cloudinary API Secret", r'(?i)cloudinary[_\-. ]?(?:api[_\-. ]?)?secret\s*[:=]\s*[\'"]([A-Za-z0-9]{27,})[\'"]', "HIGH", "cloudinary", "https://cloudinary.com/console"),
    ("Cloudflare API Token", r'(?i)cloudflare[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{40})[\'"]', "HIGH", "cloudflare", "https://dash.cloudflare.com/profile/api-tokens"),
    ("Fastly API Token", r'(?i)fastly[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{32})[\'"]', "HIGH", "fastly", "https://manage.fastly.com/account/personal/tokens"),

    # ── E-commerce ──
    ("Shopify Admin Token", r'shpat_[A-Za-z0-9]{32}', "HIGH", "shopify", "https://partners.shopify.com/"),
    ("Shopify Storefront Token", r'shpss_[A-Za-z0-9]{32}', "HIGH", "shopify", "https://partners.shopify.com/"),
    ("WooCommerce Secret", r'(?i)woocommerce[_\-. ]?(?:consumer[_\-. ]?)?secret\s*[:=]\s*[\'"]([A-Za-z0-9]{43})[\'"]', "HIGH", "woocommerce", ""),
    ("Square Access Token", r'(?i)(?:square|squareup|sq_access|square_token)\W{0,150}?(EAAA[A-Za-z0-9]{40,})', "HIGH", "square", "https://developer.squareup.com/apps"),

    # ── Social Media APIs ──
    ("Twitter/X Bearer Token", r'(?i)(?:Authorization:\s*Bearer|twitter_bearer_token|TWITTER_BEARER|bearer_token)\s*[=:"\'\s]{0,5}(A{20,}[A-Za-z0-9%]{25,})', "HIGH", "twitter", "https://developer.twitter.com/en/apps"),
    ("Twitter API Key", r'(?i)twitter[_\-. ]?(?:api[_\-. ]?)?(?:key|secret)\s*[:=]\s*[\'"]([A-Za-z0-9]{25,})[\'"]', "HIGH", "twitter", "https://developer.twitter.com/en/apps"),
    ("Facebook Access Token", r'(?i)(?:facebook|fb_access_token|instagram_token|meta_token|graph\.facebook)\W{0,200}?(EAA[A-Za-z0-9]{50,})', "HIGH", "facebook", "https://developers.facebook.com/apps/"),
    ("TikTok Client Key", r'(?i)tiktok[_\-. ]?(?:client[_\-. ]?)?(?:key|secret)\s*[:=]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', "HIGH", "tiktok", "https://developers.tiktok.com/"),
    ("LinkedIn Client Secret", r'(?i)linkedin[_\-. ]?(?:client[_\-. ]?)?secret\s*[:=]\s*[\'"]([A-Za-z0-9]{16,})[\'"]', "HIGH", "linkedin", "https://www.linkedin.com/developers/apps"),

    # ── Project Management ──
    ("Jira API Token", r'(?i)jira[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9]{24,})[\'"]', "HIGH", "jira", "https://id.atlassian.com/manage-profile/security/api-tokens"),
    ("Notion Token", r'secret_[A-Za-z0-9]{43}', "HIGH", "notion", "https://www.notion.so/my-integrations"),
    ("Linear API Key", r'lin_api_[A-Za-z0-9]{40}', "HIGH", "linear", "https://linear.app/settings/api"),
    ("Airtable API Key", r'pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}', "HIGH", "airtable", "https://airtable.com/account"),
    ("PagerDuty API Key", r'(?i)pagerduty[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9+/]{20,})[\'"]', "HIGH", "pagerduty", ""),
    ("Zendesk API Token", r'(?i)zendesk[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9]{40})[\'"]', "HIGH", "zendesk", ""),
    ("Intercom Token", r'(?i)intercom[_\-. ]?(?:access[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9_]{52})[\'"]', "HIGH", "intercom", "https://app.intercom.com/a/apps/"),
    ("Asana PAT", r'(?i)asana[_\-. ]?(?:personal[_\-. ]?)?(?:access[_\-. ]?)?token\s*[:=]\s*[\'"]([0-9]{16}/[A-Za-z0-9]{32})[\'"]', "HIGH", "asana", "https://app.asana.com/0/my-apps"),
    ("Asana PAT (2.x)", r'(?<![A-Za-z0-9/])2/[0-9]{16}/[0-9]{16}:[a-f0-9]{32}(?![A-Za-z0-9])', "HIGH", "asana", "https://app.asana.com/0/my-apps"),
    ("Atlassian API Token", r'(?<![A-Za-z0-9_\-])ATATT3[A-Za-z0-9_\-=]{180,}(?![A-Za-z0-9_\-])', "HIGH", "atlassian", "https://id.atlassian.com/manage-profile/security/api-tokens"),

    # ── Search & Data ──
    ("Algolia Admin Key", r'(?i)algolia[_\-. ]?(?:admin[_\-. ]?)?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "HIGH", "algolia", "https://www.algolia.com/account/api-keys/all"),
    ("Elastic Cloud API Key", r'(?i)elastic[_\-. ]?(?:cloud[_\-. ]?)?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', "HIGH", "elastic", "https://cloud.elastic.co/"),
    ("Shodan API Key", r'(?i)shodan[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "HIGH", "shodan", "https://account.shodan.io/"),

    # ── SMS & Telephony ──
    ("Vonage/Nexmo API Key", r'(?i)(?:vonage|nexmo)[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{8,16})[\'"]', "HIGH", "vonage", "https://dashboard.nexmo.com/settings"),
    ("MessageBird API Key", r'(?i)messagebird[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{25})[\'"]', "HIGH", "messagebird", "https://dashboard.messagebird.com/en/developers/access"),
    ("Plivo Auth Token", r'(?i)plivo[_\-. ]?(?:auth[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9]{40})[\'"]', "HIGH", "plivo", "https://console.plivo.com/dashboard/"),

    # ── Security Tools ──
    ("VirusTotal API Key", r'(?i)virustotal[_\-. ]?(?:api[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{64})[\'"]', "HIGH", "virustotal", "https://www.virustotal.com/gui/user/profile/apikey"),
    ("Snyk API Token", r'(?i)snyk[_\-. ]?(?:api[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9\-]{36})[\'"]', "HIGH", "snyk", "https://app.snyk.io/account"),
    ("SonarQube Token", r'(?<![A-Za-z0-9_\-])squ_[a-f0-9]{40}(?![A-Za-z0-9_\-])', "HIGH", "sonarqube", "https://docs.sonarqube.org/"),

    # ── Cloud / SaaS extras (ported from scannerEngine REFERENCE + DETECTOR) ──
    ("Dropbox Access Token", r'(?<![A-Za-z0-9_\-])sl\.[A-Za-z0-9_\-]{130,}(?![A-Za-z0-9_\-])', "HIGH", "dropbox", "https://www.dropbox.com/developers/apps"),
    ("Dropbox Short-Lived Token", r'(?i)dropbox[_\-. ]?(?:access[_\-. ]?)?token\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{60,})[\'"]', "HIGH", "dropbox", "https://www.dropbox.com/developers/apps"),
    ("Grafana API Key", r'(?<![A-Za-z0-9_\-])eyJrIjoi[A-Za-z0-9_\-+/=]{30,}(?![A-Za-z0-9_\-])', "HIGH", "grafana", "https://grafana.com/"),
    ("Grafana Service Account", r'(?<![A-Za-z0-9_\-])glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}(?![A-Za-z0-9_\-])', "HIGH", "grafana", "https://grafana.com/"),
    ("Segment Write Key", r'(?i)segment[_\-. ]?(?:write[_\-. ]?)?key\s*[:=]\s*[\'"]([A-Za-z0-9]{32})[\'"]', "MEDIUM", "segment", "https://segment.com/"),
    ("Clojars Deploy Token", r'(?<![A-Za-z0-9_\-])CLOJARS_[A-Za-z0-9]{60}(?![A-Za-z0-9_\-])', "HIGH", "clojars", "https://clojars.org/tokens"),
    ("Doppler API Token", r'(?<![A-Za-z0-9_\-])dp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,}(?![A-Za-z0-9_\-])', "HIGH", "doppler", "https://dashboard.doppler.com/"),
    ("Databricks Token", r'(?<![A-Za-z0-9_\-])dapi[a-f0-9]{32}(?:-[0-9])?(?![A-Za-z0-9_\-])', "HIGH", "databricks", "https://docs.databricks.com/"),
    ("Pulumi Access Token", r'(?<![A-Za-z0-9_\-])pul-[a-f0-9]{40}(?![A-Za-z0-9_\-])', "HIGH", "pulumi", "https://app.pulumi.com/account/tokens"),
    ("Rubygems API Key", r'(?<![A-Za-z0-9_\-])rubygems_[a-f0-9]{48}(?![A-Za-z0-9_\-])', "HIGH", "rubygems", "https://rubygems.org/profile/api_keys"),
    ("Postman API Key", r'(?<![A-Za-z0-9_\-])PMAK-[a-f0-9]{24}-[a-f0-9]{34}(?![A-Za-z0-9_\-])', "HIGH", "postman", "https://learning.postman.com/docs/developer/postman-api/authentication/"),

    # ── Connection strings / auth headers (scannerEngine credential rules) ──
    ("JDBC URL", r'(?i)jdbc:[a-z0-9]+://[^\s\'"]{6,}', "MEDIUM", "database", ""),
    ("AMQP/Broker URL with Creds", r'(?i)amqps?://[^:@\s]{2,}:[^@\s]{4,}@[^\s\'"]{4,}', "HIGH", "messaging", ""),
    ("FTP URL with Creds", r'(?i)ftps?://[^:@\s]{2,}:[^@\s]{4,}@[^\s\'"]{4,}', "HIGH", "network", ""),
    ("SMTP Credential", r'(?i)smtp[._]?(?:user|password|pass|pwd)\s{0,3}[:=]\s{0,3}\S*?([A-Za-z0-9_@#%!.+/\-]{8,})', "MEDIUM", "email", ""),
    ("Password in Connection String", r'(?i)(?:password|pwd)=([^;&\s\'"]{8,})', "HIGH", "credential", ""),
    ("Private Key in JSON (escaped)", r'-----BEGIN [A-Z ]*PRIVATE KEY-----\\n', "HIGH", "crypto", ""),
    ("Basic Auth Header", r'(?i)authorization\s{0,3}[:=]\s{0,3}\W?basic\s+([A-Za-z0-9+/]{16,}={0,2})', "HIGH", "auth", ""),
    ("Bearer Token (header)", r'(?i)bearer\s+([A-Za-z0-9_.=+\-]{20,})', "MEDIUM", "auth", ""),
    ("Hardcoded Password (generic)",
     r'(?i)(?<![a-z0-9_])(?:password|passwd|pwd|passphrase)\\?[\'"]?\s*[:=]\s*\\?[\'"]?([A-Za-z0-9_@#%!.+/=+\-]{8,256})',
     "MEDIUM", "credential", ""),
    ("Generic Secret/Token (broad)", r'(?i)(?<![a-z0-9_])(?:secret|token|auth|credential|apikey)\s{0,3}[:=]\s{0,3}\W?([A-Za-z0-9_+/=.\-]{16,})', "LOW", "generic", ""),

    # ── Generic / Heuristic ──
    ("Generic API Key", r'(?i)(?:api[_\-]key|api[_\-]secret|access[_\-]key)\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', "LOW", "generic", ""),
    # ── TruffleHog / Modern SaaS & Secrets (Extended Suite) ──
    ("Shopify App Token", r'(?<![A-Za-z0-9_\-])shp(?:at|ca)_[a-fA-F0-9]{32}(?![A-Za-z0-9_\-])', "HIGH", "shopify", "https://shopify.dev/docs/apps/auth"),
    ("Square Access Token", r'(?<![A-Za-z0-9_\-])sq0atp-[0-9A-Za-z\-_]{22}(?![A-Za-z0-9_\-])', "HIGH", "square", "https://developer.squareup.com/"),
    ("Square OAuth Secret", r'(?<![A-Za-z0-9_\-])sq0csp-[0-9A-Za-z\-_]{43}(?![A-Za-z0-9_\-])', "HIGH", "square", "https://developer.squareup.com/"),
    ("Sentry Auth Token", r'(?<![A-Za-z0-9_\-])sntrys_[a-f0-9]{64}(?![A-Za-z0-9_\-])', "HIGH", "sentry", "https://docs.sentry.io/api/auth/"),
    ("Linear API Key", r'(?<![A-Za-z0-9_\-])lin_api_[a-zA-Z0-9]{40}(?![A-Za-z0-9_\-])', "HIGH", "linear", "https://developers.linear.app/"),
    ("Supabase Service Role Key", r'(?<![A-Za-z0-9_\-])sbp_[a-zA-Z0-9]{40}(?![A-Za-z0-9_\-])', "HIGH", "supabase", "https://supabase.com/docs/guides/api"),
    ("HashiCorp Vault Token", r'(?<![A-Za-z0-9_\-])s\.[a-zA-Z0-9]{24}(?![A-Za-z0-9_\-])', "HIGH", "vault", "https://developer.hashicorp.com/vault"),
    ("PEM Private Key Header", r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', "HIGH", "crypto", ""),
    ("MySQL URI with Credentials", r'mysql://(?!.*@localhost)(?!.*@127\.)[^:@\s]{2,}:[^@\s]{4,}@[^\s]{5,}', "HIGH", "database", ""),
    ("Redis URI with Auth", r'redis://(?!.*@localhost)(?!.*@127\.)[^:@\s]{0,}:[^@\s]{4,}@[^\s]{5,}', "HIGH", "database", ""),
    ("MSSQL / SQL Server URI", r'mssql://(?!.*@localhost)(?!.*@127\.)[^:@\s]{2,}:[^@\s]{4,}@[^\s]{5,}', "HIGH", "database", ""),
]

COMPILED_PATTERNS = [(name, re.compile(pat), sev, tag, info) for name, pat, sev, tag, info in PATTERNS]


# ── Secret value validators (reduce false positives) ──────────────────────────
_SECRET_PLACEHOLDERS = {
    "", "null", "undefined", "none", "nil", "true", "false", "n/a", "na",
    "changeme", "changeit", "password", "secret", "your_api_key", "your-api-key",
    "xxx", "xxxx", "xxxxx", "todo", "tbd", "test", "testing", "demo", "sample",
    "dummy", "fake", "example", "placeholder", "insert_key_here", "redacted",
    "0123456789abcdef", "abcdef0123456789", "1234567890123456", "abcdefghijklmnop",
    "0000000000000000", "ffffffffffffffff", "aaaaaaaaaaaaaaaa",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_placeholder(val: str) -> bool:
    v = (val or "").strip().strip("'\"")
    if not v:
        return True
    low = v.lower()
    if low in _SECRET_PLACEHOLDERS:
        return True
    # PII placeholder set is defined later in this module; resolve at call time.
    pii = globals().get("_PII_PLACEHOLDERS")
    if isinstance(pii, set) and low in pii:
        return True
    if re.fullmatch(r"(.)\1{7,}", low):
        return True
    if re.fullmatch(r"(?:0123|abcd|xxxx|0000|1111|deadbeef)+", low):
        return True
    return False


def _is_b64ish(val: str) -> bool:
    s = re.sub(r"\s+", "", val or "")
    if len(s) < 16 or len(s) % 4 not in (0,):
        # allow missing padding
        pad = (-len(s)) % 4
        s = s + ("=" * pad)
    if not re.fullmatch(r"[A-Za-z0-9_\-+/]+=*", s):
        return False
    try:
        raw = base64.b64decode(s, validate=False)
        return len(raw) >= 12
    except Exception:
        return False


def _valid_heygen(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 32:
        return False
    # HeyGen keys are typically base64-ish or long opaque tokens.
    if _is_b64ish(val):
        return _shannon_entropy(val) >= 3.2
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]{32,}", val)) and _shannon_entropy(val) >= 3.5


def _valid_oauth_secret(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 16:
        return False
    # Skip obvious public client_ids mistaken for secrets
    if val.startswith(("http://", "https://", "urn:")):
        return False
    return _shannon_entropy(val) >= 3.0


def _valid_aes_key(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val):
        return False
    v = val.strip()
    # Hex AES-128/192/256
    if re.fullmatch(r"[0-9a-fA-F]{32}", v) or re.fullmatch(r"[0-9a-fA-F]{48}", v) or re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return _shannon_entropy(v.lower()) >= 2.5
    # Raw passphrase-length keys (16/24/32 chars) with decent entropy
    if len(v) in (16, 24, 32) and re.fullmatch(r"[A-Za-z0-9+/=_\-]{16,32}", v):
        return _shannon_entropy(v) >= 3.0
    # Base64 → 16/24/32 bytes
    if _is_b64ish(v):
        try:
            pad = (-len(v)) % 4
            raw = base64.b64decode(v + ("=" * pad), validate=False)
            return len(raw) in (16, 24, 32) and _shannon_entropy(v) >= 3.0
        except Exception:
            return False
    return False


def _valid_aes_payload(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 32:
        return False
    return _is_b64ish(val) and _shannon_entropy(val) >= 3.5


def _valid_generic_secret(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 20:
        return False
    return _shannon_entropy(val) >= 3.2


def _valid_password_value(val: str, text: str = "", idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 8:
        return False
    # Skip env interpolations / templates (value itself or surrounding assignment).
    if any(x in val for x in ("${", "{{", "<%", "%ENV", "<password>", "REDACTED")):
        return False
    win = (text or "")[max(0, idx - 24): idx + len(val) + 24]
    if any(x in win for x in ("${", "{{", "<%", "process.env", "os.environ", "os.getenv")):
        return False
    # Bare ENV_VAR style captures from inside "${DB_PASSWORD}"
    if re.fullmatch(r"[A-Z][A-Z0-9_]{7,}", val):
        return False
    if val.lower() in ("password", "passwd", "secret", "admin", "root", "user"):
        return False
    return _shannon_entropy(val) >= 2.8


def _valid_bearer_token(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 20:
        return False
    # JWT Token rule already covers three-segment JWTs — avoid duplicate noise.
    if val.count(".") >= 2 and val.startswith("eyJ"):
        return False
    return _shannon_entropy(val) >= 3.0


def _valid_basic_auth(val: str, _text: str = "", _idx: int = 0) -> bool:
    if _looks_placeholder(val) or len(val) < 16:
        return False
    try:
        pad = (-len(val)) % 4
        raw = base64.b64decode(val + ("=" * pad), validate=False).decode("utf-8", "ignore")
    except Exception:
        return False
    if ":" not in raw:
        return False
    user, _, pwd = raw.partition(":")
    if len(user) < 1 or len(pwd) < 4:
        return False
    return not _looks_placeholder(pwd)


def _valid_jdbc_url(val: str, _text: str = "", _idx: int = 0) -> bool:
    low = (val or "").lower()
    if not low.startswith("jdbc:"):
        return False
    # Skip in-memory / empty demo URLs
    if any(x in low for x in ("jdbc:h2:mem", "jdbc:sqlite::memory:", "localhost", "127.0.0.1", "example.com")):
        return False
    return "://" in low and len(val) >= 16


def _google_key_severity(val: str, text: str, idx: int, default_sev: str) -> str:
    """Elevate AIza keys when nearby context implies server / Translate usage."""
    win = text[max(0, idx - 100): idx + len(val) + 100].lower()
    if any(k in win for k in (
        "translate", "translation", "geocod", "places.googleapis",
        "generativelanguage", "gemini", "server.?key", "restrict",
    )):
        return "MEDIUM" if default_sev == "LOW" else default_sev
    return default_sev


# Optional validators: (value, full_text, match_start) -> bool
_SECRET_VALIDATORS: Dict[str, Callable[[str, str, int], bool]] = {
    "HeyGen API Key": _valid_heygen,
    "ROX CRM API Token": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 20 and _shannon_entropy(v) >= 3.0,
    "OAuth Client Secret": _valid_oauth_secret,
    "OAuth Refresh Token": _valid_oauth_secret,
    "Microsoft OAuth Client Secret": _valid_oauth_secret,
    "Google OAuth Client Secret": lambda v, t, i: (
        (v.upper().startswith("GOCSPX-") and len(v) >= 35 and not _looks_placeholder(v))
        or _valid_oauth_secret(v, t, i)
    ),
    "Slack OAuth Client Secret": _valid_oauth_secret,
    "Hardcoded AES Key": _valid_aes_key,
    "Hardcoded AES Payload": _valid_aes_payload,
    "Generic API Key": _valid_generic_secret,
    "Generic Secret": _valid_generic_secret,
    "Generic Secret/Token (broad)": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 20 and _shannon_entropy(v) >= 3.5,
    "Hardcoded Password (generic)": _valid_password_value,
    "Hardcoded Password (env/config)": _valid_password_value,
    "Password in Connection String": _valid_password_value,
    "SMTP Credential": _valid_password_value,
    "Bearer Token (header)": _valid_bearer_token,
    "Basic Auth Header": _valid_basic_auth,
    "JDBC URL": _valid_jdbc_url,
    "Dropbox Short-Lived Token": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 60 and _shannon_entropy(v) >= 3.2,
    "Segment Write Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) == 32 and _shannon_entropy(v) >= 3.0,
    "Datadog App Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) == 40,
    "Mistral API Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 32,
    "DeepSeek API Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 20,
    "Together AI Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 32,
    "Stability AI Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) >= 20,
    "ElevenLabs API Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) == 32,
    "Azure OpenAI Key": lambda v, t, i: (not _looks_placeholder(v)) and len(v) == 32,
}


# ══════════════════════════ INFRA / OPS (opt-in) ══════════════════════════════
# Gated behind include_infra. High-signal internal hosts always preferred;
# private IPs require non-mock context to avoid demo/seed false positives.

INFRA_PATTERNS: List[tuple] = [
    ("Kubernetes Internal Host",
     r'(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:svc\.cluster\.local)(?::\d{2,5})?\b',
     "HIGH", "k8s", ""),
    ("Docker Internal Host",
     r'(?i)\b(?:host\.docker\.internal|gateway\.docker\.internal)(?::\d{2,5})?\b',
     "MEDIUM", "docker", ""),
    ("Internal / Corp Hostname",
     r'(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:internal|corp|lan|localdomain|intranet)(?::\d{2,5})?\b',
     "MEDIUM", "infra", ""),
    ("Private IPv4 in URL",
     r'(?i)(?:https?|wss?)://((?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}))(?::(\d{2,5}))?(?:/[^\s\'"]*)?',
     "MEDIUM", "infra", ""),
    ("Private IPv4 Host:Port",
     r'(?<![\d.])((?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})):(0|[1-9]\d{1,4})(?![\d.])',
     "MEDIUM", "infra", ""),
    ("Localhost Service URL",
     r'(?i)(?:https?|wss?)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::(\d{2,5}))(?:/[^\s\'"]*)?',
     "LOW", "localhost", ""),
    ("Kubeconfig Token",
     r'(?i)(?:^|\n)\s*(?:token|client-key-data|client-certificate-data)\s*:\s*([A-Za-z0-9+/=_\-]{40,})',
     "HIGH", "k8s", ""),
    ("Internal Module Endpoint",
     r'(?i)["\']?(?:endpointURL|endpointUri|endpoint|websocket(?:URL|Uri)?|baseURL|baseUri|serviceUrl|apiUrl|callbackUrl|webhookUrl|redirectUrl|APPLICATION_CONTEXTS|APPLICATION_SCREENSHOT_CONTEXTS|connector-configurations|jobExecutionViewer)["\']?\s*[:=]\s*[\'"]([^\'"]{8,240})[\'"]',
     "MEDIUM", "infra", ""),
]

COMPILED_INFRA_PATTERNS = [
    (name, re.compile(pat), sev, tag, info) for name, pat, sev, tag, info in INFRA_PATTERNS
]

_INFRA_MOCK_CTX = re.compile(
    r'(?i)\b(?:mock|example|sample|demo|placeholder|dummy|fake|ipLogins|help\s*copy|'
    r'weak\s+validation|documentation|lorem|fixture|seed\s*data|test\s*data)\b'
)


def _infra_context_ok(text: str, idx: int, window: int = 140) -> bool:
    win = text[max(0, idx - window): idx + window]
    return not _INFRA_MOCK_CTX.search(win)


def _valid_private_ip_octets(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    # Skip broadcast / obviously bogus padded examples like 192.168.001.001 already normalized by int
    if nums == [0, 0, 0, 0] or nums[0] == 127:
        return False
    return True


# JSON / JS keys that commonly hold backend URLs (param-name detection).
_URL_KEY_SENSITIVE = {
    "endpointurl", "endpointuri", "endpoint", "endpoints",
    "baseurl", "baseuri", "basehref", "basepath", "basehost",
    "serviceurl", "serviceuri", "apiurl", "apiuri", "serverurl", "serveruri",
    "hosturl", "internalurl", "internalhost", "internalendpoint",
    "websocketurl", "websocketuri", "websocket", "wsurl", "wssurl",
    "callbackurl", "webhookurl", "redirecturl", "returnurl",
    "logouturl", "loginurl", "authurl", "tokenurl", "jwksurl",
    "siteurl", "appurl", "asseturl", "cdnurl", "mediaurl",
    "originurl", "origin",
    "applicationcontexts", "applicationscreenshotcontexts",
    "connectorconfigurations", "jobexecutionviewer",
}
_URL_KEY_GENERIC = {
    "url", "uri", "link", "href", "src", "targeturl", "location",
    "website", "webpage", "homepage", "weburl",
}

_URLISH_RE = re.compile(
    r'(?i)^(?:https?|wss?|ftp)://|^[a-z0-9][a-z0-9.\-]+(?:\.[a-z]{2,}|\.svc\.cluster\.local)(?::\d{2,5})?(?:/|$)'
)
_INTERNAL_URL_HINTS = (
    ".svc.", ".cluster.local", ".internal", ".corp", ".lan", ".localdomain",
    ".intranet", "localhost", "127.0.0.1", "0.0.0.0", "192.168.",
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def _value_looks_urlish(val: str) -> bool:
    v = (val or "").strip()
    if len(v) < 8 or len(v) > 500:
        return False
    low = v.lower()
    if low in ("null", "undefined", "none", "n/a", "-", "true", "false"):
        return False
    if low.startswith(("javascript:", "data:", "about:", "mailto:", "tel:", "#")):
        return False
    if low.startswith("/") and "://" not in low:
        return False
    return bool(_URLISH_RE.search(v))


def _value_looks_internal_url(val: str) -> bool:
    low = (val or "").lower()
    if "http://" in low or "ws://" in low:
        return True
    return any(h in low for h in _INTERNAL_URL_HINTS)


def _url_param_kind(key: str) -> Optional[str]:
    nk = _norm_key(key)
    if not nk:
        return None
    if nk in _URL_KEY_GENERIC:
        return "generic"
    if nk in _URL_KEY_SENSITIVE:
        return "sensitive"
    if nk.endswith(("url", "uri", "link")) and len(nk) >= 6:
        return "sensitive"
    if "endpoint" in nk or "websocket" in nk:
        return "sensitive"
    return None


def _classify_url_param(key: str, value: Any, source: str, host: str, url: str) -> Optional[Dict[str, Any]]:
    if value is None or isinstance(value, (bool, dict, list, int, float)):
        return None
    val = str(value).strip()
    if not val or not _value_looks_urlish(val):
        return None
    kind = _url_param_kind(key)
    if not kind:
        return None
    internal = _value_looks_internal_url(val)
    if kind == "generic" and not internal:
        return None
    if kind == "sensitive" and not internal:
        try:
            raw = val if "://" in val else "http://" + val
            vh = (urlparse(raw).netloc or "").split("@")[-1].split(":")[0].lower()
            ph = (host or "").split(":")[0].lower()
            if not vh or not ph or vh == ph or vh.endswith("." + ph) or ph.endswith("." + vh):
                return None
        except Exception:
            return None
    sev = "HIGH" if internal else "MEDIUM"
    return {
        "severity": sev,
        "type": f"URL Param · {key}",
        "value": val,
        "source": source,
        "host": host or "",
        "url": url,
        "service": "urlparam",
        "info_url": "",
    }


def scan_url_params_text(text: str, source: str, host: str, url: str) -> List[Dict[str, Any]]:
    """Detect URL-like JSON/JS keys: endpointURL, baseUrl, link, url, …"""
    if not text:
        return []
    if len(text) > MAX_SCAN_LEN:
        text = text[:MAX_SCAN_LEN]
    findings: List[Dict[str, Any]] = []
    seen = set()

    t = text.strip()
    if t[:1] in "{[":
        try:
            data = json.loads(t)
            pairs: list = []
            _walk_json_pairs(data, pairs)
            for k, v in pairs:
                f = _classify_url_param(k, v, source, host, url)
                if not f:
                    continue
                sig = (f["type"], f["value"])
                if sig in seen:
                    continue
                seen.add(sig)
                findings.append(f)
        except Exception:
            pass

    for m in _KV_RE.finditer(text):
        k = m.group(1) or m.group(3) or ""
        v = m.group(2) or m.group(4) or ""
        f = _classify_url_param(k, v, source, host, url)
        if not f:
            continue
        sig = (f["type"], f["value"])
        if sig in seen:
            continue
        seen.add(sig)
        findings.append(f)
    return findings


def scan_infra_text(text: str, source: str, host: str, url: str) -> List[Dict[str, Any]]:
    """Opt-in infra/ops exposure scan (k8s hosts, private IPs, internal endpoints)."""
    if not text:
        return []
    if len(text) > MAX_SCAN_LEN:
        text = text[:MAX_SCAN_LEN]
    findings = scan_url_params_text(text, source, host, url)
    for name, pattern, sev, tag, info in COMPILED_INFRA_PATTERNS:
        for m in pattern.finditer(text):
            if name in (
                "Private IPv4 in URL", "Private IPv4 Host:Port",
                "Localhost Service URL", "Internal Module Endpoint",
                "Internal / Corp Hostname",
            ) and not _infra_context_ok(text, m.start()):
                continue
            value = m.group(0)
            if name == "Private IPv4 in URL":
                ip = m.group(1)
                if not _valid_private_ip_octets(ip):
                    continue
                port = m.group(2)
                value = f"{ip}:{port}" if port else ip
            elif name == "Private IPv4 Host:Port":
                ip, port = m.group(1), m.group(2)
                if not _valid_private_ip_octets(ip):
                    continue
                try:
                    if not (1 <= int(port) <= 65535):
                        continue
                except ValueError:
                    continue
                value = f"{ip}:{port}"
            elif name == "Kubeconfig Token":
                value = m.group(1)
                if _looks_placeholder(value) or _shannon_entropy(value) < 3.5:
                    continue
            elif name == "Internal Module Endpoint":
                value = m.group(1).strip()
                # Only keep if value looks like an internal URL / host, not a relative path alone
                low = value.lower()
                if not any(x in low for x in (
                    "http://", "https://", "ws://", "wss://", ".svc.", ".internal",
                    "localhost", "127.0.0.1", "192.168.", "10.", "172.",
                )):
                    continue
            value = (value or "").strip()
            if not value or _looks_placeholder(value):
                continue
            findings.append({
                "severity": sev, "type": name, "value": value,
                "source": source, "host": host or "", "url": url,
                "service": tag, "info_url": info,
            })
    # Prefer URL-form private IP over bare host:port for the same value.
    url_ips = {f["value"] for f in findings if f["type"] == "Private IPv4 in URL"}
    findings = [
        f for f in findings
        if not (f["type"] == "Private IPv4 Host:Port" and f["value"] in url_ips)
    ]
    return findings

# ══════════════════════════ PII / SENSITIVE DATA (opt-in) ═════════════════════
# Gated behind include_pii. Only RESPONSE body/headers (never request — login
# POSTs legitimately carry password/email). Detection is value-validated:
# key name alone is NOT enough ("email":"xyz" must not fire).
#
# Strategy:
#   1) Walk JSON / nested dicts (typical POST/PUT API responses) — key + value
#   2) Shape-scan free text / headers for IBAN, IFSC, PAN, cards, emails, phones
#   3) Regex key=value fallback for non-JSON bodies
# Every hit must pass a type-specific validator (checksum / format / entropy).

# JWT in Authorization (and similar) request headers is expected session
# material — not an exposed secret. Still flag JWTs in URL / body / response.
# Expected session material in outbound request Authorization headers —
# still flagged in URL / body / response.
_SKIP_JWT_IN_REQUEST_HEADERS = {
    "JWT Token",
    "Bearer Token (header)",
    "Basic Auth Header",
}

_PII_PLACEHOLDERS = {
    "", "null", "undefined", "none", "nil", "true", "false", "n/a", "na", "nan",
    "-", "--", "---", ".", "*", "**", "***", "****", "*****", "x", "xx", "xxx",
    "xyz", "abc", "test", "testing", "demo", "sample", "dummy", "fake", "example",
    "string", "object", "array", "number", "boolean", "password", "passwd", "pwd",
    "email", "username", "user", "phone", "mobile", "token", "secret", "admin",
    "guest", "anonymous", "unknown", "redacted", "masked", "hidden", "private",
    "todo", "tbd", "changeme", "password123", "123456", "12345678", "qwerty",
    "user@example.com", "test@test.com", "email@email.com", "name@domain.com",
    "0000000000", "1111111111", "9999999999", "000000", "1234567890",
}

_EMAIL_RE = re.compile(
    r'^[A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?'
    r'@[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?'
    r'\.[A-Za-z]{2,24}$'
)
_EMAIL_FREE_RE = re.compile(
    r'(?<![A-Za-z0-9._%+\-])'
    r'([A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9])?'
    r'@[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,24})'
    r'(?![A-Za-z0-9._%+\-])'
)
_IFSC_RE = re.compile(r'^[A-Z]{4}0[A-Z0-9]{6}$')
_PAN_RE = re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$')
# India GSTIN: 2-digit state + PAN(10) + entity + 'Z' + checksum
_GSTIN_RE = re.compile(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$')
# India TAN: 4 letters + 5 digits + 1 letter
_TAN_RE = re.compile(r'^[A-Z]{4}[0-9]{5}[A-Z]$')
# India CIN (Company Identification Number)
_CIN_RE = re.compile(r'^[UL][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$')
_UPI_RE = re.compile(
    r'^[A-Za-z0-9._\-]{2,256}@[A-Za-z]{2,64}$'
)
_IBAN_RE = re.compile(r'^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$')
_SSN_RE = re.compile(r'^(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}$')
_AADHAAR_RE = re.compile(r'^\d{12}$')
_PHONE_RE = re.compile(
    r'^\+?[1-9]\d{6,14}$'  # E.164-ish after digit normalize
)
_CVV_RE = re.compile(r'^\d{3,4}$')
_ROUTING_RE = re.compile(r'^\d{9}$')
_SWIFT_RE = re.compile(r'^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$')

# Standalone shape extractors (value-only — no key required)
_IBAN_FREE_RE = re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{10,30})\b')
_IFSC_FREE_RE = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b')
_PAN_FREE_RE = re.compile(r'\b([A-Z]{5}[0-9]{4}[A-Z])\b')
_CARD_FREE_RE = re.compile(r'(?<!\d)((?:\d[ \-]*){12,18}\d)(?!\d)')
_AADHAAR_FREE_RE = re.compile(r'(?<!\d)(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)')
_SSN_FREE_RE = re.compile(r'\b(\d{3}-\d{2}-\d{4})\b')

# Key → semantic family (normalized key match)
_KEY_FAMILY = [
    ("password", re.compile(
        r'^(?:password|passwd|pwd|userpass(?:word)?|confirm(?:ation)?password|'
        r'oldpassword|newpassword|currentpassword|loginpassword)$')),
    ("email", re.compile(
        r'^(?:email|e[_-]?mail|emailaddress|mailid|useremail|primaryemail|'
        r'workemail|personalemail)$')),
    ("phone", re.compile(
        r'^(?:phone|phonenumber|mobile|mobilenumber|cellphone|telephone|'
        r'contactnumber|msisdn|whatsapp|tel)$')),
    # NOTE: do NOT include bare "name" / "displayName" — those are UI labels,
    # country lists, app module titles, etc. (massive FP source).
    ("username", re.compile(
        r'^(?:username|user[_-]?name|uname|loginid|loginname|screenname|'
        r'userid|login)$')),
    ("iban", re.compile(r'^(?:iban|ibannumber)$')),
    ("ifsc", re.compile(r'^(?:ifsc|ifsccode)$')),
    ("account", re.compile(
        r'^(?:bankaccount(?:number)?|accountnumber|acct(?:number|no|num)?|'
        r'bankacct|savingsaccount|currentaccount|accountno)$')),
    ("card", re.compile(
        r'^(?:cardnumber|creditcard(?:number)?|debitcard(?:number)?|'
        r'ccnumber|primaryaccountnumber)$')),
    ("cvv", re.compile(r'^(?:cvv|cvc|cvv2|cvc2|cardsecuritycode)$')),
    ("upi", re.compile(r'^(?:upi|upiid|vpa|virtualpaymentaddress)$')),
    ("routing", re.compile(r'^(?:routingnumber|abanumber|routingno|sortcode)$')),
    ("swift", re.compile(r'^(?:swift|swiftcode|bic|biccode)$')),
    # panNo / pan_no → panno after normalize (common API field names)
    ("pan_in", re.compile(
        r'^(?:pan|panno|pannumber|pancard|pancardno|pancardnumber|'
        r'permanentaccountnumber|incometaxpan|incometaxpanno)$')),
    ("gst_in", re.compile(
        r'^(?:gst|gstin|gstno|gstnumber|gstinno|gstinnumber|'
        r'goodsservicetax|goodsandservicetaxin)$')),
    ("tan_in", re.compile(
        r'^(?:tan|tanno|tannumber|taxdeductionaccountnumber|'
        r'taxcollectionaccountnumber)$')),
    ("vat", re.compile(
        r'^(?:vat|vatno|vatnumber|vatregistration(?:number|no)?|'
        r'tin|tinno|tinnumber|taxid|taxidentifier|taxidentification(?:number|no)?|'
        r'vattin|gstvat)$')),
    ("cin_in", re.compile(
        r'^(?:cin|cinno|cinnumber|companyidentificationnumber)$')),
    ("din_in", re.compile(
        r'^(?:din|dinno|dinnumber|directoridentificationnumber)$')),
    ("uan_in", re.compile(
        r'^(?:uan|uanno|uannumber|universalaccountnumber)$')),
    ("cr_number", re.compile(
        r'^(?:commercialregistration(?:number|no)?|crnumber|crno|'
        r'companyregistration(?:number|no)?)$')),
    ("aadhaar", re.compile(
        r'^(?:aadhaar|aadhar|aadhaarno|aadhaarnumber|uidai(?:number|no)?|'
        r'uidnumber|uidno)$')),
    ("ssn", re.compile(r'^(?:ssn|socialsecurity(?:number)?)$')),
    ("dob", re.compile(
        r'^(?:dob|dateofbirth|birthdate|birthday)$')),
    ("address", re.compile(
        r'^(?:address|streetaddress|homeaddress|residentialaddress|'
        r'permanentaddress|mailingaddress|fulladdress)$')),
    ("postal", re.compile(
        r'^(?:pincode|zipcode|postalcode|zip|pin)$')),
    ("token", re.compile(
        r'^(?:accesstoken|authtoken|refreshtoken|sessiontoken|idtoken|'
        r'bearertoken|apitoken)$')),
    ("passport", re.compile(
        r'^(?:passport|passportno|passportnumber)$')),
    ("license", re.compile(
        r'^(?:drivinglicense|driverlicense|dlnumber|licensenumber)$')),
]


def _norm_key(k: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(k).lower())


def _is_placeholder(val: str) -> bool:
    v = (val or "").strip()
    if not v:
        return True
    vl = v.lower()
    if vl in _PII_PLACEHOLDERS:
        return True
    # Masked / redacted forms
    if re.fullmatch(r'[\*•xX#]+', v):
        return True
    if re.fullmatch(r'[0\.\-]+', v):
        return True
    return False


def _digits_only(s: str) -> str:
    return re.sub(r'\D', '', s or "")


def _luhn_ok(num: str) -> bool:
    d = _digits_only(num)
    if not (13 <= len(d) <= 19):
        return False
    # Reject obvious fakes
    if len(set(d)) == 1:
        return False
    total, alt = 0, False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _iban_ok(iban: str) -> bool:
    raw = re.sub(r'\s+', '', (iban or "").upper())
    if not _IBAN_RE.fullmatch(raw):
        return False
    # ISO 13616 mod-97 checksum
    rearr = raw[4:] + raw[:4]
    num = ""
    for ch in rearr:
        if ch.isdigit():
            num += ch
        else:
            num += str(ord(ch) - 55)
    try:
        return int(num) % 97 == 1
    except Exception:
        return False


def _verhoeff_ok(num: str) -> bool:
    """Aadhaar uses Verhoeff checksum on 12 digits."""
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = d[c][p[i % 8][ord(ch) - 48]]
    return c == 0


def _valid_email(v: str) -> bool:
    v = (v or "").strip()
    if _is_placeholder(v) or not _EMAIL_RE.fullmatch(v):
        return False
    domain = v.rsplit("@", 1)[-1].lower()
    # Reject disposable / docs domains
    bad_domains = {
        "example.com", "example.org", "example.net", "test.com", "test.in",
        "email.com", "domain.com", "localhost", "mailinator.com", "yopmail.com",
        "sample.com", "fake.com", "xxx.com",
    }
    if domain in bad_domains:
        return False
    if domain.endswith(".local") or domain.endswith(".test"):
        return False
    local = v.split("@", 1)[0].lower()
    if local in {"test", "user", "admin", "demo", "sample", "email", "name", "xyz"}:
        return False
    return True


def _valid_phone_one(v: str) -> bool:
    if _is_placeholder(v):
        return False
    d = _digits_only(v)
    if len(d) < 7 or len(set(d)) <= 2:
        return False
    if v.strip().startswith("+"):
        return bool(_PHONE_RE.fullmatch("+" + d))
    # India: 10-digit mobile starting 6–9, or 91-prefixed
    if len(d) == 10 and d[0] in "6789":
        return True
    if len(d) == 12 and d.startswith("91") and d[2] in "6789":
        return True
    # GCC / intl: 9–12 digits often without +
    if 9 <= len(d) <= 12 and d[0] != "0":
        return True
    # Other national numbers: 7–15 digits, not starting with 0
    return bool(re.fullmatch(r"[1-9]\d{6,14}", d))


def _valid_phone(v: str) -> bool:
    """Accept a single phone or multi-number contact fields (joined by - / ,)."""
    if _valid_phone_one(v):
        return True
    # "+966 13 510 0144 - +966 56 433 3790" / "a / b"
    for part in re.split(r'[\s]*[-–,/|;][\s]*', v or ""):
        part = part.strip()
        if part and _valid_phone_one(part):
            return True
    return False


_PASSWORD_UI_WORDS = {
    "password", "password1", "passw0rd", "enabled", "disabled", "success",
    "failure", "failed", "submit", "submitted", "active", "inactive", "true",
    "false", "none", "null", "default", "required", "optional", "hidden",
    "visible", "change", "changed", "update", "updated", "reset", "locked",
    "unlocked", "expired", "valid", "invalid", "pending", "approved",
}


def _valid_password(v: str) -> bool:
    if _is_placeholder(v):
        return False
    # Real password exposure, including encrypted/base64 blobs (often 64–200 chars)
    if len(v) < 6 or len(v) > 512:
        return False
    if v.lower() in _PASSWORD_UI_WORDS:
        return False
    # Status / single dictionary words without complexity are UI noise
    if v.isalpha() and v.isascii() and len(v) <= 12:
        return False
    return True


# Country / territory names (lowercase) — common API list payloads (HR, KYC).
_COUNTRY_NAMES = {
    "afghanistan", "albania", "algeria", "andorra", "angola", "anguilla",
    "antarctica", "argentina", "armenia", "aruba", "australia", "austria",
    "azerbaijan", "bahamas", "bahrain", "bangladesh", "barbados", "belarus",
    "belgium", "belize", "benin", "bermuda", "bhutan", "bolivia", "botswana",
    "brazil", "brunei", "bulgaria", "burundi", "cambodia", "cameroon", "canada",
    "chad", "chile", "china", "colombia", "congo", "croatia", "cuba", "cyprus",
    "denmark", "djibouti", "dominica", "ecuador", "egypt", "eritrea", "estonia",
    "eswatini", "ethiopia", "fiji", "finland", "france", "gabon", "gambia",
    "georgia", "germany", "ghana", "gibraltar", "greece", "greenland", "grenada",
    "guadeloupe", "guam", "guatemala", "guernsey", "guinea", "guyana", "haiti",
    "honduras", "hungary", "iceland", "india", "indonesia", "iran", "iraq",
    "ireland", "israel", "italy", "jamaica", "japan", "jersey", "jordan",
    "kazakhstan", "kenya", "kiribati", "kuwait", "kyrgyzstan", "laos", "latvia",
    "lebanon", "lesotho", "liberia", "libya", "liechtenstein", "lithuania",
    "luxembourg", "macao", "madagascar", "malawi", "malaysia", "maldives", "mali",
    "malta", "martinique", "mauritania", "mauritius", "mayotte", "mexico",
    "micronesia", "moldova", "monaco", "mongolia", "montenegro", "montserrat",
    "morocco", "mozambique", "myanmar", "namibia", "nauru", "nepal", "netherlands",
    "nicaragua", "niger", "nigeria", "niue", "norway", "oman", "pakistan", "palau",
    "panama", "paraguay", "peru", "philippines", "poland", "portugal", "qatar",
    "romania", "russia", "rwanda", "samoa", "senegal", "serbia", "seychelles",
    "singapore", "slovakia", "slovenia", "somalia", "spain", "sudan", "suriname",
    "sweden", "switzerland", "syria", "taiwan", "tajikistan", "tanzania",
    "thailand", "togo", "tonga", "tunisia", "turkey", "turkmenistan", "tuvalu",
    "uganda", "ukraine", "uruguay", "uzbekistan", "vanuatu", "venezuela",
    "vietnam", "yemen", "zambia", "zimbabwe",
    "american samoa", "antigua and barbuda", "bosnia and herzegovina",
    "burkina faso", "cape verde", "central african republic", "costa rica",
    "czech republic", "dominican republic", "el salvador", "equatorial guinea",
    "faroe islands", "french guiana", "french polynesia", "hong kong",
    "isle of man", "ivory coast", "marshall islands", "new zealand",
    "north korea", "north macedonia", "northern mariana islands",
    "papua new guinea", "puerto rico", "saudi arabia", "sierra leone",
    "solomon islands", "south africa", "south korea", "south sudan",
    "sri lanka", "trinidad and tobago", "united arab emirates", "united kingdom",
    "united states", "vatican city", "virgin islands", "western sahara",
}


def _looks_like_unix_ms(d: str) -> bool:
    """13-digit millisecond epoch (IDs / modificationTime) — not a PAN."""
    if len(d) != 13 or not d.isdigit():
        return False
    try:
        n = int(d)
    except Exception:
        return False
    # ~2001-09 → ~2100-01 in ms
    return 1_000_000_000_000 <= n <= 4_102_444_800_000


def _looks_like_compact_datetime(d: str) -> bool:
    """YYYYMMDD / YYYYMMDDHHMMSS style stamps (e.g. 20260309114037)."""
    if not d.isdigit():
        return False
    if len(d) in (8, 14) and d.startswith(("19", "20")):
        mm = int(d[4:6])
        dd = int(d[6:8])
        if 1 <= mm <= 12 and 1 <= dd <= 31:
            return True
    return False


def _looks_like_card_iin(d: str) -> bool:
    """Major-scheme IIN/BIN prefixes — rejects random Luhn-passing IDs."""
    if not d.isdigit():
        return False
    n = len(d)
    if d[0] == "0":
        return False
    # Visa: 4 + 13/16/19
    if d.startswith("4") and n in (13, 16, 19):
        return True
    # Mastercard 51–55
    if n == 16 and d[:2] in {"51", "52", "53", "54", "55"}:
        return True
    # Mastercard 2-series 2221–2720
    if n == 16 and d[:4].isdigit() and 2221 <= int(d[:4]) <= 2720:
        return True
    # Amex
    if n == 15 and d[:2] in {"34", "37"}:
        return True
    # Discover
    if n == 16 and (d.startswith("6011") or d.startswith("65") or d.startswith("644")
                    or d.startswith("645") or d.startswith("646")
                    or d.startswith("647") or d.startswith("648") or d.startswith("649")):
        return True
    # JCB
    if n == 16 and d.startswith("35"):
        return True
    # UnionPay
    if d.startswith("62") and 16 <= n <= 19:
        return True
    # Diners
    if n == 14 and (d.startswith("36") or d.startswith("38") or d[:4] in {"3001", "3002", "3003", "3004", "3005"}
                    or (d[:3].isdigit() and 300 <= int(d[:3]) <= 305)):
        return True
    return False


def _valid_username(v: str) -> bool:
    if _is_placeholder(v):
        return False
    if len(v) < 3 or len(v) > 64:
        return False
    # Must look like an identifier, not a sentence / JSON fragment
    if not re.fullmatch(r'[A-Za-z0-9._@+\-]{3,64}', v):
        return False
    vl = v.lower()
    if vl in _COUNTRY_NAMES:
        return False
    # Title-Case proper noun alone (Albania, Rohit) — not a login id
    if re.fullmatch(r'[A-Z][a-z]{2,}', v):
        return False
    # SCREAMING_SNAKE / config constants (HRMS_APP_NAME, X101_SAMPLE_LIST_SERVER)
    if re.fullmatch(r'[A-Z0-9]+(?:_[A-Z0-9]+)+', v):
        return False
    # Pure digits — user ids belong under userid numeric fields elsewhere
    if v.isdigit():
        return False
    return True


def _valid_account(v: str) -> bool:
    if _is_placeholder(v):
        return False
    d = _digits_only(v)
    # Typical bank account: 8–18 digits (IN/EU/US common ranges)
    if not (8 <= len(d) <= 18):
        return False
    if len(set(d)) <= 2:
        return False
    # Timestamps / compact datetimes are not account numbers
    if _looks_like_unix_ms(d) or _looks_like_compact_datetime(d):
        return False
    # Leading-zero padded ledger IDs
    if d.startswith("0") and len(d) >= 12:
        return False
    return True


_IFSC_FAKE_BANKS = {
    "NONE", "TEST", "FAKE", "DEMO", "XXXX", "ABCD", "AAAA", "ZZZZ", "BANK",
    "NULL", "TEMP", "SAMPLE", "DUMMY",
}


def _valid_ifsc(v: str) -> bool:
    v = re.sub(r'\s+', '', (v or "").upper())
    if not _IFSC_RE.fullmatch(v):
        return False
    if v[:4] in _IFSC_FAKE_BANKS:
        return False
    # Branch "000000" / "ABCDEF" style placeholders
    branch = v[5:]
    if branch in {"000000", "111111", "ABCDEF", "XXXXXX", "123456"}:
        return False
    return True


_PAN_FAKE = {
    "AAAAA0000A", "ABCDE1234F", "XXXXX0000X", "PANPA1234A", "AAAAA1111A",
}


def _valid_pan(v: str) -> bool:
    v = re.sub(r'\s+', '', (v or "").upper())
    if not _PAN_RE.fullmatch(v):
        return False
    if v in _PAN_FAKE:
        return False
    # 4th char is person/status code — must be P/C/H/F/A/T/B/L/J/G (IT rules)
    if v[3] not in "PCHFATBLJG":
        return False
    return True


def _valid_gst(v: str) -> bool:
    """India GSTIN (strict) or gstNo-field values that still look like tax IDs."""
    if _is_placeholder(v):
        return False
    v = re.sub(r'[\s\-]', '', (v or "").upper())
    if len(v) < 8 or len(v) > 20:
        return False
    if _GSTIN_RE.fullmatch(v):
        return True
    # Prefixed vendor forms e.g. GSTIN89765430 (seen in live APIs)
    if v.startswith("GSTIN") and len(v) >= 10:
        rest = v[5:]
        if any(c.isdigit() for c in rest) and any(c.isalpha() for c in rest):
            return True
    # Bare alphanumeric tax-id style when length matches GSTIN-ish
    if 10 <= len(v) <= 15 and re.fullmatch(r'[A-Z0-9]+', v):
        if sum(c.isalpha() for c in v) >= 2 and sum(c.isdigit() for c in v) >= 2:
            if v not in {"GSTIN00000000", "AAAAAAAAAAAAAAA", "000000000000000"}:
                return True
    return False


def _valid_tan(v: str) -> bool:
    """India TAN (strict) or tanNo-field alphanumeric IDs."""
    if _is_placeholder(v):
        return False
    v = re.sub(r'\s+', '', (v or "").upper())
    if _TAN_RE.fullmatch(v):
        return v not in {"AAAA00000A", "DELF12345A"}
    # Key-confirmed TAN-like (APIs sometimes use non-standard shapes)
    if 8 <= len(v) <= 12 and re.fullmatch(r'[A-Z0-9]+', v):
        if sum(c.isalpha() for c in v) >= 3 and sum(c.isdigit() for c in v) >= 2:
            return True
    return False


def _valid_vat(v: str) -> bool:
    """VAT / tax identifier — Saudi 15-digit, EU VAT, generic tax id."""
    if _is_placeholder(v):
        return False
    raw = re.sub(r'[\s\-.]', '', (v or "").upper())
    if len(raw) < 8:
        return False
    d = _digits_only(raw)
    # Saudi / GCC VAT: 15 digits starting with 3
    if len(d) == 15 and d.startswith("3") and len(set(d)) > 2:
        return True
    # EU VAT style: 2-letter country + 8–12 alnum
    if re.fullmatch(r'[A-Z]{2}[A-Z0-9]{8,12}', raw):
        return True
    # Generic numeric/alphanumeric tax id (8–20) with enough digits
    if 8 <= len(raw) <= 20 and re.fullmatch(r'[A-Z0-9]+', raw):
        if sum(c.isdigit() for c in raw) >= 6 and len(set(raw)) > 2:
            # Reject pure words without digits already handled; reject labels
            if raw.lower() in {"googlecloud", "none", "null", "notapplicable"}:
                return False
            # taxIdentifier: "Google_cloud" has underscore stripped → GOOGLECLOUD — no digits → fail
            return True
    return False


def _valid_cin(v: str) -> bool:
    v = re.sub(r'\s+', '', (v or "").upper())
    return bool(_CIN_RE.fullmatch(v))


def _valid_din(v: str) -> bool:
    d = _digits_only(v)
    if not re.fullmatch(r'\d{8}', d):
        return False
    return len(set(d)) > 2


def _valid_uan(v: str) -> bool:
    d = _digits_only(v)
    if not re.fullmatch(r'\d{12}', d):
        return False
    return len(set(d)) > 2 and d[0] != "0"


def _valid_cr_number(v: str) -> bool:
    """Commercial / company registration numbers (Saudi CR, etc.)."""
    if _is_placeholder(v):
        return False
    d = _digits_only(v)
    # Saudi CR often 10 digits; allow 8–15 digit registration ids
    if 8 <= len(d) <= 15 and len(set(d)) > 2 and not d.startswith("0" * 3):
        return True
    raw = re.sub(r'[\s\-]', '', (v or "").upper())
    if 8 <= len(raw) <= 20 and re.fullmatch(r'[A-Z0-9]+', raw):
        if sum(c.isdigit() for c in raw) >= 5:
            return True
    return False


def _valid_aadhaar(v: str) -> bool:
    d = _digits_only(v)
    if not _AADHAAR_RE.fullmatch(d):
        return False
    if len(set(d)) <= 2:
        return False
    # UIDAI: first digit 2–9; Verhoeff checksum
    if d[0] == "0" or d[0] == "1":
        return False
    return _verhoeff_ok(d)


def _valid_ssn(v: str) -> bool:
    v = (v or "").strip()
    return bool(_SSN_RE.fullmatch(v))


def _valid_card(v: str) -> bool:
    if _is_placeholder(v):
        return False
    d = _digits_only(v)
    if not (13 <= len(d) <= 19):
        return False
    # Epoch ms / YYYYMMDDHHMMSS often pass Luhn by chance (modificationTime, etc.)
    if _looks_like_unix_ms(d) or _looks_like_compact_datetime(d):
        return False
    if not _looks_like_card_iin(d):
        return False
    return _luhn_ok(d)


def _valid_cvv(v: str) -> bool:
    v = (v or "").strip()
    if not _CVV_RE.fullmatch(v):
        return False
    return v not in {"000", "0000", "123", "111", "999"}


def _valid_upi(v: str) -> bool:
    v = (v or "").strip().lower()
    if _is_placeholder(v) or not _UPI_RE.fullmatch(v):
        return False
    # Must not look like a normal email (has TLD with dot) — UPI handles have no dot in PSP
    handle, _, psp = v.partition("@")
    if "." in psp:  # email-like
        return False
    if handle in {"test", "demo", "user", "xyz", "sample"}:
        return False
    return len(psp) >= 2


def _valid_routing(v: str) -> bool:
    d = _digits_only(v)
    if not _ROUTING_RE.fullmatch(d):
        return False
    # ABA checksum
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    return sum(int(a) * b for a, b in zip(d, weights)) % 10 == 0


# ISO 3166-1 alpha-2 used in BIC positions 5–6 (common set; rejects TE/XX junk)
_ISO_CC = {
    "AD","AE","AF","AG","AI","AL","AM","AO","AQ","AR","AS","AT","AU","AW","AX","AZ",
    "BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN","BO","BQ","BR","BS",
    "BT","BV","BW","BY","BZ","CA","CC","CD","CF","CG","CH","CI","CK","CL","CM","CN",
    "CO","CR","CU","CV","CW","CX","CY","CZ","DE","DJ","DK","DM","DO","DZ","EC","EE",
    "EG","EH","ER","ES","ET","FI","FJ","FK","FM","FO","FR","GA","GB","GD","GE","GF",
    "GG","GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT","GU","GW","GY","HK","HM",
    "HN","HR","HT","HU","ID","IE","IL","IM","IN","IO","IQ","IR","IS","IT","JE","JM",
    "JO","JP","KE","KG","KH","KI","KM","KN","KP","KR","KW","KY","KZ","LA","LB","LC",
    "LI","LK","LR","LS","LT","LU","LV","LY","MA","MC","MD","ME","MF","MG","MH","MK",
    "ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV","MW","MX","MY","MZ","NA",
    "NC","NE","NF","NG","NI","NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF","PG",
    "PH","PK","PL","PM","PN","PR","PS","PT","PW","PY","QA","RE","RO","RS","RU","RW",
    "SA","SB","SC","SD","SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO","SR","SS",
    "ST","SV","SX","SY","SZ","TC","TD","TF","TG","TH","TJ","TK","TL","TM","TN","TO",
    "TR","TT","TV","TW","TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE","VG","VI",
    "VN","VU","WF","WS","YE","YT","ZA","ZM","ZW",
}


def _valid_swift(v: str) -> bool:
    v = re.sub(r'\s+', '', (v or "").upper())
    if not _SWIFT_RE.fullmatch(v):
        return False
    # BIC[4:6] = ISO country; location "XX" is reserved for test
    if v[4:6] not in _ISO_CC:
        return False
    if v[6:8] == "XX":
        return False
    if v[:4] in {"TEST", "XXXX", "NONE", "FAKE", "DEMO"}:
        return False
    return True


def _valid_dob(v: str) -> bool:
    if _is_placeholder(v):
        return False
    v = v.strip()
    # ISO / common date forms with plausible year
    m = re.fullmatch(
        r'(\d{4})[-/](\d{1,2})[-/](\d{1,2})'
        r'|(\d{1,2})[-/](\d{1,2})[-/](\d{4})',
        v,
    )
    if not m:
        return False
    if m.group(1):
        year = int(m.group(1))
    else:
        year = int(m.group(6))
    return 1920 <= year <= 2015


_ADDRESS_UI_LABELS = {
    "personal info", "personal information", "home address", "office address",
    "work address", "mailing address", "permanent address", "residential address",
    "street address", "full address", "address line", "address line 1",
    "address line 2", "enter address", "n/a", "not available", "same as above",
}


def _valid_address(v: str) -> bool:
    if _is_placeholder(v):
        return False
    v = v.strip()
    # Need real street-like content, not a single token / UI label
    if len(v) < 10 or len(v) > 300:
        return False
    if v.lower() in _ADDRESS_UI_LABELS:
        return False
    # Require a digit (house / street no) — "Personal Info" style labels fail
    if not re.search(r'\d', v):
        return False
    words = re.findall(r'[A-Za-z]{2,}', v)
    return len(words) >= 2


def _valid_postal(v: str) -> bool:
    if _is_placeholder(v):
        return False
    v = v.strip()
    # Reject trivial / sequential placeholders
    if v in {"000000", "111111", "123456", "00000", "11111", "12345", "99999"}:
        return False
    # IN PIN 6-digit; US ZIP 5 or 5+4
    if re.fullmatch(r'[1-9]\d{5}', v):
        return True
    if re.fullmatch(r'\d{5}(-\d{4})?', v):
        return True
    if re.fullmatch(r'[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}', v.upper()):  # UK
        return True
    return False


def _valid_token(v: str) -> bool:
    if _is_placeholder(v):
        return False
    v = v.strip()
    # Strip Bearer prefix if present
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    if len(v) < 16 or len(v) > 2048:
        return False
    # JWT
    if v.count(".") == 2 and v.startswith("eyJ"):
        return True
    # UUIDs are identifiers, not auth tokens
    if re.fullmatch(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        v,
    ):
        return False
    # Opaque token — enough entropy (not repeated char / trivial)
    if re.fullmatch(r'[A-Za-z0-9_\-+/=.]{20,}', v):
        if len(set(v)) < 8:
            return False
        if re.fullmatch(r'(.)\1{19,}', v):
            return False
        return True
    return False


def _valid_passport(v: str) -> bool:
    if _is_placeholder(v):
        return False
    v = v.strip().upper()
    # Reject status / module words
    if v in {"ACTIVE", "INACTIVE", "PENDING", "EXPIRED", "VALID", "INVALID",
             "HRCORE", "HR-CORE", "PASSPORT", "NONE", "NULL"}:
        return False
    # Common: 1–2 letters + 6–9 alnum (IN: letter+7digits, US varies)
    if not (re.fullmatch(r'[A-Z0-9]{6,12}', v) and any(c.isalpha() for c in v)):
        return False
    # Need at least 3 digits — rejects ACTIVE12-style soft matches less often,
    # and MODULE01 config codes
    if sum(c.isdigit() for c in v) < 3:
        return False
    return True


def _valid_license(v: str) -> bool:
    if _is_placeholder(v):
        return False
    v = v.strip().upper()
    if v in {"HR-CORE", "HRCORE", "LICENSE", "NONE", "NULL", "ACTIVE"}:
        return False
    if not (re.fullmatch(r'[A-Z0-9\-]{5,20}', v) and sum(c.isdigit() for c in v) >= 2):
        return False
    # Prefer at least one letter + digits (not pure module codes like X101)
    if not any(c.isalpha() for c in v):
        return False
    return True


_FAMILY_META = {
    # family: (finding_type, severity, validator)
    "password": ("Password Exposed", "HIGH", _valid_password),
    "email":    ("Email Address Exposed", "MEDIUM", _valid_email),
    "phone":    ("Phone Number Exposed", "MEDIUM", _valid_phone),
    "username": ("Username Exposed", "LOW", _valid_username),
    "iban":     ("IBAN Exposed", "HIGH", _iban_ok),
    "ifsc":     ("IFSC Code Exposed", "HIGH", _valid_ifsc),
    "account":  ("Bank Account Number Exposed", "HIGH", _valid_account),
    "card":     ("Payment Card Number Exposed", "HIGH", _valid_card),
    "cvv":      ("CVV / CVC Exposed", "HIGH", _valid_cvv),
    "upi":      ("UPI ID Exposed", "HIGH", _valid_upi),
    "routing":  ("Bank Routing Number Exposed", "HIGH", _valid_routing),
    "swift":    ("SWIFT / BIC Code Exposed", "HIGH", _valid_swift),
    "pan_in":   ("PAN (India) Exposed", "HIGH", _valid_pan),
    "gst_in":   ("GSTIN / GST Number Exposed", "HIGH", _valid_gst),
    "tan_in":   ("TAN (India) Exposed", "HIGH", _valid_tan),
    "vat":      ("VAT / Tax Identifier Exposed", "HIGH", _valid_vat),
    "cin_in":   ("CIN (India) Exposed", "HIGH", _valid_cin),
    "din_in":   ("DIN (India) Exposed", "MEDIUM", _valid_din),
    "uan_in":   ("UAN (India) Exposed", "MEDIUM", _valid_uan),
    "cr_number": ("Commercial Registration Number Exposed", "MEDIUM", _valid_cr_number),
    "aadhaar":  ("Aadhaar Number Exposed", "HIGH", _valid_aadhaar),
    "ssn":      ("SSN Exposed", "HIGH", _valid_ssn),
    "dob":      ("Date of Birth Exposed", "MEDIUM", _valid_dob),
    "address":  ("Physical Address Exposed", "MEDIUM", _valid_address),
    "postal":   ("Postal / ZIP Code Exposed", "LOW", _valid_postal),
    "token":    ("Access/Auth Token Exposed", "HIGH", _valid_token),
    "passport": ("Passport Number Exposed", "HIGH", _valid_passport),
    "license":  ("Driving License Exposed", "MEDIUM", _valid_license),
}


def _family_for_key(key: str) -> Optional[str]:
    nk = _norm_key(key)
    if not nk:
        return None
    for fam, cre in _KEY_FAMILY:
        if cre.fullmatch(nk):
            return fam
    return None


def _finding(ftype: str, value: str, sev: str, source: str, host: str, url: str) -> Dict[str, Any]:
    return {
        "severity": sev, "type": ftype, "value": value.strip(),
        "source": source, "host": host or "", "url": url,
        "service": "pii", "info_url": "",
    }


def _classify_key_value(key: str, value: Any, source: str, host: str, url: str) -> Optional[Dict[str, Any]]:
    if value is None or isinstance(value, (bool, dict, list)):
        return None
    val = str(value).strip()
    if not val or _is_placeholder(val):
        return None
    # Skip taxIdentifier-style labels with no digits (e.g. "Google_cloud")
    fam = _family_for_key(key)
    if not fam:
        return None
    ftype, sev, validator = _FAMILY_META[fam]
    try:
        ok = validator(val)
    except Exception:
        ok = False
    if not ok:
        # Multi-phone contact fields: report first valid segment
        if fam == "phone":
            for part in re.split(r'[\s]*[-–,/|;][\s]*', val):
                part = part.strip()
                try:
                    if part and _valid_phone_one(part):
                        return _finding(ftype, part, sev, source, host, url)
                except Exception:
                    pass
        return None
    # Prefer a clean single phone when the field holds several
    if fam == "phone" and not _valid_phone_one(val):
        for part in re.split(r'[\s]*[-–,/|;][\s]*', val):
            part = part.strip()
            if part and _valid_phone_one(part):
                return _finding(ftype, part, sev, source, host, url)
    return _finding(ftype, val, sev, source, host, url)


def _walk_embedded_json_string(s: str, out: list, depth: int) -> None:
    """If a JSON string value is itself JSON (common for nested payloads), walk it."""
    t = (s or "").strip()
    if depth > 12 or len(t) < 8 or t[:1] not in "{[":
        return
    try:
        data = json.loads(t)
    except Exception:
        return
    if isinstance(data, (dict, list)):
        _walk_json_pairs(data, out, depth)


def _walk_json_pairs(obj: Any, out: list, depth: int = 0):
    """Collect (key, scalar_value) pairs from nested JSON."""
    if depth > 12:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _walk_json_pairs(v, out, depth + 1)
            else:
                out.append((str(k), v))
                if isinstance(v, str):
                    _walk_embedded_json_string(v, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:200]:  # cap huge arrays
            _walk_json_pairs(item, out, depth + 1)
            if isinstance(item, str):
                _walk_embedded_json_string(item, out, depth + 1)


def _scan_pii_json(text: str, source: str, host: str, url: str) -> List[Dict[str, Any]]:
    t = text.strip()
    if not t or t[0] not in "{[":
        return []
    try:
        data = json.loads(t)
    except Exception:
        return []
    pairs: list = []
    _walk_json_pairs(data, pairs)
    findings = []
    for k, v in pairs:
        f = _classify_key_value(k, v, source, host, url)
        if f:
            findings.append(f)
    return findings


# Regex key=value for non-JSON / HTML / header lines
_KV_RE = re.compile(
    r'(?i)\\?[\'"]([A-Za-z][A-Za-z0-9_\-]{1,64})\\?[\'"]\s*[:=]\s*\\?[\'"]([^\'"\\\n\r]{1,512})\\?[\'"]'
    r'|\\?[\'"]?([A-Za-z][A-Za-z0-9_\-]{1,64})\\?[\'"]?\s*[:=]\s*([^\s,;\'"}\]\\]{1,256})'
)


def _scan_pii_kv_regex(text: str, source: str, host: str, url: str) -> List[Dict[str, Any]]:
    findings = []
    for m in _KV_RE.finditer(text):
        if m.group(1) is not None:
            key, val = m.group(1), m.group(2)
        else:
            key, val = m.group(3), m.group(4)
        val = (val or "").strip().rstrip("\\")
        f = _classify_key_value(key, val, source, host, url)
        if f:
            findings.append(f)
    return findings


def _scan_pii_shapes(text: str, source: str, host: str, url: str,
                     *, skip_bare_ids: bool = False) -> List[Dict[str, Any]]:
    """
    Value-shape detection. Prefer key+value (JSON / kv) for ambiguous IDs.

    skip_bare_ids=True when the body already walked as JSON — card / Aadhaar
    free-scans then only add FPs (timestamps, record ids) without key context.
    """
    findings = []

    for m in _EMAIL_FREE_RE.finditer(text):
        v = m.group(1)
        if _valid_email(v):
            findings.append(_finding("Email Address Exposed", v, "MEDIUM", source, host, url))

    for m in _IBAN_FREE_RE.finditer(text):
        v = m.group(1)
        if _iban_ok(v):
            findings.append(_finding("IBAN Exposed", v, "HIGH", source, host, url))

    # IFSC / PAN in free text — only with nearby keyword (random ABCD0XXXXXX / ABCDE1234F noise)
    for m in re.finditer(
        r'(?i)(?:ifsc(?:\s*code)?|ifsccode)[^A-Z0-9]{0,24}([A-Z]{4}0[A-Z0-9]{6})',
        text,
    ):
        v = m.group(1)
        if _valid_ifsc(v):
            findings.append(_finding("IFSC Code Exposed", v, "HIGH", source, host, url))

    for m in re.finditer(
        r'(?i)(?:\bpan\b|pan[_ ]?(?:no|number|card)|pancard|permanent\s*account)'
        r'[^A-Z0-9]{0,24}([A-Z]{5}[0-9]{4}[A-Z])',
        text,
    ):
        v = m.group(1)
        if _valid_pan(v):
            findings.append(_finding("PAN (India) Exposed", v, "HIGH", source, host, url))

    # GSTIN / GST number near keyword
    for m in re.finditer(
        r'(?i)(?:gstin|gst[_ ]?(?:no|number)|goods\s*and\s*services\s*tax)'
        r'[^A-Z0-9]{0,24}'
        r'([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]|GSTIN[A-Z0-9]{8,15})',
        text,
    ):
        v = m.group(1)
        if _valid_gst(v):
            findings.append(_finding("GSTIN / GST Number Exposed", v, "HIGH", source, host, url))

    # TAN near keyword
    for m in re.finditer(
        r'(?i)(?:\btan\b|tan[_ ]?(?:no|number)|tax\s*deduction\s*account)'
        r'[^A-Z0-9]{0,24}([A-Z]{4}[0-9]{5}[A-Z])',
        text,
    ):
        v = m.group(1)
        if _valid_tan(v):
            findings.append(_finding("TAN (India) Exposed", v, "HIGH", source, host, url))

    # VAT registration (esp. Saudi 15-digit) near keyword
    # NOTE: use \b around tin — bare "tin" matches inside "GSTIN…" and FPs.
    for m in re.finditer(
        r'(?i)(?:\bvat[_ ]?(?:no|number|reg(?:istration)?)?\b|\btax[_ ]?identifier\b|'
        r'\btin\b(?:[_ ]?(?:no|number))?|\bvatregistration(?:number|no)?\b)'
        r'[^0-9A-Z]{0,24}([0-9]{8,15}|[A-Z]{2}[A-Z0-9]{8,12})',
        text,
    ):
        v = m.group(1)
        if _valid_vat(v):
            findings.append(_finding("VAT / Tax Identifier Exposed", v, "HIGH", source, host, url))

    for m in _SSN_FREE_RE.finditer(text):
        v = m.group(1)
        if _valid_ssn(v):
            findings.append(_finding("SSN Exposed", v, "HIGH", source, host, url))

    if not skip_bare_ids:
        # Aadhaar: require keyword — bare 12-digit groups collide with IDs
        for m in re.finditer(
            r'(?i)(?:aadhaar|aadhar|uidai)[^0-9]{0,24}'
            r'(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})',
            text,
        ):
            v = m.group(1)
            if _valid_aadhaar(v):
                findings.append(_finding("Aadhaar Number Exposed", v, "HIGH", source, host, url))

        # Cards only when a card-ish keyword sits nearby — never bare digit runs
        for m in re.finditer(
            r'(?i)(?:card\s*(?:number|no|#)?|credit\s*card|debit\s*card|'
            r'ccnum|cardnum|primaryaccountnumber)'
            r'[^0-9]{0,32}'
            r'((?:\d[ \-]*){12,18}\d)',
            text,
        ):
            raw = m.group(1)
            if _valid_card(raw):
                findings.append(_finding(
                    "Payment Card Number Exposed", _digits_only(raw), "HIGH", source, host, url,
                ))

    # Phones: only when near a phone-ish keyword OR E.164 with +
    # (bare 10-digit numbers FP heavily in IDs)
    for m in re.finditer(
        r'(?i)(?:phone|mobile|tel|msisdn|whatsapp|contact)[^0-9+]{0,24}'
        r'(\+?\d[\d\s\-().]{7,18}\d)',
        text,
    ):
        v = m.group(1)
        if _valid_phone(v):
            findings.append(_finding("Phone Number Exposed", v, "MEDIUM", source, host, url))
    for m in re.finditer(r'(?<!\w)(\+[1-9]\d{7,14})(?!\w)', text):
        v = m.group(1)
        if _valid_phone(v):
            findings.append(_finding("Phone Number Exposed", v, "MEDIUM", source, host, url))

    return findings


def scan_pii_text(text: str, source: str, host: str, url: str) -> List[Dict[str, Any]]:
    if not text:
        return []
    if len(text) > MAX_SCAN_LEN:
        text = text[:MAX_SCAN_LEN]

    findings: List[Dict[str, Any]] = []
    # Prefer structured JSON walk for API responses (POST/PUT/GET JSON)
    json_hits = _scan_pii_json(text, source, host, url)
    findings.extend(json_hits)
    # Key=value regex covers headers / form / HTML / partial JSON
    findings.extend(_scan_pii_kv_regex(text, source, host, url))
    # Shape scan: if JSON already walked, skip bare card/Aadhaar (key-first)
    findings.extend(_scan_pii_shapes(
        text, source, host, url, skip_bare_ids=bool(json_hits) or _is_json_body(text),
    ))

    # Local dedupe (JSON walk + kv + shapes often hit the same value)
    seen, out = set(), []
    for f in findings:
        key = (f["type"], f["value"], f["url"], f["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _is_json_body(text: str) -> bool:
    t = (text or "").lstrip()
    if not t or t[0] not in "{[":
        return False
    try:
        json.loads(t if len(t) <= MAX_SCAN_LEN else t[:MAX_SCAN_LEN])
        return True
    except Exception:
        return False


# ══════════════════════════ SCANNING ══════════════════════════════════════════

def scan_text(text: str, source: str, host: str, url: str,
              skip_types: Optional[set] = None) -> List[Dict[str, Any]]:
    if not text:
        return []
    if len(text) > MAX_SCAN_LEN:
        text = text[:MAX_SCAN_LEN]
    skip = skip_types or set()
    findings = []
    for name, pattern, sev, tag, info in COMPILED_PATTERNS:
        if name in skip:
            continue
        for m in pattern.finditer(text):
            value = m.group(0)
            if m.lastindex:
                for i in range(1, m.lastindex + 1):
                    g = m.group(i)
                    if g:
                        value = g
                        break
            if not value:
                continue
            value = value.strip()
            validator = _SECRET_VALIDATORS.get(name)
            if validator and not validator(value, text, m.start()):
                continue
            out_sev = sev
            if name == "GCP / Firebase API Key":
                out_sev = _google_key_severity(value, text, m.start(), sev)
            findings.append({
                "severity": out_sev, "type": name, "value": value,
                "source": source, "host": host or "", "url": url,
                "service": tag, "info_url": info,
            })
    # Prefer vendor-specific Google/OAuth findings over generic duplicates.
    specific_google = {
        f["value"] for f in findings
        if f["type"] in ("Google Translation API Key", "Gemini / Google AI Key")
    }
    specific_oauth = {
        f["value"] for f in findings
        if f["type"] in (
            "Google OAuth Client Secret", "Microsoft OAuth Client Secret",
            "Slack OAuth Client Secret", "Auth0 Client Secret",
        )
    }
    findings = [
        f for f in findings
        if not (
            (f["type"] == "GCP / Firebase API Key" and f["value"] in specific_google)
            or (f["type"] == "OAuth Client Secret" and f["value"] in specific_oauth)
        )
    ]
    return findings


# ══════════════════════════ TRUFFLEHOG SHANNON ENTROPY SCANNER ═══════════════
_ENTROPY_KEYWORD_REGEX = re.compile(
    r'(?i)[\'"]?(?<![a-z0-9_])(?:'
    r'api[_\-]?key|api[_\-]?secret|secret[_\-]?key|private[_\-]?key|'
    r'auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|session[_\-]?token|'
    r'bearer[_\-]?token|id[_\-]?token|oauth[_\-]?token|oauth[_\-]?secret|'
    r'client[_\-]?secret|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|'
    r'jwt[_\-]?secret|app[_\-]?secret|token[_\-]?secret|session[_\-]?secret|'
    r'webhook[_\-]?secret|service[_\-]?key|service[_\-]?secret|shared[_\-]?secret|'
    r'credential[s]?|db[_\-]?pass(?:word)?|database[_\-]?pass(?:word)?|'
    r'secret|token|apikey|appkey'
    r')[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9+/=_\-]{20,90})[\'"]?'
)


def scan_entropy_text(text: str, source: str, host: str, url: str) -> List[Dict[str, Any]]:
    """TruffleHog-style Shannon Entropy analysis to find unknown high-randomness secrets."""
    if not text:
        return []
    if len(text) > MAX_SCAN_LEN:
        text = text[:MAX_SCAN_LEN]
    findings = []
    seen = set()
    for m in _ENTROPY_KEYWORD_REGEX.finditer(text):
        val = m.group(1).strip("'\"")
        if not val or val in seen or len(val) < 20 or len(val) > 90:
            continue
        if _looks_placeholder(val):
            continue

        is_hit = False
        if re.fullmatch(r"[0-9a-fA-F]+", val):
            if re.search(r"\d", val) and re.search(r"[a-fA-F]", val):
                is_hit = _shannon_entropy(val.lower()) >= 3.2
        elif re.fullmatch(r"[0-9a-zA-Z+/=_\-]+", val):
            char_types = sum([
                bool(re.search(r"[A-Z]", val)),
                bool(re.search(r"[a-z]", val)),
                bool(re.search(r"\d", val)),
            ])
            if char_types >= 2 and not (re.fullmatch(r"[a-z0-9_]+", val) or re.fullmatch(r"[a-z0-9\-]+", val)):
                is_hit = _shannon_entropy(val) >= 3.7

        if is_hit:
            seen.add(val)
            findings.append({
                "severity": "MEDIUM",
                "type": "High-Entropy Secret (TruffleHog)",
                "value": val,
                "source": source,
                "host": host or "",
                "url": url,
                "service": "trufflehog",
                "info_url": "https://github.com/trufflesecurity/trufflehog",
            })
    return findings


def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for f in findings:
        key = (f["type"], f["value"], f["url"], f["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    out.sort(key=lambda r: sev_order.get(r["severity"], 9))
    return out


def _headers_blob(headers) -> str:
    return "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())


# Captured requests carry the browser's conditional-cache headers as-is. Replaying
# them verbatim makes the server correctly answer 304 Not Modified with an empty
# body — nothing to scan. Stripped here so every request always gets the real body.
_CACHE_HEADERS = {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}

# After Abort, new HTTP fires use a short timeout so in-flight workers exit fast.
TIMEOUT_ABORT = 1.5


def _interruptible_sleep(seconds: float, stop_event: threading.Event) -> bool:
    """Sleep in small slices; return False if abort was signalled."""
    if seconds <= 0:
        return not stop_event.is_set()
    end = time.time() + seconds
    while time.time() < end:
        if stop_event.is_set():
            return False
        time.sleep(min(0.05, max(0.0, end - time.time())))
    return not stop_event.is_set()


def _fire(url: str, method: str, headers: Dict[str, str], body: Any,
          timeout: float = TIMEOUT):
    if req_lib is None:
        raise RuntimeError("requests library not available")
    clean_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in _CACHE_HEADERS}
    kwargs = dict(headers=clean_headers, timeout=timeout, verify=VERIFY_SSL, allow_redirects=True)
    m = (method or "GET").upper()
    if body is not None and m in ("POST", "PUT", "PATCH"):
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
        else:
            kwargs["data"] = str(body)
    return req_lib.request(m, url, **kwargs)


# Cap on request/response body kept per log/finding for expand-to-validate.
# Bounded so a huge payload can't blow up memory across a long session, but
# large enough that typical API list responses stay searchable in the UI.
MAX_LOG_BODY = 200_000


def _find_needle_index(text: str, needle: Optional[str]) -> int:
    """Locate needle in text; falls back to digit-flexible phone matching."""
    if not text or not needle:
        return -1
    idx = text.find(needle)
    if idx >= 0:
        return idx
    collapsed = re.sub(r"\s+", "", needle)
    if collapsed and collapsed != needle:
        idx = text.find(collapsed)
        if idx >= 0:
            return idx
    digits = re.sub(r"\D", "", needle)
    if len(digits) >= 7:
        flex = r"[\s\-().]*".join(re.escape(d) for d in digits)
        m = re.search(r"\+?" + flex, text)
        if m:
            return m.start()
    return -1


def _clip_body_for_ui(
    text: Any,
    max_len: int = MAX_LOG_BODY,
    ensure_contains: Optional[str] = None,
) -> str:
    """Truncate body for UI storage, keeping a window around a finding value."""
    if text is None:
        return ""
    if not isinstance(text, str):
        try:
            text = json.dumps(text, ensure_ascii=False)
        except Exception:
            text = str(text)
    if len(text) <= max_len:
        return text
    idx = _find_needle_index(text, ensure_contains)
    if idx >= 0:
        # Keep the match roughly in the first half so it scrolls into view soon.
        start = max(0, idx - max_len // 4)
        end = min(len(text), start + max_len)
        start = max(0, end - max_len)
        chunk = text[start:end]
        prefix = "…[truncated before]…\n" if start > 0 else ""
        suffix = "\n…[truncated after]…" if end < len(text) else ""
        return prefix + chunk + suffix
    return text[:max_len] + "\n…[truncated]…"


def scan_endpoint(ep: "JsaEndpoint", stop_event: threading.Event,
                  include_pii: bool = False, include_infra: bool = False,
                  use_recorded: bool = False, enable_entropy: bool = False):
    # Abort checks at each stage — pending futures are also cancelled via
    # executor.shutdown(cancel_futures=True) from /jsa/abort.
    if stop_event.is_set():
        return None

    host = urlparse(ep.url).netloc
    # Split request scan so JWT can be skipped in headers only (auth noise),
    # while JWT leaked in URL / body is still reported.
    _url_body = [ep.url]
    if ep.body is not None:
        _url_body.append(ep.body if isinstance(ep.body, str) else json.dumps(ep.body))
    req_blob = "\n".join(_url_body)
    findings = scan_text(req_blob, "Request", host, ep.url)
    findings += scan_text(
        _headers_blob(ep.headers), "Request", host, ep.url,
        skip_types=_SKIP_JWT_IN_REQUEST_HEADERS,
    )
    if include_infra:
        findings += scan_infra_text(req_blob, "Request", host, ep.url)
        findings += scan_infra_text(
            _headers_blob(ep.headers), "Request", host, ep.url,
        )
    if enable_entropy:
        findings += scan_entropy_text(req_blob, "Request", host, ep.url)
        findings += scan_entropy_text(_headers_blob(ep.headers), "Request", host, ep.url)

    if stop_event.is_set():
        # Keep request-side findings already collected; skip live replay.
        return (findings, None, "aborted", ep.url, ep.method,
                ep.headers or {}, ep.body, "")

    status, error, resp_text = None, None, ""
    try:
        if use_recorded:
            # Offline path: scan HAR-recorded response — never hit the API.
            # Update-Token only changes request Authorization; recorded body stays as captured.
            status = ep.recorded_status
            resp_text = ep.recorded_body or ""
            resp_headers = ep.recorded_headers or {}
            if status is None and not resp_text and not resp_headers:
                error = "no recorded response"
            else:
                findings += scan_text(resp_text, "Response", host, ep.url)
                findings += scan_text(
                    _headers_blob(resp_headers), "Response Header", host, ep.url,
                )
                if include_infra:
                    findings += scan_infra_text(resp_text, "Response", host, ep.url)
                    findings += scan_infra_text(
                        _headers_blob(resp_headers), "Response Header", host, ep.url,
                    )
                if include_pii:
                    findings += scan_pii_text(resp_text, "Response", host, ep.url)
                    findings += scan_pii_text(
                        _headers_blob(resp_headers), "Response Header", host, ep.url,
                    )
                if enable_entropy:
                    findings += scan_entropy_text(resp_text, "Response", host, ep.url)
                    findings += scan_entropy_text(_headers_blob(resp_headers), "Response Header", host, ep.url)
        else:
            if not _interruptible_sleep(REQUEST_DELAY, stop_event):
                return (findings, None, "aborted", ep.url, ep.method,
                        ep.headers or {}, ep.body, "")

            # Shorter timeout once Abort is set so workers drain quickly.
            to = TIMEOUT_ABORT if stop_event.is_set() else TIMEOUT
            if stop_event.is_set():
                return (findings, None, "aborted", ep.url, ep.method,
                        ep.headers or {}, ep.body, "")

            resp = _fire(ep.url, ep.method, ep.headers, ep.body, timeout=to)
            if stop_event.is_set():
                # Drop response processing — request findings already captured.
                return (findings, getattr(resp, "status_code", None), "aborted",
                        ep.url, ep.method, ep.headers or {}, ep.body, "")

            resp_text = resp.text or ""
            status = resp.status_code
            findings += scan_text(resp_text, "Response", host, ep.url)
            # Secrets in response headers too (Set-Cookie, custom tokens, etc.).
            # Source label matches the Results "Response Header" filter.
            findings += scan_text(
                _headers_blob(resp.headers), "Response Header", host, ep.url,
            )
            if include_infra:
                findings += scan_infra_text(resp_text, "Response", host, ep.url)
                findings += scan_infra_text(
                    _headers_blob(resp.headers), "Response Header", host, ep.url,
                )
            if include_pii:
                findings += scan_pii_text(resp_text, "Response", host, ep.url)
                findings += scan_pii_text(_headers_blob(resp.headers), "Response Header", host, ep.url)
            if enable_entropy:
                findings += scan_entropy_text(resp_text, "Response", host, ep.url)
                findings += scan_entropy_text(_headers_blob(resp.headers), "Response Header", host, ep.url)
    except Exception as e:
        if stop_event.is_set():
            error = "aborted"
        else:
            error = str(e)[:200]

    # Pass full response text; the job loop clips per log/finding so each
    # finding's expand view can keep a window around its matched value.
    return (findings, status, error, ep.url, ep.method,
            ep.headers or {}, ep.body, resp_text or "")


# ══════════════════════════ MODELS ════════════════════════════════════════════

class JsaEndpoint(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[Any] = None
    # Populated from HAR import when Analyse Recorded Result is enabled.
    recorded_status: Optional[int] = None
    recorded_body: Optional[str] = None
    recorded_headers: Optional[Dict[str, str]] = None


class JsaScanRequest(BaseModel):
    endpoints: List[JsaEndpoint]
    include_pii: bool = False
    include_infra: bool = False
    use_recorded: bool = False
    enable_entropy: bool = False


class JsaTextScanRequest(BaseModel):
    text: Optional[str] = None
    spec_url: Optional[str] = None
    source_name: str = "Swagger Spec"
    enable_entropy: bool = False
    include_pii: bool = False
    include_infra: bool = False


class JsaSwaggerParseRequest(BaseModel):
    spec_url: Optional[str] = None
    spec_text: Optional[str] = None
    headers: Dict[str, str] = {}
    auth_token: Optional[str] = None
    base_url: Optional[str] = None


# ── In-memory job store ───────────────────────────────────────────────────────
jobs: Dict[str, Dict[str, Any]] = {}   # job_id → {status, progress, total, completed, findings, logs, errors, start_time, elapsed}
abort_events: Dict[str, threading.Event] = {}   # job_id → Event, set by /jsa/abort

# jobs never get removed on their own — this is a long-running desktop app,
# so without pruning, every scan ever run keeps its full findings/logs in
# memory for the lifetime of the process. Prune finished jobs past a TTL,
# with a hard count cap as a backstop against many short scans inside the
# TTL window.
JOB_TTL  = 3600   # seconds a finished job's results stay available
MAX_JOBS = 50      # hard cap on jobs kept regardless of age

def _prune_old_jobs():
    now = time.time()
    stale = [
        jid for jid, j in jobs.items()
        if j["status"] != "running" and now - j.get("finished_at", j["start_time"]) > JOB_TTL
    ]
    for jid in stale:
        jobs.pop(jid, None)

    if len(jobs) > MAX_JOBS:
        finished = sorted(
            (jid for jid, j in jobs.items() if j["status"] != "running"),
            key=lambda jid: jobs[jid].get("finished_at", jobs[jid]["start_time"]),
        )
        for jid in finished[: len(jobs) - MAX_JOBS]:
            jobs.pop(jid, None)


# ══════════════════════════ ENDPOINTS ════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "ok", "service": "JS Analyser Backend"}


@app.get("/jsa/health")
def health():
    return {"status": "ok"}


@app.post("/jsa/scan-text")
def scan_raw_text(req: JsaTextScanRequest):
    """Scan raw text or Swagger specification content offline for leaked credentials."""
    raw = (req.text or "").strip()
    if not raw and req.spec_url and req.spec_url.strip():
        if fetch_swagger_from_url is None:
            raise HTTPException(500, "swagger_helper is not available.")
        try:
            raw = fetch_swagger_from_url(req.spec_url.strip())
        except Exception as e:
            raise HTTPException(400, f"Failed to fetch Swagger URL: {str(e)}")

    if not raw or not raw.strip():
        return {"findings": [], "total": 0}

    src = req.source_name or "Spec Text"
    findings = scan_text(raw, src, "", "")
    if req.include_infra:
        findings += scan_infra_text(raw, src, "", "")
    if req.include_pii:
        findings += scan_pii_text(raw, src, "", "")
    if req.enable_entropy:
        findings += scan_entropy_text(raw, src, "", "")
    findings = _dedupe(findings)
    return {"findings": findings, "total": len(findings)}


@app.post("/jsa/parse-swagger")
def parse_swagger(req: JsaSwaggerParseRequest):
    """Parse Swagger / OpenAPI specification for JS & Secret Analyser."""
    if parse_swagger_spec is None:
        raise HTTPException(500, "swagger_helper is not available.")

    headers = dict(req.headers or {})
    if req.auth_token and req.auth_token.strip():
        tok_str = req.auth_token.strip()
        if parse_devtools_or_raw_headers is not None:
            parsed_tok, parsed_hdrs = parse_devtools_or_raw_headers(tok_str)
            headers.update(parsed_hdrs)
            if parsed_tok:
                tok_str = parsed_tok.strip()
        if tok_str and not tok_str.lower().startswith(("bearer ", "basic ", "token ", "apikey ")):
            tok_str = f"Bearer {tok_str}"
        if tok_str:
            headers["Authorization"] = tok_str

    res = parse_swagger_spec(spec_text=req.spec_text, spec_url=req.spec_url, headers=headers, custom_base_url=req.base_url)
    if not res.get("success"):
        raise HTTPException(400, res.get("error", "Failed to parse Swagger specification."))
    return res


# ── TruffleHog Engine Status & Installer ──────────────────────────────────────
_truffle_install_lock = threading.Lock()
_truffle_install_status: Dict[str, Any] = {"status": "idle", "logs": []}


@app.get("/jsa/engine/status")
def get_truffle_engine_status():
    """Returns status of TruffleHog CLI and in-memory detectors."""
    if get_trufflehog_info is not None:
        return get_trufflehog_info()
    return {
        "installed": False,
        "engine_mode": "native",
        "binary_path": None,
        "version": "Native v2.4 (Compiled In-Memory)",
        "native_detectors": 181,
        "entropy_enabled": True,
    }


@app.post("/jsa/engine/install")
def install_trufflehog():
    """Trigger background Homebrew installation of official TruffleHog CLI."""
    global _truffle_install_status
    with _truffle_install_lock:
        if _truffle_install_status.get("status") == "installing":
            return {"success": True, "status": "installing", "message": "Installation already in progress."}
        _truffle_install_status = {"status": "installing", "logs": ["🚀 Starting TruffleHog installation via Homebrew ('brew install trufflehog')..."]}

    def _worker():
        global _truffle_install_status
        brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
        if not os.path.isfile(brew_bin):
            brew_bin = "/usr/local/bin/brew"

        if os.path.isfile(brew_bin):
            try:
                env = dict(os.environ)
                env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
                env["HOMEBREW_NO_ENV_HINTS"] = "1"
                proc = subprocess.Popen(
                    [brew_bin, "install", "trufflehog"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
                )
                if proc.stdout:
                    for line in proc.stdout:
                        l = line.strip()
                        if l:
                            _truffle_install_status["logs"].append(l)
                proc.wait()
                if proc.returncode == 0:
                    _truffle_install_status["status"] = "completed"
                    _truffle_install_status["logs"].append("✅ TruffleHog installed successfully! CLI is ready.")
                else:
                    _truffle_install_status["status"] = "failed"
                    _truffle_install_status["logs"].append(f"❌ Brew exited with code {proc.returncode}")
            except Exception as e:
                _truffle_install_status["status"] = "failed"
                _truffle_install_status["logs"].append(f"❌ Installation error: {str(e)}")
        else:
            _truffle_install_status["status"] = "failed"
            _truffle_install_status["logs"].append("❌ Homebrew not detected. Run 'brew install trufflehog' manually in terminal.")

    threading.Thread(target=_worker, daemon=True).start()
    return {"success": True, "status": "installing"}


@app.get("/jsa/engine/install-status")
def get_truffle_install_status():
    """Poll current TruffleHog installation logs."""
    return _truffle_install_status


@app.post("/jsa/engine/update")
def update_trufflehog():
    """Run brew upgrade trufflehog."""
    bin_path = find_trufflehog_binary() if find_trufflehog_binary is not None else None
    if not bin_path:
        return {
            "success": False,
            "installed": False,
            "message": "TruffleHog CLI is not installed yet. Click 'Run 1-Click Install' first, or continue using the Native Engine.",
            "output": "TruffleHog CLI not installed."
        }

    brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
    if not os.path.isfile(brew_bin):
        brew_bin = "/usr/local/bin/brew"
    if not os.path.isfile(brew_bin):
        return {
            "success": False,
            "installed": True,
            "message": "Homebrew not detected on system.",
            "output": "Homebrew not found."
        }

    env = dict(os.environ)
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_ENV_HINTS"] = "1"

    try:
        proc = subprocess.run([brew_bin, "upgrade", "trufflehog"], capture_output=True, text=True, timeout=30, env=env)
        out = (proc.stdout or proc.stderr or "").strip()
        is_ok = proc.returncode == 0
        if is_ok:
            if "already installed" in out.lower() or "already up-to-date" in out.lower():
                msg = f"TruffleHog is already at the latest version! ({out})"
            else:
                msg = "TruffleHog upgraded successfully!"
        else:
            msg = out or "Upgrade failed"
        return {"success": is_ok, "installed": True, "output": out or "Up to date.", "message": msg}
    except Exception as e:
        return {"success": False, "installed": True, "message": f"Update failed: {str(e)}", "output": str(e)}


@app.post("/jsa/scan")
def start_scan(req: JsaScanRequest):
    if not req.endpoints:
        raise HTTPException(400, "No endpoints to scan")

    _prune_old_jobs()

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status": "running", "progress": 0, "total": len(req.endpoints),
        "completed": 0, "findings": [], "logs": [],
        "errors": 0, "start_time": time.time(), "elapsed": 0,
    }
    stop_event = threading.Event()
    abort_events[job_id] = stop_event
    endpoints = req.endpoints
    include_pii = req.include_pii
    include_infra = req.include_infra
    use_recorded = req.use_recorded
    enable_entropy = req.enable_entropy

    def run_scan():
        job = jobs[job_id]
        all_findings, logs = [], []
        errs, completed = 0, 0

        with ThreadPoolExecutor(max_workers=THREADS) as pool:
            futures = {
                pool.submit(scan_endpoint, ep, stop_event, include_pii, include_infra, use_recorded, enable_entropy): ep
                for ep in endpoints
            }
            # Exposed so /jsa/abort can cancel_futures that haven't started
            job["_futures"] = list(futures.keys())
            try:
                for future in as_completed(futures):
                    if future.cancelled():
                        continue
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if result is None:
                        continue   # aborted before it ever started
                    findings, status, error, url, method, req_headers, req_body, resp_body = result
                    completed += 1
                    if error and error != "aborted":
                        errs += 1
                    # Attach request/response context so Results expand + Copy cURL
                    # work without a separate log lookup.
                    body_out = req_body
                    if isinstance(body_out, (dict, list)):
                        try:
                            body_out = json.dumps(body_out, ensure_ascii=False)
                        except Exception:
                            body_out = str(body_out)
                    elif body_out is None:
                        body_out = ""
                    else:
                        body_out = str(body_out)
                    for f in findings:
                        val = f.get("value") or ""
                        src = (f.get("source") or "").lower()
                        # Prefer keeping the window around the finding value in
                        # the side where it was found (Response vs Request).
                        if "response" in src:
                            f_req = _clip_body_for_ui(body_out, MAX_LOG_BODY)
                            f_resp = _clip_body_for_ui(resp_body, MAX_LOG_BODY, val)
                        elif "request" in src:
                            f_req = _clip_body_for_ui(body_out, MAX_LOG_BODY, val)
                            f_resp = _clip_body_for_ui(resp_body, MAX_LOG_BODY)
                        else:
                            f_req = _clip_body_for_ui(body_out, MAX_LOG_BODY, val)
                            f_resp = _clip_body_for_ui(resp_body, MAX_LOG_BODY, val)
                        f["method"] = method
                        f["req_headers"] = req_headers or {}
                        f["req_body"] = f_req
                        f["resp_body"] = f_resp
                        f["status"] = status
                        f["error"] = error
                    all_findings.extend(findings)
                    # Scanning-tab log: keep a window around the first finding
                    # value so expand+search can still locate it in large bodies.
                    log_needle = next(
                        (f.get("value") for f in findings if f.get("value")),
                        None,
                    )
                    logs.append({
                        "url": url, "method": method, "status": status,
                        "error": error, "findings": len(findings),
                        "req_headers": req_headers,
                        "req_body": _clip_body_for_ui(body_out, MAX_LOG_BODY),
                        "resp_body": _clip_body_for_ui(resp_body, MAX_LOG_BODY, log_needle),
                    })
                    job["completed"] = completed
                    job["progress"]  = int(100 * completed / max(len(endpoints), 1))
                    job["findings"]  = _dedupe(all_findings)
                    job["logs"]      = logs
                    job["errors"]    = errs
                    if stop_event.is_set():
                        for f in futures:
                            if not f.done():
                                f.cancel()
            finally:
                job.pop("_futures", None)

        job["elapsed"] = round(time.time() - job["start_time"], 1)
        # Prefer status already set by /jsa/abort (immediate UI unblock)
        if job.get("status") != "aborted":
            job["status"] = "aborted" if stop_event.is_set() else "done"
        job["finished_at"] = time.time()
        if job["status"] == "done":
            job["progress"] = 100
        abort_events.pop(job_id, None)

    threading.Thread(target=run_scan, daemon=True).start()
    return {"job_id": job_id, "total": len(endpoints)}


@app.post("/jsa/abort/{job_id}")
def abort_job(job_id: str):
    """
    Harder abort:
      1) set stop Event (workers skip delay / replay / response scan)
      2) mark job aborted immediately so UI pollers unblock
      3) cancel() any futures that have not started yet
    Already-running HTTP calls finish quickly (short path / TIMEOUT_ABORT).
    """
    ev = abort_events.get(job_id)
    job = jobs.get(job_id)
    if not ev or not job:
        raise HTTPException(404, f"Job {job_id} not found or already finished")
    ev.set()
    job["status"] = "aborted"
    job["elapsed"] = round(time.time() - job["start_time"], 1)
    for f in list(job.get("_futures") or []):
        try:
            f.cancel()
        except Exception:
            pass
    return {"ok": True}


@app.get("/jsa/progress/{job_id}")
def get_progress(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    return {
        "status"   : job["status"],
        "progress" : job["progress"],
        "completed": job["completed"],
        "total"    : job["total"],
        "findings" : job["findings"],
        "logs"     : job["logs"],
        "errors"   : job["errors"],
        "elapsed"  : round(time.time() - job["start_time"], 1) if job["status"] == "running"
                     else job.get("elapsed", 0),
    }
