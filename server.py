#!/usr/bin/env python3
"""
Suspicion — Hybrid Backend & Analysis Server
Combines deterministic security heuristics with Gemini LLM deep semantic inspection.
Uses Python standard library for zero-dependency portability.
"""

import os
import sys
import json
import re
import urllib.request
import urllib.error
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

KNOWN_BRANDS = [
    'paypal.com', 'amazon.com', 'apple.com', 'microsoft.com', 'google.com',
    'netflix.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'usbank.com', 'capitalone.com', 'americanexpress.com', 'discover.com',
    'dropbox.com', 'icloud.com', 'outlook.com', 'yahoo.com', 'aol.com',
    'fedex.com', 'ups.com', 'usps.com', 'dhl.com', 'walmart.com',
    'target.com', 'bestbuy.com', 'ebay.com', 'etsy.com', 'spotify.com',
    'adobe.com', 'zoom.us', 'slack.com', 'github.com', 'twitch.tv',
    'tiktok.com', 'snapchat.com', 'whatsapp.com', 'telegram.org', 'discord.com',
    'venmo.com', 'cashapp.com', 'zelle.com', 'stripe.com', 'square.com',
    'coinbase.com', 'binance.com', 'robinhood.com'
]

FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'mail.com', 'protonmail.com', 'proton.me', 'icloud.com', 'yandex.com',
    'zoho.com', 'gmx.com', 'live.com', 'msn.com', 'inbox.com'
]

SCAM_TAXONOMY = [
    {"name": "Package & Delivery Phishing", "keywords": ['delivery', 'package', 'parcel', 'shipment', 'tracking', 'shipped', 'courier', 'fedex', 'ups', 'usps', 'dhl', 'order', 'dispatch']},
    {"name": "Banking & Financial Fraud", "keywords": ['bank', 'account', 'transaction', 'transfer', 'payment', 'balance', 'statement', 'overdraft', 'wire', 'routing', 'iban', 'debit', 'credit']},
    {"name": "Account Security Scare", "keywords": ['password', 'login', 'sign in', 'unauthorized', 'compromised', 'breached', 'hacked', 'security', 'verify', 'locked', 'suspended', 'two-factor', '2fa', 'mfa']},
    {"name": "Sweepstakes & Prize Scam", "keywords": ['won', 'winner', 'lottery', 'prize', 'congratulations', 'sweepstakes', 'jackpot', 'selected', 'reward', 'claim']},
    {"name": "Recruitment & Job Offer Scam", "keywords": ['job', 'position', 'hire', 'hiring', 'salary', 'remote work', 'work from home', 'opportunity', 'recruitment', 'interview', 'resume', 'cv', 'offer letter']},
    {"name": "Invoice & Billing Fraud", "keywords": ['invoice', 'payment due', 'overdue', 'billing', 'subscription', 'renew', 'receipt', 'refund', 'charge', 'fee']},
    {"name": "Executive Impersonation (BEC)", "keywords": ['ceo', 'cfo', 'director', 'manager', 'behalf of', 'executive', 'wire', 'confidential', "don't tell", 'keep this between', 'favor']}
]

WARNING_PATTERNS = [
    {
        "id": "urgency",
        "name": "Artificial Urgency & Pressure",
        "severity": "high",
        "iconName": "clock",
        "patterns": [
            r"\b(act now|immediately|right away|as soon as possible|asap|urgent|urgently)\b",
            r"\bwithin\s+\d+\s*(hours?|minutes?|days?)\b",
            r"\b(don'?t delay|time.?sensitive|limited time|expires? (today|soon|shortly))\b",
            r"\b(your account (will be|has been|is being) (suspended|closed|locked|deactivated|terminated|restricted))\b",
            r"\b(failure to (act|respond|verify|comply|confirm))\b",
            r"\b(last (chance|warning|notice|reminder))\b",
            r"\b(respond|reply|act|verify|confirm|update)\b.{0,15}\b(before|or else|otherwise)\b",
        ],
        "explanation": "Attackers engineer high-pressure deadlines to induce impulsive responses before victims can conduct independent verification."
    },
    {
        "id": "sensitive_info",
        "name": "Requests for Sensitive Information",
        "severity": "high",
        "iconName": "lock",
        "patterns": [
            r"\b(password|passcode|pin\s*code|pin\s*number|security code)\b",
            r"\b(social security|ssn|tax\s*id|national\s*id)\b",
            r"\b(credit card|debit card|card number|cvv|cvc|expir(y|ation)\s*date)\b",
            r"\b(bank account|routing number|account number|sort code|iban)\b",
            r"\b(verify your (identity|account|information|details|credentials))\b",
            r"\b(confirm your (identity|account|information|details|credentials))\b",
            r"\b(update your (payment|billing|account)\s*(info|information|details|method))\b",
            r"\b(login|log\s*in|sign\s*in)\s*(credentials?|details?|info(rmation)?)\b",
        ],
        "explanation": "Legitimate enterprise services never request raw credentials, PINs, or complete card data via unauthenticated messages."
    },
    {
        "id": "suspicious_links",
        "name": "Suspicious or Deceptive Links",
        "severity": "medium",
        "iconName": "link",
        "patterns": [
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s]*",
            r"https?://[^\s]*\.(tk|ml|ga|cf|gq|xyz|top|club|buzz|icu|cam|rest|surf)\b[^\s]*",
            r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|soo\.gd|s\.id|rebrand\.ly|short\.io)\b[^\s]*",
            r"https?://[^\s]*(-secure|-verify|-login|-update|-account|-confirm|-alert|-support)[^\s]*",
        ],
        "explanation": "Deceptive top-level domains (.xyz, .tk) or shortened URLs conceal landing pages built for credential harvesting."
    },
    {
        "id": "threats",
        "name": "Threats & Coercive Language",
        "severity": "high",
        "iconName": "shieldAlert",
        "patterns": [
            r"\b(unauthorized (access|activity|transaction|login|charge))\b",
            r"\b(legal action|law enforcement|prosecut(e|ed|ion)|arrest)\b",
            r"\b(permanently (locked|closed|suspended|banned|deleted))\b",
            r"\b(security (breach|alert|incident|threat|compromise))\b",
            r"\b(your (account|data|information) (is|has been|was) (compromised|breached|stolen|hacked|accessed))\b",
        ],
        "explanation": "Coercive threats of legal action or permanent data loss override analytical thinking through fear."
    },
    {
        "id": "impersonation",
        "name": "Corporate Impersonation Cues",
        "severity": "medium",
        "iconName": "user",
        "patterns": [
            r"\b(support team|security (team|department|division)|customer (service|care|support)\s*(team|department|center)?)\b",
            r"\b(official (notice|notification|communication|message|announcement))\b",
            r"\b(this is\s+(an?\s+)?(official|automated|system)\s*(message|notification|alert|email|notice))\b",
        ],
        "explanation": "Fabricated titles such as 'Security Dispatch' or 'Official Alert' attempt to establish unearned authority."
    },
    {
        "id": "money_payment",
        "name": "Untraceable Payment or Transfer Request",
        "severity": "high",
        "iconName": "dollar",
        "patterns": [
            r"\b(wire transfer|bank transfer|money transfer)\b",
            r"\b(gift card|itunes card|google play card|steam card|amazon card)\b",
            r"\b(crypto(currency)?|bitcoin|btc|ethereum|eth|usdt)\b",
            r"\b(processing fee|handling fee|shipping fee|activation fee|insurance fee|tax fee)\b",
            r"\b(venmo|zelle|cash\s*app|paypal\.me)\b",
        ],
        "explanation": "Demands for untraceable or irreversible tender (gift cards, wire transfers, crypto) are standard indicators of fraud."
    }
]

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def extract_domains(text):
    urls = re.findall(r"https?://([^\s/\]\"'>]+)", text, re.IGNORECASE)
    cleaned = []
    for u in urls:
        d = re.sub(r"^www\.", "", u.lower())
        if d not in cleaned:
            cleaned.append(d)
    return cleaned

def find_lookalikes(domains):
    results = []
    for domain in domains:
        if domain in KNOWN_BRANDS:
            continue
        base = domain.split('.')[0]
        for brand in KNOWN_BRANDS:
            b_base = brand.split('.')[0]
            dist = levenshtein(base, b_base)
            max_len = max(len(base), len(b_base))
            if 0 < dist <= 2 and max_len >= 4:
                results.append({"found": domain, "real": brand, "distance": dist})
                break
    return results

def analyze_sender(from_addr, reply_to):
    flags = []
    if from_addr:
        match = re.search(r"@([^\s>]+)", from_addr)
        if match:
            domain = match.group(1).lower().replace("www.", "")
            lookalikes = find_lookalikes([domain])
            if lookalikes:
                flags.append({
                    "severity": "high",
                    "text": f"Sender domain <strong>{lookalikes[0]['found']}</strong> mimics trusted authority <strong>{lookalikes[0]['real']}</strong>.",
                    "domain": lookalikes[0]
                })
            if domain in FREE_EMAIL_PROVIDERS:
                lower = from_addr.lower()
                for kw in ['bank', 'paypal', 'amazon', 'apple', 'microsoft', 'support', 'security', 'admin']:
                    if kw in lower:
                        flags.append({
                            "severity": "high",
                            "text": f"Sender operates from a free public mail provider ({domain}) while asserting affiliation with '{kw}'."
                        })
                        break
            if re.search(r"\d", domain.split('.')[0]) and domain not in KNOWN_BRANDS:
                flags.append({
                    "severity": "medium",
                    "text": f"Sender domain embeds numeric substitutions (<strong>{domain}</strong>), typical of typosquatting."
                })
    if from_addr and reply_to:
        m1 = re.search(r"@([^\s>]+)", from_addr)
        m2 = re.search(r"@([^\s>]+)", reply_to)
        if m1 and m2 and m1.group(1).lower() != m2.group(1).lower():
            flags.append({
                "severity": "high",
                "text": f"Reply-To destination (<strong>{m2.group(1)}</strong>) diverts replies away from From domain (<strong>{m1.group(1)}</strong>)."
            })
    return flags

def analyze_headers(header_text):
    flags = []
    if not header_text or not header_text.strip():
        return flags
    from_m = re.search(r"^From:\s*.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)", header_text, re.MULTILINE | re.IGNORECASE)
    ret_m = re.search(r"^Return-Path:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)", header_text, re.MULTILINE | re.IGNORECASE)
    if from_m and ret_m:
        d1 = from_m.group(1).split('@')[1].lower()
        d2 = ret_m.group(1).split('@')[1].lower()
        if d1 != d2:
            flags.append({
                "severity": "high",
                "text": f"Envelope Return-Path (<strong>{d2}</strong>) conflicts with From domain (<strong>{d1}</strong>)."
            })
    if re.search(r"spf=(fail|softfail)", header_text, re.IGNORECASE):
        flags.append({"severity": "high", "text": "SPF validation failure: originating mail host lacks domain relay authorization."})
    if re.search(r"dkim=fail", header_text, re.IGNORECASE):
        flags.append({"severity": "high", "text": "DKIM signature failure: cryptographic payload verification failed."})
    if re.search(r"dmarc=fail", header_text, re.IGNORECASE):
        flags.append({"severity": "high", "text": "DMARC policy failure: message breaches domain sender compliance standard."})
    return flags

def classify_scam(text):
    lower = text.lower()
    best_cat = None
    best_score = 0
    for cat in SCAM_TAXONOMY:
        score = sum(1 for kw in cat['keywords'] if kw in lower)
        if score > best_score:
            best_score = score
            best_cat = cat['name']
    return best_cat if best_score >= 2 else None

def call_gemini_llm(message, message_type, sender_from, api_key):
    """
    Invokes Gemini API via standard library urllib to perform semantic intent analysis.
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    
    prompt = f"""
You are an expert cybersecurity fraud investigator. Analyze the following {message_type} message for phishing, social engineering, smishing, or scam manipulation tactics.

SENDER: {sender_from if sender_from else 'Unknown/Not provided'}
MESSAGE CONTENT:
\"\"\"
{message}
\"\"\"

Respond STRICTLY with valid JSON following this exact schema:
{{
  "is_scam": boolean,
  "confidence_score": integer (0 to 100),
  "verdict_title": string (e.g. "Credential Harvesting Phishing", "Legitimate Notification", "Suspected Smishing"),
  "manipulation_tactics": [list of 2-4 strings describing specific social engineering techniques, e.g. "Manufactured Urgency", "False Technical Authority", "Pretexting"],
  "threat_summary": string (2-3 concise sentences detailing attacker motives and deception mechanisms),
  "recommended_action": string (1-2 clear, actionable security instructions for the customer)
}}
Do not include any markdown formatting, backticks, or other text outside the JSON object.
"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode('utf-8'))
            candidate = result['candidates'][0]['content']['parts'][0]['text']
            parsed = json.loads(candidate)
            parsed['enabled'] = True
            parsed['provider'] = "Google Gemini 1.5 Flash"
            return parsed
    except Exception as e:
        print(f"[LLM Warning] Gemini call error: {e}")
        return None

def heuristic_semantic_fallback(message, category, warnings, lookalikes, sender_flags):
    """
    Intelligent heuristic semantic synthesis when LLM API key is not configured.
    """
    tactics = []
    for w in warnings:
        if w['id'] == 'urgency':
            tactics.append("Manufactured Panic & Artificial Deadlines")
        elif w['id'] == 'sensitive_info':
            tactics.append("Direct Credential Harvesting")
        elif w['id'] == 'threats':
            tactics.append("Coercive Consequence Intimidation")
        elif w['id'] == 'impersonation':
            tactics.append("Institutional Authority Impersonation")
        elif w['id'] == 'suspicious_links':
            tactics.append("Host Obfuscation & URL Deception")
        elif w['id'] == 'money_payment':
            tactics.append("Irreversible Tender Solicitation")
    
    if lookalikes or any(f.get('domain') for f in sender_flags):
        tactics.append("Typosquatting Trademark Substitution")
    
    if not tactics:
        tactics = ["Informational Communication", "Standard Notification"]
    
    flag_count = len(warnings) + len(lookalikes) + len(sender_flags)
    is_scam = flag_count >= 3
    
    if is_scam:
        threat = f"The message employs {', '.join(tactics[:2]).lower()} to compel immediate action. The attacker targets recipient trust by simulating an urgent {category or 'account'} event."
        action = "Do not click links or furnish credentials. Disconnect from this thread and verify through the service's official public telephone line or domain."
        verdict = f"High Risk: {category or 'Phishing Fraud'}"
        confidence = min(60 + flag_count * 7, 98)
    elif flag_count > 0:
        threat = "Low-to-moderate heuristic indicators detected. The text incorporates patterns occasionally seen in automated marketing or ambiguous notices."
        action = "Exercise standard caution before clicking embedded links; verify the sender address independently."
        verdict = "Suspicious Notice (Verification Recommended)"
        confidence = 50
    else:
        threat = "No prevalent deception tactics detected. Content structure adheres to typical non-coercive personal or transactional correspondence."
        action = "Standard verification: proceed normally while adhering to common security hygiene."
        verdict = "Low Risk Correspondence"
        confidence = 15

    return {
        "enabled": False,
        "provider": "Rule-Based Semantic Engine",
        "is_scam": is_scam,
        "confidence_score": confidence,
        "verdict_title": verdict,
        "manipulation_tactics": tactics[:4],
        "threat_summary": threat,
        "recommended_action": action,
        "note": "Connect a Gemini API key to activate live LLM neural analysis."
    }

class SuspicionHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        if self.path == '/api/analyze':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Malformed JSON payload"}).encode('utf-8'))
                return

            message = data.get('message', '')
            msg_type = data.get('message_type', 'email')
            sender_from = data.get('sender_from', '')
            sender_reply_to = data.get('sender_reply_to', '')
            headers = data.get('headers', '')
            user_api_key = data.get('api_key') or os.environ.get('GEMINI_API_KEY')

            # 1. Heuristic Pattern Detection
            detected_warnings = []
            all_matches = []
            for wp in WARNING_PATTERNS:
                matches = []
                for p in wp['patterns']:
                    for m in re.finditer(p, message, re.IGNORECASE):
                        matches.append({
                            "start": m.start(),
                            "end": m.end(),
                            "text": m.group(0)
                        })
                        all_matches.append({
                            "start": m.start(),
                            "end": m.end(),
                            "text": m.group(0),
                            "category": wp['name'],
                            "severity": wp['severity']
                        })
                if matches:
                    detected_warnings.append({
                        "id": wp['id'],
                        "name": wp['name'],
                        "severity": wp['severity'],
                        "iconName": wp['iconName'],
                        "explanation": wp['explanation'],
                        "matches": matches
                    })

            # 2. Domain & Lookalikes
            domains = extract_domains(message)
            lookalikes = find_lookalikes(domains)

            # 3. Sender & Header Flags
            sender_flags = analyze_sender(sender_from, sender_reply_to)
            header_flags = analyze_headers(headers)
            all_sender_flags = sender_flags + header_flags

            # 4. Scam Taxonomy Classification
            category = classify_scam(message)

            # 5. Severity Score
            flag_count = len(detected_warnings) + len(lookalikes) + (1 if sender_flags else 0) + (1 if header_flags else 0)
            max_score = len(WARNING_PATTERNS) + 2

            if flag_count <= 2:
                risk_level = "Low Risk"
                risk_class = "low"
            elif flag_count <= 5:
                risk_level = "Medium Risk"
                risk_class = "medium"
            else:
                risk_level = "High Risk"
                risk_class = "high"

            # 6. LLM Semantic Layer
            llm_result = None
            if user_api_key and user_api_key.strip():
                llm_result = call_gemini_llm(message, msg_type, sender_from, user_api_key.strip())
            
            if not llm_result:
                llm_result = heuristic_semantic_fallback(message, category, detected_warnings, lookalikes, all_sender_flags)

            response_payload = {
                "risk_level": risk_level,
                "risk_class": risk_class,
                "flag_count": flag_count,
                "max_score": max_score,
                "scam_category": category,
                "detected_warnings": detected_warnings,
                "lookalikes": lookalikes,
                "sender_flags": all_sender_flags,
                "all_matches": all_matches,
                "llm_analysis": llm_result
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response_payload).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def main():
    print(f"==================================================")
    print(f"🛡️  Suspicion Backend Server running on port {PORT}")
    print(f"📍 Directory: {DIRECTORY}")
    print(f"🌐 Serving http://localhost:{PORT}")
    print(f"🧠 Endpoint: POST http://localhost:{PORT}/api/analyze")
    print(f"==================================================")
    server = HTTPServer(('0.0.0.0', PORT), SuspicionHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()

if __name__ == '__main__':
    main()
