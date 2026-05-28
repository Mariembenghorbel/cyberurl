import re
import math
import requests
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from scanner.models import Incident
from .virustotal import analyze_url_virustotal
from scanner.models import Incident, Asset

# =========================
# UTIL
# =========================

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


# =========================
# RISK ENGINE FORMAT UNIFIÉ
# =========================

def build_result(status, score, details, recommendations=None):
    return {
        "status": status,
        "score": min(max(int(score), 0), 100),
        "details": details,
        "recommendations": recommendations or []
    }


# =========================
# URL CHECKER
# =========================

import re

def check_url_reputation(url):

    url = url.lower().strip()

    score = 0
    details = []
    risk_factors = []

    # =========================
    # DOMAIN EXTRACTION
    # =========================
    domain_match = re.findall(r"https?://([^/]+)", url)
    domain = domain_match[0] if domain_match else url

    # =========================
    # 1. BASIC SECURITY
    # =========================
    if not url.startswith("https"):
        score += 10
        risk_factors.append("No HTTPS encryption")
        details.append("🔓 Connection is not encrypted (HTTP detected)")

    # IP-based URL
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        score += 40
        risk_factors.append("IP URL")
        details.append("⚠️ URL uses raw IP instead of domain (common in phishing)")

    # =========================
    # 2. SHORTENERS (VERY COMMON PHISHING VECTOR)
    # =========================
    shorteners = ["bit.ly", "tinyurl", "t.co", "is.gd", "cutt.ly"]

    if any(s in domain for s in shorteners):
        score += 35
        risk_factors.append("URL shortener")
        details.append("🔗 URL is shortened (destination hidden → phishing risk)")

    # =========================
    # 3. SUSPICIOUS TLDs
    # =========================
    suspicious_tlds = [".zip", ".xyz", ".top", ".click", ".tk", ".pw"]

    if any(tld in domain for tld in suspicious_tlds):
        score += 25
        risk_factors.append("Suspicious TLD")
        details.append("🌐 Domain uses high-risk extension often abused in attacks")

    # =========================
    # 4. PHISHING KEYWORDS
    # =========================
    phishing_keywords = [
        "login", "secure", "verify", "update",
        "account", "bank", "password", "confirm",
        "signin", "authentication"
    ]

    keyword_hits = [k for k in phishing_keywords if k in url]

    if keyword_hits:
        score += len(keyword_hits) * 8
        risk_factors.append("Phishing keywords")
        details.append(f"🎯 Suspicious words found: {', '.join(keyword_hits)}")

    # =========================
    # 5. BRAND IMPERSONATION
    # =========================
    brands = ["paypal", "google", "microsoft", "apple", "facebook", "amazon"]

    for brand in brands:
        if brand in url:
            if "-" in domain or brand + "secure" in url or "verify" in url:
                score += 30
                risk_factors.append("Brand impersonation")
                details.append(f"🧠 Possible spoofing of {brand} detected")

    # =========================
    # 6. STRUCTURAL ATTACK PATTERNS
    # =========================

    if len(url) > 80:
        score += 10
        details.append("📏 Very long URL (used for obfuscation in phishing)")

    if domain.count(".") > 3:
        score += 15
        details.append("🌐 Excessive subdomains (suspicious structure)")

    if "@" in url:
        score += 30
        details.append("⚠️ '@' symbol used to trick users (credential abuse technique)")

    # =========================
    # 7. HOMOGRAPH / FAKE DOMAIN DETECTION
    # =========================
    if "go0gle" in url or "paypaI" in url or "micros0ft" in url:
        score += 40
        risk_factors.append("Typosquatting")
        details.append("🧬 Lookalike domain detected (typosquatting attack)")

    # =========================
    # 8. VIRUSTOTAL INTELLIGENCE (if available)
    # =========================
    vt_result = analyze_url_virustotal(url)

    vt_score = vt_result.get("score", 0)
    vt_details = vt_result.get("details", "No threat intelligence available")

    # =========================
    # 9. FINAL SCORE FUSION
    # =========================
    local_score = min(score, 100)
    final_score = int((local_score * 0.7) + (vt_score * 0.3))

    # =========================
    # 10. SOC OVERRIDE
    # =========================
    if len(keyword_hits) >= 4 and not url.startswith("https"):
        final_score = max(final_score, 90)
        details.append("🚨 SOC override triggered: high confidence phishing")

    # =========================
    # 11. CLASSIFICATION
    # =========================
    if final_score >= 85:
        status = "CRITICAL RISK"
    elif final_score >= 70:
        status = "HIGH RISK"
    elif final_score >= 40:
        status = "MEDIUM RISK"
    else:
        status = "LOW RISK"

    # =========================
    # 12. USER-FRIENDLY SOC RECOMMENDATIONS
    # =========================
    recommendations = [
        "🚫 Do NOT click this link",
        "🔍 Verify domain directly via official website",
        "📢 Report to SOC/security team",
        "🛡️ Check for similar phishing campaigns online"
    ]

    if "URL shortener" in risk_factors:
        recommendations.insert(0, "⚠️ Expand shortened URL before interacting")

    if "Typosquatting" in risk_factors:
        recommendations.append("🧠 This is a lookalike domain attack (common phishing technique)")

    # =========================
    # FINAL OUTPUT
    # =========================
    return {
        "status": status,
        "score": final_score,
        "details": " | ".join(details),
        "virus_total": vt_details,
        "risk_factors": risk_factors,
        "recommendations": recommendations
    }

# =========================
# PASSWORD CHECK
# =========================
def check_password_entropy(password):
    if not password:
        return build_result(
            "WEAK",
            0,
            "Empty password detected",
            ["Use a strong password with at least 12 characters"]
        )

    password_lower = password.lower()

    # =========================
    # BASIC ENTROPY CALC
    # =========================
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool += 32

    entropy = len(password) * math.log2(pool) if pool else 0
    score = min(int((entropy / 128) * 100), 100)

    details = []
    recommendations = []

    # =========================
    # 🔴 COMMON WEAK PASSWORD ATTACKS
    # =========================
    weak_passwords = [
        "123456", "password", "123456789", "qwerty",
        "admin", "welcome", "111111", "123123"
    ]

    if password_lower in weak_passwords:
        score = max(score, 10)
        details.append("Very common password used in global data breaches (e.g., RockYou leak)")
        recommendations.append("Never use common passwords like '123456' or 'password'")
        recommendations.append("Use a random password or password manager")

    # =========================
    # 🧠 KEYBOARD PATTERNS (BRUTE FORCE TARGETS)
    # =========================
    keyboard_patterns = ["qwerty", "asdf", "zxcv", "1q2w3e", "qazwsx"]

    if any(p in password_lower for p in keyboard_patterns):
        score = max(score, 20)
        details.append("Keyboard pattern detected (easy for brute-force attacks)")
        recommendations.append("Avoid keyboard sequences like qwerty or asdfgh")

    # =========================
    # 👤 NAME / PERSONAL INFO GUESSING
    # =========================
    if password_lower in ["mohamed", "ahmed", "ali", "mariem", "admin123"]:
        score = max(score, 15)
        details.append("Password based on common names (easily guessable)")
        recommendations.append("Avoid using your name or family names in passwords")

    # detect name + numbers combo (e.g. mariem123)
    if re.search(r'[a-zA-Z]+[0-9]{1,4}', password_lower):
        details.append("Name + number pattern detected (very common in credential stuffing attacks)")
        recommendations.append("Avoid predictable patterns like name123 or admin2024")

    # =========================
    # 📅 YEAR PATTERNS
    # =========================
    if re.search(r'(19|20)\d{2}', password):
        details.append("Year detected in password (commonly used in leaks)")
        recommendations.append("Avoid using birth years or current years")

    # =========================
    # 🔁 REPETITION ATTACKS
    # =========================
    if re.search(r'(.)\1{3,}', password):
        details.append("Repeated characters detected (e.g. aaaaa)")
        recommendations.append("Avoid repeated characters or patterns")

    # =========================
    # 🔐 ENTROPY CLASSIFICATION
    # =========================
    if entropy < 60:
        status = "WEAK"
        recommendations += [
            "Use at least 12–16 characters",
            "Mix uppercase, lowercase, numbers, and symbols",
            "Avoid dictionary words"
        ]

    elif entropy < 90:
        status = "MEDIUM"
        recommendations += [
            "Add special characters (!@#$%)",
            "Increase length for better protection",
            "Avoid predictable patterns"
        ]

    else:
        status = "STRONG"
        recommendations.append("Good job — this password is strong against brute force attacks")

    # =========================
    # FINAL RESULT
    # =========================
    return build_result(
        status,
        score,
        f"Entropy: {int(entropy)} bits | Analysis completed by SOC engine",
        list(set(recommendations))  # remove duplicates
    )
# =========================
# MAIN VIEW (EMPLOYEE PORTAL)
# =========================

@login_required
def url_scan_view(request):

    ip_detectee = get_client_ip(request)

    resultat_scan = None
    success_message = None
    active_tab = "url"

    my_incidents = Incident.objects.filter(
        employe=request.user
    ).order_by('-date_creation')

    # =========================
    # POST HANDLING CLEAN
    # =========================
    if request.method == "POST":

        # =========================
        # SCAN ACTIONS (NO INCIDENT)
        # =========================
        if "scan_action" in request.POST:

            action = request.POST.get("scan_action")
            active_tab = action

            if action == "url":
                url = request.POST.get("url_cyberlink", "")
                resultat_scan = check_url_reputation(url)

            

            elif action == "password":
                password = request.POST.get("password_check", "")
                resultat_scan = check_password_entropy(password)

            elif action == "hardware":
                desc = request.POST.get("hardware_behavior", "").lower()

                suspicious_keywords = [
                    "cmd", "powershell", "script", "usb",
                    "autorun", "popup", "unknown",
                    "disabled antivirus", "keyboard typing"
                ]

                matched = [k for k in suspicious_keywords if k in desc]
                score = len(matched) * 15

                if score >= 60:
                    status = "HIGH RISK"
                    recommendations = [
                        "Disconnect device immediately",
                        "Run antivirus scan",
                        "Escalate to SOC"
                    ]
                elif score >= 30:
                    status = "MEDIUM RISK"
                    recommendations = [
                        "Monitor activity",
                        "Run antivirus check"
                    ]
                else:
                    status = "LOW RISK"
                    recommendations = ["No major suspicious behavior detected"]

                resultat_scan = build_result(
                    status=status,
                    score=min(score, 100),
                    details=f"Detected: {', '.join(matched) if matched else 'none'}",
                    recommendations=recommendations
                )

        # =========================
        # INCIDENT ONLY (ESCALATION)
        # =========================
        elif "report_action" in request.POST:

            Incident.objects.create(
                employe=request.user,
                titre=request.POST.get("titre"),
                type_menace=request.POST.get("type_menace"),
                description=request.POST.get("description"),
                statut="PENDING"
            )

            success_message = "Incident successfully sent to SOC."

            my_incidents = Incident.objects.filter(
                employe=request.user
            ).order_by('-date_creation')

    return render(request, "scan_url.html", {
        "resultat_scan": resultat_scan,
        "success_message": success_message,
        "ip_detectee": ip_detectee,
        "active_tab": active_tab,
        "my_incidents": my_incidents
    })