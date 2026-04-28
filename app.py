from flask import Flask, request, jsonify, render_template
import pickle
import pandas as pd
import requests
import re
import base64
import json
import os
from datetime import datetime

app = Flask(__name__)

model = pickle.load(open("model.pkl", "rb"))

# ⚠️ Shu yerga o'zingning VirusTotal API keyingni qo'y:
VIRUSTOTAL_API_KEY = "77cb9135fda0aff3d6d05af9eb375ca86ee22704c9263b3b40e0d034bcfb5352"

FEATURE_COLS = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
    "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
    "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup",
    "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton",
    "HasHiddenFields", "HasPasswordField", "Bank", "Pay", "Crypto",
    "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
    "NoOfEmptyRef", "NoOfExternalRef"
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account", "signin",
    "credential", "suspend", "unlock", "validate", "authenticate", "password",
    "recovery", "restore", "alert", "urgent", "billing", "invoice"
]

BRAND_NAMES = [
    "paypal", "google", "facebook", "apple", "microsoft", "amazon", "netflix",
    "instagram", "twitter", "ebay", "bank", "wellsfargo", "chase", "citibank",
    "dhl", "fedex", "ups", "whatsapp", "telegram", "tiktok"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ru", ".cn", ".top", ".club", ".work", ".online", ".site",
    ".icu", ".buzz", ".ml", ".ga", ".cf", ".gq"
]

# Tarix saqlash (xotirada)
history = []

def get_domain(url):
    try:
        domain = re.sub(r"https?://", "", url).split("/")[0].split("?")[0]
        return domain
    except:
        return url

def url_to_features(url):
    f = {col: 0 for col in FEATURE_COLS}
    url_lower = url.lower()
    domain = get_domain(url_lower)

    f["URLLength"] = len(url)
    f["DomainLength"] = len(domain)
    f["IsHTTPS"] = 1 if url_lower.startswith("https") else 0
    f["NoOfSubDomain"] = max(url.count(".") - 1, 0)
    f["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    f["NoOfLettersInURL"] = sum(c.isalpha() for c in url)
    f["NoOfEqualsInURL"] = url.count("=")
    f["NoOfQMarkInURL"] = url.count("?")
    f["NoOfAmpersandInURL"] = url.count("&")
    f["NoOfOtherSpecialCharsInURL"] = sum(1 for c in url if c in "@#!$%^*")
    f["HasObfuscation"] = 1 if "@" in url or "%2" in url else 0
    f["HasPasswordField"] = 1 if any(w in url_lower for w in ["login", "password", "signin"]) else 0
    f["Bank"] = 1 if "bank" in url_lower else 0
    f["Pay"] = 1 if "pay" in url_lower else 0
    f["Crypto"] = 1 if "crypto" in url_lower or "bitcoin" in url_lower else 0
    f["IsDomainIP"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0
    f["URLSimilarityIndex"] = 1 if any(b in url_lower for b in BRAND_NAMES) else 0
    f["TLDLength"] = len(url.split(".")[-1]) if "." in url else 0

    if f["URLLength"] > 0:
        f["DegitRatioInURL"] = round(f["NoOfDegitsInURL"] / f["URLLength"], 4)
        f["LetterRatioInURL"] = round(f["NoOfLettersInURL"] / f["URLLength"], 4)
        f["SpacialCharRatioInURL"] = round(f["NoOfOtherSpecialCharsInURL"] / f["URLLength"], 4)

    return [f[col] for col in FEATURE_COLS]

def get_reasons(url, prediction):
    reasons = []
    url_lower = url.lower()
    if not url_lower.startswith("https"):
        reasons.append("HTTPS yo'q — xavfli ulanish")
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        reasons.append("IP manzil ishlatilgan (domen o'rniga)")
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            reasons.append(f"Shubhali kalit so'z: '{kw}'")
            break
    for brand in BRAND_NAMES:
        if brand in url_lower and brand not in get_domain(url_lower).replace("www.", "").split(".")[0]:
            reasons.append(f"'{brand}' brend nomini taqlid qilmoqda")
            break
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or tld + "/" in url_lower:
            reasons.append(f"Xavfli domen kengaytmasi: {tld}")
            break
    if url.count(".") > 4:
        reasons.append("Juda ko'p subdomain")
    if "@" in url:
        reasons.append("URL da '@' belgisi — aldamchi yo'naltirish")
    if len(url) > 80:
        reasons.append("URL juda uzun (yashirishga urinish)")
    return reasons

def check_virustotal(url):
    """VirusTotal API orqali URL tekshirish"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=8
        )

        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "checked": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total,
                "vt_result": "phishing" if (malicious + suspicious) > 0 else "safe"
            }
        elif resp.status_code == 404:
            # URL topilmadi — submit qilamiz
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=8
            )
            return {"checked": False, "reason": "Yangi URL, VirusTotal tahlil qilmoqda..."}
        else:
            return {"checked": False, "reason": f"VirusTotal xatolik: {resp.status_code}"}
    except Exception as e:
        return {"checked": False, "reason": str(e)}

def extract_urls_from_sms(text):
    """SMS matnidan URL larni ajratib olish"""
    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b'
    urls = re.findall(pattern, text)
    # www. bilan boshlanganlarni http:// qo'shamiz
    result = []
    for u in urls:
        if not u.startswith("http"):
            u = "http://" + u
        result.append(u)
    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL kiritilmadi"}), 400

    if not url.startswith("http"):
        url = "http://" + url

    features = url_to_features(url)
    df = pd.DataFrame([features], columns=FEATURE_COLS)

    prediction = int(model.predict(df)[0])
    probability = model.predict_proba(df)[0]
    confidence = round(float(max(probability)) * 100, 1)

    # Rule-based override
    url_lower = url.lower()
    rule_phishing = (
        any(kw in url_lower for kw in PHISHING_KEYWORDS) or
        (any(brand in url_lower for brand in BRAND_NAMES) and not url_lower.startswith("https://www.")) or
        "@" in url or
        any(tld in url_lower for tld in SUSPICIOUS_TLDS) or
        bool(re.match(r"https?://\d+\.\d+\.\d+\.\d+", url))
    )

    if rule_phishing:
        prediction = 1
        confidence = max(confidence, 82.0)

    reasons = get_reasons(url, prediction) if prediction == 1 else []

    # VirusTotal tekshirish
    vt = {}
    if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "YOUR_VIRUSTOTAL_API_KEY":
        vt = check_virustotal(url)
        if vt.get("vt_result") == "phishing":
            prediction = 1
            confidence = max(confidence, 95.0)
            reasons.append(f"VirusTotal: {vt['malicious']} antivirus xavfli dedi")

    result = {
        "url": url,
        "result": "phishing" if prediction == 1 else "safe",
        "confidence": confidence,
        "reasons": reasons,
        "virustotal": vt,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }

    # Tarixga qo'shish
    history.insert(0, {
        "url": url,
        "result": result["result"],
        "confidence": confidence,
        "time": result["timestamp"]
    })
    if len(history) > 50:
        history.pop()

    return jsonify(result)

@app.route("/analyze_sms", methods=["POST"])
def analyze_sms():
    """SMS matnini tahlil qilish"""
    data = request.json
    sms_text = data.get("text", "").strip()

    if not sms_text:
        return jsonify({"error": "SMS matni kiritilmadi"}), 400

    urls = extract_urls_from_sms(sms_text)

    if not urls:
        # URL topilmadi, matn o'zini tekshirish
        suspicious_words = ["yuting", "sovg'a", "yutib oldingiz", "click", "tasdiqlang",
                          "hisobingiz", "blokland", "shoshiling", "muddati", "kod yuboring",
                          "pin kod", "parol", "bank karta", "CVV", "chegirma 90%",
                          "bepul", "million", "dollar", "imkon", "limited"]
        found = [w for w in suspicious_words if w.lower() in sms_text.lower()]
        if found:
            return jsonify({
                "urls_found": [],
                "sms_verdict": "suspicious",
                "sms_reasons": [f"Shubhali so'z: '{w}'" for w in found[:3]],
                "message": "URL topilmadi, lekin shubhali so'zlar aniqlandi"
            })
        else:
            return jsonify({
                "urls_found": [],
                "sms_verdict": "safe",
                "sms_reasons": [],
                "message": "URL topilmadi, matn xavfsiz ko'rinadi"
            })

    # Har bir URL ni tekshirish
    url_results = []
    overall_phishing = False

    for url in urls[:5]:  # Max 5 ta URL
        if not url.startswith("http"):
            url = "http://" + url

        features = url_to_features(url)
        df = pd.DataFrame([features], columns=FEATURE_COLS)
        prediction = int(model.predict(df)[0])
        probability = model.predict_proba(df)[0]
        confidence = round(float(max(probability)) * 100, 1)

        url_lower = url.lower()
        rule_phishing = (
            any(kw in url_lower for kw in PHISHING_KEYWORDS) or
            any(brand in url_lower for brand in BRAND_NAMES) or
            "@" in url or
            any(tld in url_lower for tld in SUSPICIOUS_TLDS)
        )

        if rule_phishing:
            prediction = 1
            confidence = max(confidence, 82.0)

        if prediction == 1:
            overall_phishing = True

        reasons = get_reasons(url, prediction) if prediction == 1 else []

        url_results.append({
            "url": url,
            "result": "phishing" if prediction == 1 else "safe",
            "confidence": confidence,
            "reasons": reasons
        })

        # Tarixga
        history.insert(0, {
            "url": url,
            "result": "phishing" if prediction == 1 else "safe",
            "confidence": confidence,
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": "SMS"
        })

    return jsonify({
        "urls_found": url_results,
        "sms_verdict": "phishing" if overall_phishing else "safe",
        "sms_reasons": [],
        "message": f"{len(url_results)} ta URL tekshirildi"
    })

@app.route("/history", methods=["GET"])
def get_history():
    return jsonify(history[:20])

@app.route("/clear_history", methods=["POST"])
def clear_history():
    history.clear()
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
