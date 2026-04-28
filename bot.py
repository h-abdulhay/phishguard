import telebot
import pickle
import pandas as pd
import requests
import re
import base64
from datetime import datetime

# ⚠️ Shu yerga o'zingning tokeningni qo'y:
BOT_TOKEN = "YOUR_BOT_TOKEN"

# ⚠️ VirusTotal API key (app.py dagi bilan bir xil):
VIRUSTOTAL_API_KEY = "77cb9135fda0aff3d6d05af9eb375ca86ee22704c9263b3b40e0d034bcfb5352"

bot = telebot.TeleBot("8201651470:AAFFkic32cNARj2EhsfJgrcO9BdbwyUyUjI")
model = pickle.load(open("model.pkl", "rb"))

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

def get_domain(url):
    try:
        return re.sub(r"https?://", "", url).split("/")[0].split("?")[0]
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

def get_reasons(url):
    reasons = []
    url_lower = url.lower()
    if not url_lower.startswith("https"):
        reasons.append("HTTPS yo'q")
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        reasons.append("IP manzil ishlatilgan")
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            reasons.append(f"Shubhali so'z: '{kw}'")
            break
    for brand in BRAND_NAMES:
        if brand in url_lower:
            reasons.append(f"'{brand}' brend taqlidi")
            break
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or tld + "/" in url_lower:
            reasons.append(f"Xavfli domen: {tld}")
            break
    if "@" in url:
        reasons.append("'@' belgisi bor")
    if len(url) > 80:
        reasons.append("URL juda uzun")
    return reasons

def check_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=8
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return malicious, suspicious, total
    except:
        pass
    return None, None, None

def analyze_url(url):
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
        any(tld in url_lower for tld in SUSPICIOUS_TLDS) or
        bool(re.match(r"https?://\d+\.\d+\.\d+\.\d+", url))
    )

    if rule_phishing:
        prediction = 1
        confidence = max(confidence, 82.0)

    # VirusTotal
    vt_malicious, vt_suspicious, vt_total = None, None, None
    if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "YOUR_VIRUSTOTAL_API_KEY":
        vt_malicious, vt_suspicious, vt_total = check_virustotal(url)
        if vt_malicious and (vt_malicious + (vt_suspicious or 0)) > 0:
            prediction = 1
            confidence = max(confidence, 95.0)

    reasons = get_reasons(url) if prediction == 1 else []

    return {
        "url": url,
        "is_phishing": prediction == 1,
        "confidence": confidence,
        "reasons": reasons,
        "vt_malicious": vt_malicious,
        "vt_total": vt_total
    }

def extract_urls(text):
    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b'
    urls = re.findall(pattern, text)
    result = []
    for u in urls:
        if not u.startswith("http"):
            u = "http://" + u
        result.append(u)
    return result

def format_result(result):
    if result["is_phishing"]:
        msg = "🚨 *PHISHING ANIQLANDI*\n\n"
        msg += f"🔗 `{result['url']}`\n"
        msg += f"📊 Ishonch: *{result['confidence']}%*\n\n"
        if result["reasons"]:
            msg += "⚠️ *Sabablar:*\n"
            for r in result["reasons"]:
                msg += f"  • {r}\n"
        if result["vt_malicious"] is not None:
            msg += f"\n🔬 VirusTotal: *{result['vt_malicious']}/{result['vt_total']}* xavfli"
        msg += "\n\n🛑 *Bu havolani OCHMANG!*"
    else:
        msg = "✅ *XAVFSIZ*\n\n"
        msg += f"🔗 `{result['url']}`\n"
        msg += f"📊 Ishonch: *{result['confidence']}%*"
        if result["vt_total"] is not None:
            msg += f"\n🔬 VirusTotal: *{result['vt_total']}* tekshiruv — xavfsiz"
    return msg

# /start
@bot.message_handler(commands=["start"])
def start(message):
    bot.send_message(message.chat.id,
        "🛡 *PhishGuard Botga xush kelibsiz!*\n\n"
        "Men sizga URL va SMS xabarlarni phishing (fishing hujumi) uchun tekshirib beraman.\n\n"
        "*Qanday ishlatish:*\n"
        "• URL yuboring → tekshiraman\n"
        "• SMS matnini yuboring → ichidagi havolalarni tekshiraman\n\n"
        "📌 Buyruqlar:\n"
        "/start — boshlash\n"
        "/help — yordam\n"
        "/about — bot haqida",
        parse_mode="Markdown"
    )

# /help
@bot.message_handler(commands=["help"])
def help_cmd(message):
    bot.send_message(message.chat.id,
        "📖 *Yordam*\n\n"
        "1️⃣ URL tekshirish:\n"
        "Shunchaki URL yuboring:\n"
        "`http://fake-login-verify.com`\n\n"
        "2️⃣ SMS tekshirish:\n"
        "SMS matnini to'liq yuboring — ichidagi barcha havolalar tekshiriladi\n\n"
        "3️⃣ Bir nechta URL:\n"
        "Har birini alohida qatorda yuboring\n\n"
        "⚡ VirusTotal bilan 91 ta antivirus tekshiruvi ham qo'shilgan!",
        parse_mode="Markdown"
    )

# /about
@bot.message_handler(commands=["about"])
def about_cmd(message):
    bot.send_message(message.chat.id,
        "🛡 *PhishGuard v2.0*\n\n"
        "AI asosidagi phishing aniqlovchi bot.\n\n"
        "🤖 Texnologiyalar:\n"
        "• Random Forest ML modeli\n"
        "• Rule-based detection\n"
        "• VirusTotal API (91 antivirus)\n\n"
        "👨‍💻 @AbdulhaySecurity_Bot",
        parse_mode="Markdown"
    )

# Barcha xabarlar
@bot.message_handler(func=lambda m: True)
def handle_message(message):
    text = message.text.strip()

    # URL larni ajratib olish
    urls = extract_urls(text)

    if not urls:
        # URL topilmadi — shubhali so'zlarni tekshir
        suspicious_words = [
            "yutdingiz", "sovg'a", "tabriklaymiz", "click here", "tasdiqlang",
            "hisobingiz blok", "shoshiling", "muddati tugaydi", "pin kod",
            "bank kartangiz", "CVV", "chegirma 90%", "bepul iPhone",
            "million dollar", "limited offer", "verify your account"
        ]
        found = [w for w in suspicious_words if w.lower() in text.lower()]

        if found:
            msg = "⚠️ *SHUBHALI SMS*\n\n"
            msg += "URL topilmadi, lekin shubhali so'zlar aniqlandi:\n"
            for w in found[:3]:
                msg += f"  • `{w}`\n"
            msg += "\n🔍 Bunday xabarlarga ishonmang!"
            bot.send_message(message.chat.id, msg, parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id,
                "ℹ️ URL topilmadi.\n\n"
                "Tekshirish uchun URL yoki SMS matnini yuboring.\n"
                "Masalan: `http://example.com`",
                parse_mode="Markdown"
            )
        return

    # 1 ta URL
    if len(urls) == 1:
        bot.send_message(message.chat.id, "🔍 Tekshirilmoqda...", parse_mode="Markdown")
        result = analyze_url(urls[0])
        bot.send_message(message.chat.id, format_result(result), parse_mode="Markdown")

    # Ko'p URL
    else:
        bot.send_message(message.chat.id,
            f"🔍 *{len(urls)} ta URL* topildi, tekshirilmoqda...",
            parse_mode="Markdown"
        )
        phishing_count = 0
        for url in urls[:5]:  # Max 5 ta
            result = analyze_url(url)
            if result["is_phishing"]:
                phishing_count += 1
            bot.send_message(message.chat.id, format_result(result), parse_mode="Markdown")

        # Umumiy xulosa
        if phishing_count > 0:
            bot.send_message(message.chat.id,
                f"🚨 *Xulosa: {phishing_count}/{len(urls)} ta URL xavfli!*\n"
                f"Bu SMS ga ishonmang va havolalarni ochmang!",
                parse_mode="Markdown"
            )
        else:
            bot.send_message(message.chat.id,
                f"✅ *Xulosa: Barcha {len(urls)} ta URL xavfsiz*",
                parse_mode="Markdown"
            )

print("🤖 PhishGuard Bot ishga tushdi...")
print("Ctrl+C bilan to'xtatish mumkin")
bot.polling(none_stop=True)
