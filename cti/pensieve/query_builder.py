"""
query_builder.py — Multilingual CTI query expansion for Pensieve.

Builds search queries in 8 languages optimized per target type.
Used by twitter_scraper.py, and callable from Go via subprocess.

Usage:
    python3 query_builder.py --target "example.com" --type DOMAIN
    → outputs JSON array of {"lang": "en", "query": "..."}
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from typing import Optional

# ── Security terms in 8 languages ──────────────────────────────────────────
# en, ru, zh, ar, es, de, fr, pt
TERMS = {
    "phishing": {
        "en": "phishing",
        "ru": "фишинг",
        "zh": "网络钓鱼",
        "ar": "تصيد احتيالي",
        "es": "phishing",
        "de": "Phishing",
        "fr": "hameçonnage",
        "pt": "phishing",
    },
    "breach": {
        "en": "data breach",
        "ru": "утечка данных",
        "zh": "数据泄露",
        "ar": "اختراق بيانات",
        "es": "brecha de datos",
        "de": "Datenleck",
        "fr": "fuite de données",
        "pt": "vazamento de dados",
    },
    "leak": {
        "en": "leak",
        "ru": "утечка",
        "zh": "泄露",
        "ar": "تسريب",
        "es": "filtración",
        "de": "Leak",
        "fr": "fuite",
        "pt": "vazamento",
    },
    "ransomware": {
        "en": "ransomware",
        "ru": "вымогатель",
        "zh": "勒索软件",
        "ar": "فيروس الفدية",
        "es": "ransomware",
        "de": "Ransomware",
        "fr": "rançongiciel",
        "pt": "ransomware",
    },
    "hack": {
        "en": "hacked",
        "ru": "взлом",
        "zh": "黑客攻击",
        "ar": "اختراق",
        "es": "hackeado",
        "de": "gehackt",
        "fr": "piraté",
        "pt": "hackeado",
    },
    "credentials": {
        "en": "credentials stolen",
        "ru": "украденные учетные данные",
        "zh": "凭证被盗",
        "ar": "سرقة بيانات الاعتماد",
        "es": "credenciales robadas",
        "de": "gestohlene Zugangsdaten",
        "fr": "identifiants volés",
        "pt": "credenciais roubadas",
    },
    "exploit": {
        "en": "exploit",
        "ru": "эксплойт",
        "zh": "漏洞利用",
        "ar": "استغلال",
        "es": "exploit",
        "de": "Exploit",
        "fr": "exploit",
        "pt": "exploit",
    },
    "vulnerability": {
        "en": "vulnerability",
        "ru": "уязвимость",
        "zh": "漏洞",
        "ar": "ثغرة",
        "es": "vulnerabilidad",
        "de": "Schwachstelle",
        "fr": "vulnérabilité",
        "pt": "vulnerabilidade",
    },
    "malware": {
        "en": "malware",
        "ru": "вредоносное ПО",
        "zh": "恶意软件",
        "ar": "برمجيات خبيثة",
        "es": "malware",
        "de": "Schadsoftware",
        "fr": "logiciel malveillant",
        "pt": "malware",
    },
    "impersonation": {
        "en": "impersonation",
        "ru": "выдача себя за другого",
        "zh": "冒充",
        "ar": "انتحال هوية",
        "es": "suplantación",
        "de": "Identitätsmissbrauch",
        "fr": "usurpation d'identité",
        "pt": "falsificação de identidade",
    },
    "scam": {
        "en": "scam",
        "ru": "мошенничество",
        "zh": "诈骗",
        "ar": "احتيال",
        "es": "estafa",
        "de": "Betrug",
        "fr": "arnaque",
        "pt": "golpe",
    },
    "victim": {
        "en": "victim",
        "ru": "жертва",
        "zh": "受害者",
        "ar": "ضحية",
        "es": "víctima",
        "de": "Opfer",
        "fr": "victime",
        "pt": "vítima",
    },
    "attack": {
        "en": "cyberattack",
        "ru": "кибератака",
        "zh": "网络攻击",
        "ar": "هجوم سيبراني",
        "es": "ciberataque",
        "de": "Cyberangriff",
        "fr": "cyberattaque",
        "pt": "ciberataque",
    },
}

LANGUAGES = ["en", "ru", "zh", "ar", "es", "de", "fr", "pt"]

# ── Target type → which term groups to use ─────────────────────────────────
TYPE_QUERIES = {
    "DOMAIN": [
        ["phishing", "scam"],
        ["breach", "leak"],
        ["hack", "impersonation"],
    ],
    "ORGANIZATION": [
        ["breach", "leak"],
        ["ransomware", "attack"],
        ["phishing", "impersonation"],
        ["credentials"],
    ],
    "THREAT_ACTOR": [
        ["victim", "attack"],
        ["ransomware", "malware"],
        ["leak", "breach"],
    ],
    "CVE": [
        ["exploit", "vulnerability"],
        ["attack"],
    ],
    "USERNAME": [
        ["leak", "breach"],
        ["hack", "credentials"],
    ],
    "KEYWORD": [
        ["breach", "leak"],
        ["hack", "attack"],
    ],
    "APP_PACKAGE": [
        ["malware", "vulnerability"],
        ["breach", "hack"],
    ],
    "CRYPTO_WALLET": [
        ["scam"],
        ["hack"],
    ],
}


def _term(key: str, lang: str) -> str:
    return TERMS.get(key, {}).get(lang, TERMS.get(key, {}).get("en", key))


def build_queries(target: str, target_type: str) -> list[dict]:
    """
    Returns list of {"lang": str, "query": str, "variant": int}.
    Each variant is a different angle (phishing, breach, etc.).
    """
    groups = TYPE_QUERIES.get(target_type, TYPE_QUERIES["KEYWORD"])
    queries = []

    for variant_idx, term_keys in enumerate(groups):
        for lang in LANGUAGES:
            # Build: "target" term1 OR term2
            or_terms = " OR ".join(_term(k, lang) for k in term_keys)
            q = f'"{target}" {or_terms}'
            queries.append({
                "lang": lang,
                "query": q,
                "variant": variant_idx,
                "terms": [_term(k, lang) for k in term_keys],
            })

    return queries


def build_queries_flat(target: str, target_type: str) -> list[str]:
    """Just the query strings, deduplicated."""
    seen = set()
    out = []
    for q in build_queries(target, target_type):
        if q["query"] not in seen:
            seen.add(q["query"])
            out.append(q["query"])
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--type", required=True, dest="target_type")
    parser.add_argument("--flat", action="store_true", help="Output flat list of query strings")
    args = parser.parse_args()

    if args.flat:
        print(json.dumps(build_queries_flat(args.target, args.target_type), ensure_ascii=False))
    else:
        print(json.dumps(build_queries(args.target, args.target_type), ensure_ascii=False, indent=2))
