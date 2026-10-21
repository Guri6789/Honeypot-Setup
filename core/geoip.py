"""
HoneyBank - GeoIP & Threat Intelligence
Looks up attacker IP geolocation and reputation
"""

import os
import json
import threading
from functools import lru_cache

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from config import GEOIP_DB_PATH, ABUSEIPDB_API_KEY

# Cache to avoid repeated API calls for same IP
_cache = {}
_cache_lock = threading.Lock()


def get_geoip(ip: str) -> dict:
    """
    Look up IP geolocation using MaxMind GeoLite2 DB.
    Returns country, city, latitude, longitude.
    """
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "??",
                "city": response.city.name or "Unknown",
                "lat": float(response.location.latitude or 0),
                "lon": float(response.location.longitude or 0),
            }
    except Exception:
        return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}


def check_abuseipdb(ip: str) -> dict:
    """
    Check IP reputation using AbuseIPDB API.
    Returns abuse confidence score and reports count.
    """
    if not ABUSEIPDB_API_KEY or not REQUESTS_AVAILABLE:
        return {"abuse_score": -1, "reports": -1, "is_known_abuser": False}

    # Check cache first
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        data = response.json().get("data", {})
        result = {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "is_known_abuser": data.get("abuseConfidenceScore", 0) >= 25,
            "isp": data.get("isp", "Unknown"),
            "usage_type": data.get("usageType", "Unknown"),
        }
        with _cache_lock:
            _cache[ip] = result
        return result
    except Exception as e:
        print(f"[GEOIP] AbuseIPDB lookup failed for {ip}: {e}")
        return {"abuse_score": -1, "reports": -1, "is_known_abuser": False}


def enrich_ip(ip: str) -> dict:
    """
    Full IP enrichment: GeoIP + Reputation.
    Returns combined threat intelligence data.
    """
    geo = get_geoip(ip)
    reputation = check_abuseipdb(ip)

    return {
        "ip": ip,
        "geo": geo,
        "reputation": reputation,
        "threat_level": _calculate_threat_level(reputation)
    }


def _calculate_threat_level(reputation: dict) -> str:
    """Calculate overall threat level from reputation data."""
    score = reputation.get("abuse_score", 0)
    if score < 0:
        return "UNKNOWN"
    elif score == 0:
        return "LOW"
    elif score < 25:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    elif score < 75:
        return "HIGH"
    else:
        return "CRITICAL"
