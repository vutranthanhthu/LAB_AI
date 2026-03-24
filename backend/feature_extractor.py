"""
Feature extraction from URLs for phishing detection.

Features are hand-crafted based on common phishing indicators studied in
Vietnamese / international literature:
  - URL length, depth, special-char counts
  - IP address in host
  - Suspicious TLD list
  - HTTPS presence
  - Presence of brand keywords in subdomain
  - Hyphens / underscores in domain
  - Digit ratio
  - etc.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict, Any

import tldextract

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Common brands frequently abused in phishing (VN-relevant list first)
_BRAND_KEYWORDS = [
    "vietcombank", "vietinbank", "bidv", "agribank", "techcombank",
    "mbbank", "vpbank", "hdbank", "sacombank", "ocb", "tpbank",
    "momo", "zalopay", "vnpay", "shopee", "lazada", "tiki",
    "facebook", "google", "apple", "microsoft", "paypal", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "youtube",
]

# Suspicious TLDs commonly seen in phishing
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "loan",
    "win", "download", "review", "stream", "gdn", "racing", "date",
    "trade", "accountant", "science", "faith", "party", "country",
    "cricket", "webcam", "men", "work", "life", "zip", "mobi",
}

# Legitimate shorteners (not phishing per se, but opaque)
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "rb.gy", "cutt.ly", "short.io",
}


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _has_ip(host: str) -> bool:
    """Return True if the host is an IPv4 address."""
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract a feature dictionary from a URL.

    Returns a flat dict of numeric / boolean features suitable for a
    scikit-learn pipeline.
    """
    # --- Parse ---
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full_url = url

    subdomain = ext.subdomain or ""
    domain = ext.domain or ""
    suffix = ext.suffix or ""
    registered_domain = f"{domain}.{suffix}" if suffix else domain

    # --- Basic length features ---
    url_length = len(full_url)
    host_length = len(host)
    path_length = len(path)
    query_length = len(query)

    # --- Path depth ---
    path_depth = len([p for p in path.split("/") if p])

    # --- Special character counts ---
    hyphen_count = full_url.count("-")
    underscore_count = full_url.count("_")
    dot_count = full_url.count(".")
    at_count = full_url.count("@")
    question_count = full_url.count("?")
    amp_count = full_url.count("&")
    equals_count = full_url.count("=")
    hash_count = full_url.count("#")
    percent_count = full_url.count("%")
    slash_count = full_url.count("/")
    double_slash = int("//" in path)

    # --- Digit ratio ---
    digits = sum(c.isdigit() for c in full_url)
    digit_ratio = digits / max(url_length, 1)

    # --- Suspicious characters ---
    has_at = int("@" in host or "@" in path)
    has_ip = int(_has_ip(host))

    # --- HTTPS ---
    is_https = int(scheme == "https")

    # --- Subdomain depth ---
    subdomain_depth = len([s for s in subdomain.split(".") if s]) if subdomain else 0

    # --- TLD suspicion ---
    is_suspicious_tld = int(suffix.split(".")[-1].lower() in _SUSPICIOUS_TLDS)

    # --- Brand impersonation in subdomain or path ---
    combined_sub_path = (subdomain + path + query).lower()
    brand_in_subdomain = int(any(b in combined_sub_path for b in _BRAND_KEYWORDS))
    brand_in_domain = int(any(b in domain.lower() for b in _BRAND_KEYWORDS))

    # --- URL shortener ---
    is_shortener = int(registered_domain.lower() in _URL_SHORTENERS)

    # --- Entropy of domain ---
    domain_entropy = _entropy(domain)
    subdomain_entropy = _entropy(subdomain)

    # --- Consecutive digits in domain ---
    max_digit_run = max(
        (len(m.group()) for m in re.finditer(r"\d+", domain)), default=0
    )

    # --- Punycode (IDN homograph attack) ---
    has_punycode = int("xn--" in host.lower())

    # --- Redirect (multiple //) ---
    redirect_count = len(re.findall(r"//", full_url)) - 1  # first // is scheme

    # --- Fragment present ---
    has_fragment = int(bool(fragment))

    # --- Query string token count ---
    query_param_count = len([p for p in query.split("&") if p]) if query else 0

    return {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "path_depth": path_depth,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "dot_count": dot_count,
        "at_count": at_count,
        "question_count": question_count,
        "amp_count": amp_count,
        "equals_count": equals_count,
        "hash_count": hash_count,
        "percent_count": percent_count,
        "slash_count": slash_count,
        "double_slash": double_slash,
        "digit_ratio": digit_ratio,
        "has_at": has_at,
        "has_ip": has_ip,
        "is_https": is_https,
        "subdomain_depth": subdomain_depth,
        "is_suspicious_tld": is_suspicious_tld,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_domain": brand_in_domain,
        "is_shortener": is_shortener,
        "domain_entropy": domain_entropy,
        "subdomain_entropy": subdomain_entropy,
        "max_digit_run": max_digit_run,
        "has_punycode": has_punycode,
        "redirect_count": redirect_count,
        "has_fragment": has_fragment,
        "query_param_count": query_param_count,
    }
