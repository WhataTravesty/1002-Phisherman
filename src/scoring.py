import pandas as pd

# keyword
from src.rules.feat.Keyword.keywordDetection import analyze_email as keyword_score
from src.rules.feat.Keyword.keywordDetection import boolean_result as keyword_boolean

# whitelist
from src.rules.feat.whitelist_check.whitelist_check import (
    get_whitelist_boolean,
    get_whitelist_score,
    get_whitelist_reason,
)

# distance
from src.rules.feat.distance_check.distance_check_function import (
    get_domain_boolean,
    get_domain_score,
    get_domain_message,
)

# suspicious urls
from src.rules.feat.suspicious_url_detection.suspicious_url_rules import parse_url
from src.rules.feat.suspicious_url_detection.url_scoring import score_single_email

WEIGHTS = {
    "keyword": 25,
    "whitelist": 20,
    "distance": 25,
    "suspicious_url": 30,
}

THRESHOLD = 20  # phishing if > 50


def score_dataset(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    # ensure expected cols exist (avoid KeyError on CEAV variations)
    for col in ["sender_domain", "sender_email", "subject_clean", "body_clean", "urls"]:
        if col not in out.columns:
            out[col] = ""

    # caching speeds up CEAV a LOT (same sender domains repeat)
    wl_cache = {}
    dist_cache = {}

    hit_keyword = []
    hit_whitelist = []
    hit_distance = []
    hit_susp_url = []

    keyword_score_pct = []
    whitelist_score_pct = []
    distance_score_pct = []
    suspicious_url_score_pct = []

    risk_score_pct = []
    predicted = []
    reasons = []

    for _, row in out.iterrows():
        sender_domain = str(row.get("sender_domain", "") or "")
        subject = str(row.get("subject_clean", "") or "")
        body = str(row.get("body_clean", "") or "")
        urls_raw = row.get("urls", "")

        # ---------------- KEYWORD (teammate scoring returns 0..1 normalized)
        text = (subject + " " + body).strip()
        ks = float(keyword_score(text) or 0.0)          # 0..1
        #ks = min(max(ks_norm, 0.0), 1.0) * WEIGHTS["keyword"]  # 0..20
        hk =  keyword_boolean(ks)# hit if contributes anything

        # ---------------- WHITELIST (pass -> 0 score, fail -> 25)
        if sender_domain in wl_cache:
            hw, sw, rw = wl_cache[sender_domain]
        else:
            # teammate helper returns True if whitelist PASSED
            passed = bool(get_whitelist_boolean(sender_domain))
            sw = int(get_whitelist_score(sender_domain))   # 0 or 25
            rw = str(get_whitelist_reason(sender_domain) or "")
            hw = not passed  # we treat "hit" as whitelist failure
            wl_cache[sender_domain] = (hw, sw, rw)

        # ---------------- DISTANCE (teammate scoring returns 0/20/25 etc)
        if sender_domain in dist_cache:
            hd, sd, rd = dist_cache[sender_domain]
        else:
            # teammate boolean_result means SAFE in their code (True = safe)
            safe = bool(get_domain_boolean(sender_domain))
            sd = int(get_domain_score(sender_domain))      # 0/20/25
            rd = str(get_domain_message(sender_domain) or "")
            hd = (not safe) and (sd > 0)  # hit if suspicious
            dist_cache[sender_domain] = (hd, sd, rd)

        # ---------------- SUSPICIOUS URL (score_single_email expects list)
        url_list = parse_url(urls_raw)  # handles "['http://...']"
        url_hit, url_score = score_single_email(url_list, sender_domain)
        # df[["url_score", "url_boolean"]] = df.apply(extract_score_and_boolean, axis=1)
        su = int(url_score)  # should already be 0..30
        hu = bool(url_hit)

        # ---------------- combine
        total = float(ks) + float(sw) + float(sd) + float(su)
        pred = "phishing" if total > THRESHOLD else "ham"

        why = []
        if hk:
            why.append(f"keyword(+{ks:.1f})")
        if hw:
            why.append(f"whitelist_fail(+{sw}): {rw}")
        if hd:
            why.append(f"distance(+{sd}): {rd}")
        if hu:
            why.append(f"suspicious_url(+{su})")

        hit_keyword.append(int(hk))
        hit_whitelist.append(int(hw))
        hit_distance.append(int(hd))
        hit_susp_url.append(int(hu))

        keyword_score_pct.append(round(float(ks), 2))
        whitelist_score_pct.append(int(sw))
        distance_score_pct.append(int(sd))
        suspicious_url_score_pct.append(int(su))

        risk_score_pct.append(round(float(total), 2))
        predicted.append(pred)
        reasons.append("; ".join(why) if why else "No rules triggered")

    out["hit_keyword"] = hit_keyword
    out["hit_whitelist"] = hit_whitelist
    out["hit_distance"] = hit_distance
    out["hit_suspicious_url"] = hit_susp_url

    out["keyword_score"] = keyword_score_pct
    out["whitelist_score"] = whitelist_score_pct
    out["distance_score"] = distance_score_pct
    out["suspicious_url_score"] = suspicious_url_score_pct

    out["risk_score_pct"] = risk_score_pct
    out["threshold"] = THRESHOLD
    out["predicted"] = predicted
    out["reasons"] = reasons

    return out