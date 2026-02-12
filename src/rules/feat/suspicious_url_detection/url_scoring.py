import pandas as pd
from .suspicious_url_rules import (
    parse_url,
    email_url_http_check,
    email_url_shortening_service_check,
    email_ip_url_check,
    email_suspicious_tld_check,
    email_sender_domain_mismatch_check,
    bool_to_score,
)


def score_single_email(
    email_urls: list,
    sender_domain: str,
    print_summary: bool = False,
):
    """
    Evaluate a single email for suspicious URLs and return:
    - Boolean: True if the score is > 15/30, otherwise False.
    - Score out of 30.
    """
    
    # ================== APPLY RULE FLAGS ==================
    http_only_flag = email_url_http_check(email_urls)
    url_shortening_flag = email_url_shortening_service_check(email_urls)
    suspicious_tld_flag = email_suspicious_tld_check(email_urls)
    ip_based_url_flag = email_ip_url_check(email_urls)
    sender_domain_mismatch_flag = email_sender_domain_mismatch_check(email_urls, sender_domain)

    # ================== SCORING (OUT OF 30) ==================
    http_score = bool_to_score(http_only_flag, 10)  # 1 point
    mismatch_score = bool_to_score(sender_domain_mismatch_flag, 6)  # 2 points
    shortener_score = bool_to_score(url_shortening_flag, 6)  # 2 points
    ip_score = bool_to_score(ip_based_url_flag, 12)  # 3 points
    tld_score = bool_to_score(suspicious_tld_flag, 6)  # 2 points

    raw = http_score + mismatch_score + shortener_score + ip_score + tld_score  # 0..32
    total_score = round((raw / 40) * 30)   # now 0..30


    # ================== OPTIONAL SUMMARY ==================
    if print_summary:
        print("Total score:", total_score)
        print("Max score:", 30)  # Max score is now 30

    # Return True if score is greater than 15, else False
    return total_score > 10, total_score


def extract_score_and_boolean(row):
    """
    Extract URL suspicious score + boolean flag for a single row.

    Returns (in this order to match df assignment):
        url_score (int),
        url_boolean (bool)
    """

    # Get url_list safely
    urls = row.get("url_list", None)

    # If url_list not created, parse from 'urls'
    if urls is None:
        urls = parse_url(row.get("urls", "[]"))

    # Get sender domain safely
    sender_domain = row.get("sender_domain", "")

    # score_single_email returns (is_suspicious, score)
    is_suspicious, score = score_single_email(urls, sender_domain)

    # Return in correct column order
    return pd.Series([score, is_suspicious])

