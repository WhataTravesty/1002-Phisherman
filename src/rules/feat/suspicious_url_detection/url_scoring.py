import pandas as pd
from suspicious_url_rules import (
    parse_url,
    email_url_http_check,
    email_url_shortening_service_check,
    email_ip_url_check,
    email_suspicious_tld_check,
    email_sender_domain_mismatch_check,
    bool_to_score,
)

# def score_urls_in_dataset(
#     csv_path: str,
#     output_csv_path: str | None = None,
#     encoding: str = "latin1",
#     engine: str = "python",
#     print_summary: bool = True,
# ) -> pd.DataFrame:
#     """
#     Load a cleaned email CSV, compute URL rule flags + scores, and optionally save to a new CSV.

#     Required columns:
#       - 'urls'
#       - 'sender_domain'
#     Optional columns:
#       - 'label' (only used for printing head)

#     Returns:
#       DataFrame with new columns added.
#     """
#     df = pd.read_csv(csv_path, encoding=encoding, engine=engine)

#     # --- basic validation ---
#     required = {"urls", "sender_domain"}
#     missing = required - set(df.columns)
#     if missing:
#         raise ValueError(f"CSV missing required columns: {sorted(missing)}")

#     # ================== PREP URL LIST COLUMN ==================
#     df["url_list"] = df["urls"].apply(parse_url)

#     # ================== APPLY RULE FLAGS ==================
#     df["http_only_flag"] = df["url_list"].apply(email_url_http_check)
#     df["url_shortening_flag"] = df["url_list"].apply(email_url_shortening_service_check)
#     df["suspicious_tld_flag"] = df["url_list"].apply(email_suspicious_tld_check)
#     df["ip_based_url_flag"] = df["url_list"].apply(email_ip_url_check)

#     def sender_mismatch_for_row(row):
#         return email_sender_domain_mismatch_check(row["url_list"], row["sender_domain"])

#     df["sender_domain_mismatch_flag"] = df.apply(sender_mismatch_for_row, axis=1)

#     # ================== TALLY SCORES ==================

#     # Calculate individual scores
#     http_score = df["http_only_flag"].apply(lambda f: bool_to_score(f, 1))
#     mismatch_score = df["sender_domain_mismatch_flag"].apply(lambda f: bool_to_score(f, 2))
#     shortener_score = df["url_shortening_flag"].apply(lambda f: bool_to_score(f, 2))
#     ip_score = df["ip_based_url_flag"].apply(lambda f: bool_to_score(f, 3))
#     tld_score = df["suspicious_tld_flag"].apply(lambda f: bool_to_score(f, 2))

#     # Tally the total score and multiply by 3 for the final score (out of 30)
#     df["total_suspicious_url_score"] = (
#         http_score + mismatch_score + shortener_score + ip_score + tld_score
#     ) * 3

#     # ================== ADD BOOLEAN COLUMN ==================
#     df["suspicious_url_boolean"] = df["total_suspicious_url_score"].apply(lambda score: score > 15)

#     # ================== OPTIONAL SUMMARY ==================
#     if print_summary:
#         cols = ["total_suspicious_url_score", "suspicious_url_boolean"]
#         if "label" in df.columns:
#             cols = ["label"] + cols

#         print(df[cols].head(20))
#         print("Max score:", df["total_suspicious_url_score"].max())
#         print("Total rows:", len(df))

#         # bucket counts
#         s = df["total_suspicious_url_score"]
#         count_0_to_15 = ((s >= 0) & (s <= 15)).sum()
#         count_15_to_30 = ((s >= 15) & (s <= 30)).sum()
#         # count_5_to_6 = ((s >= 5) & (s <= 6)).sum()
#         # count_7_above = (s >= 7).sum()

#         print("Count of scores from 0 to 15:", int(count_0_to_15))
#         print("Count of scores from 16 to 30:", int(count_15_to_30))

#     # ================== OPTIONAL SAVE ==================
#     # if output_csv_path:
#     #     df.to_csv(output_csv_path, index=False)
#     # # ================== Test ==================
#     # def test_function():
#     #     score = 30
#     #     boo_flag = True
#     #     return boo_flag, score

#     # df["test"] = test_function()[1]
    
#     return df


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
    http_score = bool_to_score(http_only_flag, 1)  # 1 point
    mismatch_score = bool_to_score(sender_domain_mismatch_flag, 2)  # 2 points
    shortener_score = bool_to_score(url_shortening_flag, 2)  # 2 points
    ip_score = bool_to_score(ip_based_url_flag, 3)  # 3 points
    tld_score = bool_to_score(suspicious_tld_flag, 2)  # 2 points

    # Calculate total score out of 10, then multiply by 3 to get out of 30
    total_score = (http_score + mismatch_score + shortener_score + ip_score + tld_score) * 3

    # ================== OPTIONAL SUMMARY ==================
    if print_summary:
        print("Total score:", total_score)
        print("Max score:", 30)  # Max score is now 30

    # Return True if score is greater than 15, else False
    return total_score > 15, total_score


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

