#==================================RULES==================================
# scoring system for URL detection
# url starting with http (no https) + 1
# sender domain & url domain mismatch + 2
# url shortening service + 2
# url with IP address + 3
# suspicious TLD + 2
#=========================================================================

# ============================== IMPORTS ==============================
import pandas as pd
import ast
import re
from urllib.parse import urlparse
import csv
import sys

# Increase max CSV field size limit
csv.field_size_limit(sys.maxsize)

# Regex to detect IPv4 addresses like 192.168.1.1
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ============================== LOAD DATASET ==============================
cleaned_dataset_path = "dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv"

df = pd.read_csv(
    cleaned_dataset_path,
    encoding="latin1",
    engine="python"
)

# ============================== LOAD SUSPICIOUS TLDS ==============================
tlds = pd.read_csv(
    "src/rules/feat/suspicious_url_detection/dataset/suspicious_tlds_list.csv",
    encoding="latin1",
    engine="python",
)

suspicious_tlds_domain = tlds["url_domain"].tolist()

SUSPICIOUS_TLD_SET = set(
    pd.Series(suspicious_tlds_domain)
    .dropna()
    .astype(str)
    .str.lower()
    .str.strip()
    .str.replace(".", "", regex=False)
    .str.replace("*", "", regex=False)
    .loc[lambda s: s != ""]
    .tolist()
)

# ============================== LOAD SHORTENERS ==============================
def load_url_shortening_services(filepath):
    shorteners = set()

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain == "" or domain.startswith("#"):
                continue
            shorteners.add(domain)

    return shorteners


SHORTENER_SET = load_url_shortening_services(
    "src/rules/feat/suspicious_url_detection/dataset/url_shortening_service.txt"
)

# ============================== HELPERS ==============================
def get_hostname_from_url(url):
    try:
        host = urlparse(url).hostname
        if not host:
            return ""
        return host.lower().strip(".")
    except Exception:
        return ""


def parse_url(url):
    if pd.isna(url):
        return []
    try:
        parsed = ast.literal_eval(url)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []

# ============================== TLD CHECK ==============================
def get_tld_from_url(url):
    try:
        host = get_hostname_from_url(url)

        if not host:
            return ""

        if IPV4_RE.match(host):
            return ""

        parts = host.split(".")
        if len(parts) < 2:
            return ""

        return parts[-1]

    except Exception:
        return ""


def email_suspicious_tld_check(urls):
    for url in urls:
        tld = get_tld_from_url(url)
        if tld in SUSPICIOUS_TLD_SET:
            return True
    return False

# ============================== HTTP CHECK ==============================
def is_http_not_https(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme == "http"
    except Exception:
        return False


def email_url_http_check(urls):
    for url in urls:
        if is_http_not_https(url):
            return True
    return False

# ============================== SHORTENER CHECK ==============================
def url_shortening_service_check(url):
    host = get_hostname_from_url(url)

    if host == "":
        return False

    if host.startswith("www."):
        host = host[4:]

    return host in SHORTENER_SET


def email_url_shortening_service_check(urls):
    for url in urls:
        if url_shortening_service_check(url):
            return True
    return False

# ============================== IP CHECK ==============================
def url_contains_ip_address(url):
    try:
        host = get_hostname_from_url(url)
        if not host:
            return False
        return IPV4_RE.match(host) is not None
    except Exception:
        return False


def email_ip_url_check(urls):
    for url in urls:
        if url_contains_ip_address(url):
            return True
    return False

# ============================== DOMAIN MISMATCH ==============================
def get_base_domain(domain):
    if not domain:
        return ""

    parts = domain.lower().strip().split(".")
    if len(parts) < 2:
        return domain.lower().strip()
    else:
        return ".".join(parts[-2:])


def is_sender_domain_mismatch(sender_domain, url):
    if sender_domain is None or pd.isna(sender_domain):
        return False

    if not isinstance(sender_domain, str):
        sender_domain = str(sender_domain)

    if not url:
        return False

    url_host = get_hostname_from_url(url)
    if not url_host:
        return False

    sender_base = get_base_domain(sender_domain)
    url_base = get_base_domain(url_host)

    return sender_base != url_base


def email_sender_domain_mismatch_check(urls, sender_domain):
    for url in urls:
        if is_sender_domain_mismatch(sender_domain, url):
            return True
    return False


def sender_domain_mismatch_for_row(row):
    return email_sender_domain_mismatch_check(
        row["url_list"],
        row["sender_domain"]
    )

# ============================== SCORING ==============================
def bool_to_score(flag, points):
    if flag:
        return points
    else:
        return 0


def score_http(flag):
    return bool_to_score(flag, 1)


def score_mismatch(flag):
    return bool_to_score(flag, 2)


def score_shortener(flag):
    return bool_to_score(flag, 2)


def score_ip(flag):
    return bool_to_score(flag, 3)


def score_tld(flag):
    return bool_to_score(flag, 2)

# # ============================== APPLY RULES ==============================
# df["url_list"] = df["urls"].apply(parse_url)

# df["http_only_flag"] = df["url_list"].apply(email_url_http_check)

# df["url_shortening_flag"] = df["url_list"].apply(email_url_shortening_service_check)

# df["suspicious_tld_flag"] = df["url_list"].apply(email_suspicious_tld_check)

# df["ip_based_url_flag"] = df["url_list"].apply(email_ip_url_check)

# df["sender_domain_mismatch_flag"] = df.apply(
#     sender_domain_mismatch_for_row,
#     axis=1
# )

# ============================== DISPLAY OPTIONS ==============================
pd.set_option("display.max_rows", None)
pd.set_option("display.max_columns", None)
pd.set_option("display.max_colwidth", None)

# ============================== OPTIONAL LABEL DISTRIBUTION ==============================
# print("Total number of emails: ", len(df))
# print("Count of label 0:", (df["label"] == 0).sum())
# print("Count of label 1:", (df["label"] == 1).sum())
