#==================================RULES==================================
# scoring system for URL detection
# url starting with http (no https) + 1 (DONE)
# sender domain & url domain mismatch + 2
# url shortening service + 2 (DONE)
# url with IP address + 3 (DONE)
# suspicious TLD + 2 (DONE)
#=========================================================================

# Imports
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
#==================================LOADING DATASETS==================================
# Load cleaned dataset small sample for testing
cleaned_dataset_path = "dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv"

df = pd.read_csv(
    cleaned_dataset_path,
    encoding="latin1",
    engine="python"
)

#Extract URLs and sender domains from the dataset
# urls = df["urls"].tolist()
domains = df["sender_domain"].tolist()

#==================================HELPERS==================================
# Load suspicious TLDs list
tlds = pd.read_csv(
    "src/rules/suspicious_url_detection/dataset/suspicious_tlds_list.csv",
    encoding="latin1",
    engine="python",
)


# TLD list formats are *.suspicious_tld
# Extract only the domain part from the TLDs List
suspicious_tlds_domain = tlds["url_domain"].tolist()


# Make suspicious TLD set
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


# Load URL shortening services list
def load_url_shortening_services(filepath: str) -> set:
    shorteners = set()

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain == "" or domain.startswith("#"):
                continue
            shorteners.add(domain)

    return shorteners


SHORTENER_SET = load_url_shortening_services(
    "src/rules/suspicious_url_detection/dataset/url_shortening_service.txt"
)
    
# Function to get hostname from URL
def get_hostname_from_url(url: str) -> str:
    try:
        host = urlparse(url).hostname
        if not host:
            return ""
        return host.lower().strip(".")
    except Exception:
        return ""
    

# Function to Parse URL
def parse_url(url):
    if pd.isna(url):
        return []
    try:
        parsed = ast.literal_eval(url)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []
    
    
#==================================TLD IN URL CHECK==================================
def get_tld_from_url(url: str) -> str:
    try:
        host = get_hostname_from_url(url)
        
        if not host:
            return ""
        
        
        host = host.lower().strip(".")
        
        if IPV4_RE.match(host):
            return ""
        
        parts = host.split(".")
        
        if len(parts) < 2:
            return ""
        
        return parts[-1]
    
    except Exception:
        return ""
    
    
# Function to check if any URL in the email has suspicious TLD
def email_suspicious_tld_check(urls: list) -> bool:
    """
    Returns True if ANY url inside the email has suspicious TLD.
    """
    for url in urls:
        tld = get_tld_from_url(url)
        if tld in SUSPICIOUS_TLD_SET:
            return True
    return False


#==================================HTTP IN URL CHECK==================================
#Function to check for domains with http only
def is_http_not_https(url: str):
    try:
        parsed = urlparse(url)
        return parsed.scheme == "http"
    except Exception:
        print("Error parsing URL:", url)
        return False
    

#Check for http only URLs in email
def email_url_http_check(urls: list) -> bool:
    """
    Returns True if ANY url inside the email starts with http only.
    """
    for url in urls:
        if is_http_not_https(url):
            return True
    return False


#==================================URL SHORTENING SERVICE CHECK==================================
def url_shortening_service_check(url: str) -> bool:
    """
    Check if the URL uses a known URL shortening service.
    """
    host = get_hostname_from_url(url)
    
    
    if host == "":
        return False

    if host.startswith("www."):
        host = host[4:]
        
    return host in SHORTENER_SET


def email_url_shortening_service_check(urls: list) -> bool:
    """
    Returns True if ANY url inside the email uses a URL shortening service.
    """
    for url in urls:
        if url_shortening_service_check(url):
            return True
    return False


#==================================IP ADDRESS IN URL CHECK==================================
def url_contains_ip_address(url: str) -> bool:
    """
    Check if the URL contains an IP address in the hostname.
    """
    try:
        host = get_hostname_from_url(url)
        if not host:
            return False
        return IPV4_RE.match(host) is not None
    except Exception:
        return False
    

def email_ip_url_check(urls: list) -> bool:
    """
    Returns True if ANY url in the email is IP-based.
    """
    for url in urls:
        if url_contains_ip_address(url):
            return True
    return False


#==================================SENDER DOMAIN =x URL DOMAIN==================================
def get_base_domain(domain: str) -> str:
    """
    Extract the base domain from a full domain.
    E.g., mail.example.co.uk -> example.co.uk
    """
    if not domain:
        return ""
    
    parts = domain.lower().strip().split(".")
    if len(parts) < 2:
        return domain.lower().strip()
    else:
        return ".".join(parts[-2:])
    

def is_sender_domain_mismatch(sender_domain: str, url: str) -> bool:
    """
    Returns True if sender domain != URL base domain.
    """
    # sender_domain might be NaN (float) so check properly
    if sender_domain is None or pd.isna(sender_domain):
        return False
    if not isinstance(sender_domain, str):
        sender_domain = str(sender_domain)

    if not url:
        return False

    url_host = get_hostname_from_url(url)
    if not url_host:
        return False

    sender_base = get_base_domain(sender_domain)  # get_base_domain already lowercases
    url_base = get_base_domain(url_host)

    return sender_base != url_base


def email_sender_domain_mismatch_check(urls: list, sender_domain: str) -> bool:
    """
    Returns True if ANY url in the email mismatches sender domain.
    """
    for url in urls:
        if is_sender_domain_mismatch(sender_domain, url):
            return True
    return False


def sender_domain_mismatch_for_row(row):
    return email_sender_domain_mismatch_check(
        row["url_list"],
        row["sender_domain"]
    )


#==================================Score Counting==================================
def bool_to_score(flag: bool, points: int) -> int:
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



#==================================Result Testing==================================
# Convert URLs from string representation of list to actual list
df["url_list"] = df["urls"].apply(parse_url)

df ["http_only_flag"] = df["url_list"].apply(email_url_http_check)

df ["url_shortening_flag"] = df["url_list"].apply(email_url_shortening_service_check)

df["suspicious_tld_flag"] = df["url_list"].apply(email_suspicious_tld_check)

df["ip_based_url_flag"] = df["url_list"].apply(email_ip_url_check)

df["sender_domain_mismatch_flag"] = df.apply(
    sender_domain_mismatch_for_row,
    axis=1
)

pd.set_option("display.max_rows", None)
pd.set_option("display.max_columns", None)
pd.set_option("display.max_colwidth", None)


# # =================To see distribution of labels in the dataset=================

# print("Total number of emails: ", len(df))
# count_0 = 0
# count_1 = 0
# for label in df["label"]:
#     if label == 0:
#         count_0 += 1
#     else:
#         count_1 += 1
        
# print("Count of label 0:", count_0)
# print("Count of label 1:", count_1)