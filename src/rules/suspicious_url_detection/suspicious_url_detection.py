# scoring system for URL detection
# url starting with http (no https) + 1
# sender domain & url domain mismatch + 2
# url shortening service + 2
# url with IP address + 3
# suspicious TLD + 2
import pandas as pd
import ast
import re
from urllib.parse import urlparse


# Regex to detect IPv4 addresses like 192.168.1.1
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# Load cleaned dataset small sample for testing
cleaned_dataset_path = "dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv"

df = pd.read_csv(
    cleaned_dataset_path,
    encoding="latin1",
    engine="python",
    nrows = 2000
)

df = df.tail(20)


#Extract URLs and sender domains from the dataset
# urls = df["urls"].tolist()
domains = df["sender_domain"].tolist()

# Load suspicious TLDs list
tlds = pd.read_csv(
    "src/rules/suspicious_url_detection/dataset/suspicious_tlds_list.csv",
    encoding="latin1",
    engine="python",
)

# TLD list formats are *.suspicious_tld
# Extract only the domain part from the TLDs List
suspicious_tlds_domain = tlds["url_domain"].tolist()


# 1) Make suspicious TLD set
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

# Uncomment to see the suspicious TLD set
# print(SUSPICIOUS_TLD_SET)

# Function to Parse URL
def parse_url(url):
    if pd.isna(url):
        return []
    try:
        parsed = ast.literal_eval(url)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []
    

# Function to get TLD from URL
def get_tld_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        
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


# Convert URLs from string representation of list to actual list
df["url_list"] = df["urls"].apply(parse_url).tolist()


# Add True / False Column
df["suspicious_tld_flag"] = df["url_list"].apply(email_suspicious_tld_check)
print(df[["urls", "url_list", "suspicious_tld_flag"]])