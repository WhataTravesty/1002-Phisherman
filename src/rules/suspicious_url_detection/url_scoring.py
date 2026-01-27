import pandas as pd
from suspicious_url_rules import (
    parse_url,
    email_url_http_check,
    email_url_shortening_service_check,
    email_ip_url_check,
    email_suspicious_tld_check,
    email_sender_domain_mismatch_check,
    bool_to_score
)

# ================== LOAD MAIN EMAIL DATASET ==================
cleaned_dataset_path = "dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv"

df = pd.read_csv(
    cleaned_dataset_path,
    encoding="latin1",
    engine="python"
)

# ================== PREP URL LIST COLUMN ==================
df["url_list"] = df["urls"].apply(parse_url)

# ================== APPLY RULE FLAGS ==================
df["http_only_flag"] = df["url_list"].apply(email_url_http_check)
df["url_shortening_flag"] = df["url_list"].apply(email_url_shortening_service_check)
df["suspicious_tld_flag"] = df["url_list"].apply(email_suspicious_tld_check)
df["ip_based_url_flag"] = df["url_list"].apply(email_ip_url_check)

# sender mismatch needs both url_list + sender_domain, so use df.apply
def sender_mismatch_for_row(row):
    return email_sender_domain_mismatch_check(row["url_list"], row["sender_domain"])

df["sender_domain_mismatch_flag"] = df.apply(sender_mismatch_for_row, axis=1)

# ================== SCORING (OUT OF 10) ==================
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


df["http_score"] = df["http_only_flag"].apply(score_http)
df["mismatch_score"] = df["sender_domain_mismatch_flag"].apply(score_mismatch)
df["shortener_score"] = df["url_shortening_flag"].apply(score_shortener)
df["ip_score"] = df["ip_based_url_flag"].apply(score_ip)
df["tld_score"] = df["suspicious_tld_flag"].apply(score_tld)
df["total_suspicious_url_score"] = (
    df["http_score"] +
    df["mismatch_score"] +
    df["shortener_score"] +
    df["ip_score"] +
    df["tld_score"]
)


# ================== OUTPUT / EVALUATION ==================
print(df[["label", "total_suspicious_url_score"]].head(20))
print("Max score:", df["total_suspicious_url_score"].max())
print("Total rows:", len(df))


print(df["total_suspicious_url_score"].max())
count_0_to_2 = 0
count_3_to_4 = 0
count_5_to_6 = 0
count_7_above = 0

for x in df["total_suspicious_url_score"]:
    if 0 <= x <= 2:
        count_0_to_2 += 1
    elif 3 <= x <= 4:
        count_3_to_4 += 1
    elif 5 <= x <= 6:
        count_5_to_6 += 1
    else:
        count_7_above += 1

print("Count of scores from 0 to 2:", count_0_to_2)
print("Count of scores from 3 to 4:", count_3_to_4)
print("Count of scores from 5 to 6:", count_5_to_6)
print("Count of scores from 7 and above:", count_7_above)