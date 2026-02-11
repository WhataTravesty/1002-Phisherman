from src.rules.feat.distance_check.distance_check_function import get_domain_boolean, get_domain_score
from src.rules.feat.suspicious_url_detection.url_scoring import extract_score_and_boolean
from src.rules.feat.Keyword.keywordDetection import analyze_email, boolean_result

import pandas as pd

# from distance_check import LEGIT_DOMAINS

def score_urls_in_dataset_with_single_test(
    csv_path: str,
):
    
    df = pd.read_csv(csv_path)
    # print(df.columns.tolist())

    df[["url_score", "url_boolean"]] = df.apply(extract_score_and_boolean, axis=1)
    df["distance_check_boolean"] = df["sender_domain"].apply(get_domain_boolean)
    df["distance_check_score"] = df["sender_domain"].apply(get_domain_score)
    df["keyword_score"] = df["body_clean"].apply(analyze_email)
    df["keyword_boolean"] = df["keyword_score"].apply(boolean_result)
    

    print(df[["url_score", "url_boolean","distance_check_score", "distance_check_boolean", "keyword_score", "keyword_boolean"]].head(20))

    return df

score_urls_in_dataset_with_single_test(csv_path="dataset/email-dataset-figshare/Cleaned/CEAS-08_cleaned.csv")

