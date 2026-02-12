from src.rules.feat.distance_check.distance_check_function import get_domain_boolean, get_domain_score
from src.rules.feat.suspicious_url_detection.url_scoring import extract_score_and_boolean
from src.rules.feat.Keyword.keywordDetection import analyze_email, boolean_result
from src.rules.feat.whitelist_check.whitelist_check import get_whitelist_boolean, get_whitelist_score
import pandas as pd

def score_urls_in_dataset_with_single_test(
    csv_path: str,
):
    
    df = pd.read_csv(csv_path)


    # print("\n📂 BEFORE SCORING — Original Headers")
    # print("-" * 50)
    # for col in df.columns:
    #     print(col)
        
        
    df[["url_score", "url_boolean"]] = df.apply(extract_score_and_boolean, axis=1)
    df["distance_check_boolean"] = df["sender_domain"].apply(get_domain_boolean)
    df["distance_check_score"] = df["sender_domain"].apply(get_domain_score)
    df["keyword_score"] = df["body_clean"].apply(analyze_email)
    df["keyword_boolean"] = df["keyword_score"].apply(boolean_result)
    df["whitelist_boolean"] = df["sender_domain"].apply(get_whitelist_boolean)
    df["whitelist_score"] = df["sender_domain"].apply(get_whitelist_score)
    
    print(df[["url_score", "url_boolean","distance_check_score", "distance_check_boolean", "keyword_score", "keyword_boolean","whitelist_score", "whitelist_boolean"]].head(20))
    # auto output path
    
    
    # -------------------------------
    # TOTAL RISK SCORE
    # -------------------------------
    df["total_risk_score"] = (
        df["url_score"]
        + df["distance_check_score"]
        + df["keyword_score"]
        + df["whitelist_score"]
    )
    # -------------------------------
    # PHISHING FLAG (>50)
    # -------------------------------
    df["is_phishing"] = (df["total_risk_score"] > 40).astype(int)

    
    # True Positives (TP)
    tp = ((df["label"] == 1) & (df["is_phishing"] == 1)).sum()

    # False Negatives (FN) — phishing but missed
    fn = ((df["label"] == 1) & (df["is_phishing"] == 0)).sum()

    # False Positives (FP) — ham flagged as phishing
    fp = ((df["label"] == 0) & (df["is_phishing"] == 1)).sum()

    # True Negatives (TN) — ham correctly ignored
    tn = ((df["label"] == 0) & (df["is_phishing"] == 0)).sum()

    print("\n📊 DETECTION EVALUATION")
    print("-" * 50)
    print(f"Phishing detected correctly (TP): {tp}")
    print(f"Phishing missed (FN):            {fn}")
    print(f"Ham flagged as phishing (FP):   {fp}")
    print(f"Ham correctly ignored (TN):     {tn}")
    # df.to_csv("scored_output.csv", index=False)
    
    accuracy = (df["label"] == df["is_phishing"].astype(int)).mean()
    print(f"Accuracy: {accuracy:.2%}")
    print(f"\n🔗 Highest URL Score: {df['url_score'].max()}")
    print(f"\n🔗 Average URL Score: {df['url_score'].mean():.2f}")

    
    # print("\n🧠 AFTER SCORING — Updated Headers")
    # print("-" * 50)
    # for col in df.columns:
    #     print(col)
    # return df

score_urls_in_dataset_with_single_test(csv_path="dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv")

