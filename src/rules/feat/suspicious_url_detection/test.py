from url_scoring import extract_score_and_boolean
from src.rules.feat.distance_check.distance_check import enhanced_distance_check
import pandas as pd

def score_urls_in_dataset_with_single_test(
    csv_path: str,
):
    df = pd.read_csv(csv_path)
    df[["url_score", "url_boolean"]] = df.apply(extract_score_and_boolean, axis=1)
    df[["enhanced_score"]] = df["senders_domain"].apply(enhanced_distance_check)
    print(df[["enhanced_score"]].head(20))
    # print(df[["url_score", "url_boolean"]].head(20))
    # print(df["url_boolean"].value_counts(dropna=False))
    # print("Any True?", df["url_boolean"].any()) 
    # print("Highest URL score:", df["url_score"].max())
    
    return df

score_urls_in_dataset_with_single_test(csv_path="dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv")