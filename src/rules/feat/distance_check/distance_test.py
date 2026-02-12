from distance_check_function import get_domain_boolean
import pandas as pd

# from distance_check import LEGIT_DOMAINS

def score_urls_in_dataset_with_single_test(
    csv_path: str,
):
    df = pd.read_csv(csv_path)
    # df[["url_score", "url_boolean"]] = df.apply(extract_score_and_boolean, axis=1)

    df["enhanced_score"] = df["sender_domain"].apply(get_domain_boolean)

    print(df[["enhanced_score"]].head(20))
    # print(df[["url_score", "url_boolean"]].head(20))S
    # print(df["url_boolean"].value_counts(dropna=False))
    # print("Any True?", df["url_boolean"].any()) 
    # print("Highest URL score:", df["url_score"].max())
    
    return df

score_urls_in_dataset_with_single_test(csv_path="dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv")

