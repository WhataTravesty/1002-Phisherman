from src.rules.feat.risk_scoring import append_results_to_dataframe
import pandas as pd

global email
global fieldnames

email = "URGENT: Click here to verify your bank account password"
def main():
    dictionary = {
        "email":[email]
        }
    df = pd.DataFrame(dictionary)
    df = append_results_to_dataframe(df)
    df.to_csv("outputs/keyword_scoring.csv")

if __name__ == "__main__":
    print(main())