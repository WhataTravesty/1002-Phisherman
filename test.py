from src.rules.feat.risk_scoring import append_results_to_dataframe
import pandas as pd

global email
global fieldnames

email = "URGENT: Click here to verify your bank account password"
domain = "asmdasd"



def main():
    dictionary = {
        "email":[email],
        "domain":["gmaail.com"]
        }
    df = pd.DataFrame(dictionary)

    df = append_results_to_dataframe(df)

    df.to_csv("outputs/keyword_scoring.csv")

if __name__ == "__main__":
    print(main())