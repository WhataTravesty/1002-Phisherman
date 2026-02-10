from src.rules.feat.risk_scoring import append_results_to_dataframe
from src.rules.feat.distance_check import get_domain_message, get_domain_boolean, get_domain_score
import pandas as pd

global email
global fieldnames

sender_domain = "user@pythonn.org"
email = "URGENT: Click here to verify your bank account password"



def main():
    dictionary = {
        "email":[email],
        "sender_domain":[sender_domain]
        }
    
    df = pd.DataFrame(dictionary)
    df = append_results_to_dataframe(df)
    df.to_csv("outputs/keyword_scoring.csv")
    print(test)

def test():
    print(get_domain_score(sender_domain))
    print(get_domain_boolean(sender_domain))
    print(get_domain_message(sender_domain))

if __name__ == "__main__":
    print(main())