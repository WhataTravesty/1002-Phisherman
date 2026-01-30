from src.rules.feat.Keyword import analyze_email
from src.rules.feat.risk_scoring import outputScoring

def main():
    email = "URGENT: Click here to verify your bank account password"
    outputScoring(analyze_email(email),"outputs/keyword_scoring.csv")
    return 0

if __name__ == "__main__":
    print(main())