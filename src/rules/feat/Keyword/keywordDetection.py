import re
import csv
from keywords_list import KEYWORDS


def position_multiplier(position: int, text_length: int) -> float:
    ratio = position / text_length

    if ratio < 0.2:
        return 1.5
    elif ratio < 0.5:
        return 1.2
    else:
        return 1.0
    

def analyze_email(email_body: str):
    email_body = email_body.lower()
    length = len(email_body)

    results = []
    total_score = 0.0

    for match in re.finditer(r"\b\w+\b", email_body):
        word = match.group()
        pos = match.start()

        if word in KEYWORDS:
            rule = KEYWORDS[word]
            multiplier = position_multiplier(pos, length)
            score = rule.base_weight * multiplier

            results.append({
                "name":word,
                "position": pos,
                "score": score
            })


            total_score += score

    #Appending the Total Score to the top of the data
    total_score_dict = {
        "name": "TOTAL_SCORE",
        "position": "nil",
        "score": round(total_score,2)
    }
    results.insert(0,total_score_dict)
        
    return results

#Takes in a list and writes in string to a txt file
def outputKeywordScoring(result):
    fieldnames = result[0].keys()
    with open("outputs/keyword_scoring.csv","w") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        # Create a DictWriter object
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        # Write the header row
        writer.writeheader()

        # Write the data rows
        writer.writerows(result)

def main():
    email = "URGENT: Click here to verify your bank account password"
    outputKeywordScoring(analyze_email(email))
    return 0

if __name__ == "__main__":
    main()