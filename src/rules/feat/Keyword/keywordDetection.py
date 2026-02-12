import re
from .keywords_list import KEYWORDS

#Take in the position where the word was found and the length of the text
def position_multiplier(position, text_length):
    ratio = position / text_length

    if ratio < 0.2:
        return 1.5
    elif ratio < 0.5:
        return 1.2
    else:
        return 1.0
    
def boolean_result(normalized_keyword_score):
    if normalized_keyword_score > 0.3:
        return True
    else:
        return False
    

def analyze_email(email_body):
    #Convert the email to only lowercase to conduct regex search
    email_body = str(email_body).lower()
    length = len(email_body)

    #Store all dictionaries in this list
    results = []
    total_score = 0.0

    #Run a for loop to catch each word inside the email.
    for match in re.finditer(r"\b\w+\b", email_body):
        word = match.group()
        pos = match.start()

        #Apply multiplier to its score based on its postition
        if word in KEYWORDS:
            rule = KEYWORDS[word]
            multiplier = position_multiplier(pos, length)
            score = rule.base_weight * multiplier

            #Add the dictionary into the results list
            results.append({
                "name":word,
                "position": pos,
                "score": score
            })

            #Add to total score
            total_score += score
    
    normalized_keyword_score = min(total_score, 20)

    #Appending the Total Score to the top of the data
    return normalized_keyword_score