KEYWORDS = [
    "urgent",
    "verify",
    "login",
    "password",
    "reset password",
    "account",
    "suspended",
    "locked",
    "click here",
    "security",
    "unusual activity",
    "invoice",
    "payment",
    "refund",
    "attachment"
]


def keyword_detection(subject, email):
    text = subject + " " + email
    found_keywords = []

    for keyword in KEYWORDS:
        if keyword in text:
            found_keywords.append(keyword)

    return found_keywords


def keyword_scoring(found_keywords):
    hit_count = len(set(found_keywords))  # distinct keywords

    if hit_count == 0:
        score = 0
    elif hit_count == 1:
        score = 5
    elif hit_count <= 3:
        score = 10
    else:
        score = 15

    return score


def main():
    subject = input("subject: ")
    email = input("email: ")

    found_keywords = keyword_detection(subject, email)
    score = keyword_scoring(found_keywords)

    print("\n--- Keyword Detection Result ---")
    print("Detected keywords:", found_keywords)
    print("Number of keyword hits:", len(set(found_keywords)))
    print("Keyword risk score:", score, "/ 15")


main()
