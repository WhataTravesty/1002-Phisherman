import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

# load your already scored dataset
df = pd.read_csv("outputs/latest_scored.csv")

# features (your rule outputs)
X = df[
    [
        "keyword_score",
        "whitelist_score",
        "distance_score",
        "suspicious_url_score",
    ]
]

# convert CEAV labels: phishing=1, safe=0
y = (df["label"] == 0).astype(int)

# split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# train logistic regression
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# evaluate
y_pred = model.predict(X_test)

print(classification_report(y_test, y_pred))

print("\nLearned weights:")
for name, coef in zip(X.columns, model.coef_[0]):
    print(f"{name}: {coef:.3f}")

print("Bias:", model.intercept_[0])