# import pandas as pd
# from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.linear_model import LogisticRegression
# import pickle

# df = pd.read_csv("processed_results.csv")

# df['label'] = df['score'].apply(lambda x: 1 if x >= 3 else 0)

# vec = TfidfVectorizer()
# X = vec.fit_transform(df['query'])
# y = df['label']

# model = LogisticRegression()
# model.fit(X, y)

# pickle.dump(model, open("models/model.pkl", "wb"))
# pickle.dump(vec, open("models/vectorizer.pkl", "wb"))


import os

import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier

from threat_detector import PrivacyPreservingThreatDetector


# Load dataset + preprocessing
df = pd.read_csv(
    "data/dataset_small.txt",
    sep="\t"
)

# Remove missing rows
df = df.dropna(subset=["Query", "AnonID", "QueryTime"])

# Convert query to string
df["Query"] = df["Query"].astype(str)

# Remove empty queries
df = df[df["Query"].str.strip() != ""]

# Convert time
df["QueryTime"] = pd.to_datetime(
    df["QueryTime"],
    errors="coerce"
)

# Remove invalid dates
df = df.dropna(subset=["QueryTime"])


# Sort by user + time
df["QueryTime"] = pd.to_datetime(df["QueryTime"])
df = df.sort_values(["AnonID", "QueryTime"])


training_data = []


# Process one user at a time
print("Processing users and extracting features...")
for user_id, group in df.groupby("AnonID"):

    detector = PrivacyPreservingThreatDetector()

    dangerous_queries = 0
    max_score = 0
    total_score = 0

    # Feed searches one-by-one
    for _, row in group.iterrows():

        alert, result = detector.analyze_query(
            row["Query"]
        )

        score = result["score"]

        total_score += score

        if score > 0:
            dangerous_queries += 1

        if score > max_score:
            max_score = score

    # Feature 1
    total_searches = len(group)

    # Feature 2
    avg_score = total_score / total_searches

    # Feature 3
    escalation = int(
        detector.detect_escalation()
    )

    # Feature vector
    features = [
        total_searches,
        dangerous_queries,
        max_score,
        avg_score,
        escalation
    ]

    # Label
    # risky = many dangerous searches
    label = int(
        dangerous_queries >= 3
        or escalation == 1
        or avg_score >= 2
    )

    training_data.append(
        features + [label]
    )

print("Feature extraction completed. Total users processed:", len(training_data))
# Create dataframe
train_df = pd.DataFrame(
    training_data,
    columns=[
        "total_searches",
        "dangerous_queries",
        "max_score",
        "avg_score",
        "escalation",
        "label"
    ]
)


# Split X and y
X = train_df.drop("label", axis=1)
y = train_df["label"]

print("Training data prepared. Sample:")
# Train model
model = RandomForestClassifier()

model.fit(X, y)

os.makedirs("models", exist_ok=True)
# Save model
pickle.dump(
    model,
    open("models/model.pkl", "wb")
)

print("Model trained successfully")