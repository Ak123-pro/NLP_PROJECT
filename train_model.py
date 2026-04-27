import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle

df = pd.read_csv("processed_results.csv")

df['label'] = df['score'].apply(lambda x: 1 if x >= 3 else 0)

vec = TfidfVectorizer()
X = vec.fit_transform(df['query'])
y = df['label']

model = LogisticRegression()
model.fit(X, y)

pickle.dump(model, open("models/model.pkl", "wb"))
pickle.dump(vec, open("models/vectorizer.pkl", "wb"))