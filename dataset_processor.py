import pandas as pd
from threat_detector import PrivacyPreservingThreatDetector

def process_dataset(path):
    df = pd.read_csv(path, sep="\t")
    df['QueryTime'] = pd.to_datetime(df['QueryTime'])

    results = []

    for user, group in df.groupby('AnonID'):
        detector = PrivacyPreservingThreatDetector()
        group = group.sort_values('QueryTime')

        for _, row in group.iterrows():
            alert, reason = detector.analyze_query(row['Query'])

            results.append({
                "user": user,
                "query": row['Query'],
                "time": row['QueryTime'],
                "score": reason["score"],
                "alert": alert
            })

    return pd.DataFrame(results)

if __name__ == "__main__":
    df = process_dataset("data/dataset.csv")
    df.to_csv("processed_results.csv", index=False)