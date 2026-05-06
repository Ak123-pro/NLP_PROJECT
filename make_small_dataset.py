import pandas as pd

df = pd.read_csv(
    "data/dataset.txt",
    sep="\t"
)

small_df = df.sample(
    n=300000,
    random_state=42
)

small_df.to_csv(
    "data/dataset_small.txt",
    sep="\t",
    index=False
)

print("Done")