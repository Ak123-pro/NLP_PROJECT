import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("processed_results.csv")

plt.plot(df['score'])
plt.title("Threat Score Over Time")
plt.xlabel("Index")
plt.ylabel("Score")
plt.show()
