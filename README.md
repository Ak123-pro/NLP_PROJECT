# Privacy-Preserving Threat Detection System

A machine learning + NLP-based behavioral threat detection system that analyzes user search history and predicts potential violent or escalating behavior while preserving user privacy.

## Project Overview

This project analyzes search queries over time and identifies potentially threatening behavioral patterns such as:

- Violent intent
- Escalating search behavior
- Repeated harmful searches
- Weapon/explosive-related intent

Instead of storing raw user searches, the system stores only:

- Query hashes
- Threat scores
- Behavioral statistics

This helps preserve privacy while still enabling threat detection.

---

## Features

### NLP-Based Query Analysis

The system detects:

- Violent keywords
- Harmful intent
- Weapon-related searches
- Explosive-related searches

Example:

- "how to make a bomb"
- "best weapon for attack"

---

### Behavioral Analysis

The system analyzes:

- Search history progression
- Frequency of dangerous searches
- Escalation patterns
- Average threat score
- Maximum threat score

---

### Machine Learning Prediction

The system extracts behavioral features and predicts:

- SAFE
- HIGH RISK

Machine learning model:

- Random Forest Classifier

---

### Privacy Preservation

Raw user queries are never stored.

Each query is converted into:

- SHA-256 hash

Stored data:

- Query hash
- Timestamp
- Threat score

---

## Project Structure

```text
NLP_PROJECT/
│
├── app.py
├── threat_detector.py
├── train_model.py
├── data_preprocessing.py
├── make_small_dataset.py
│
├── templates/
│   └── index.html
│
├── models/
│   └── model.pkl
│
├── data/               (ignored in git)
│   └── dataset.txt
│
├── requirements.txt
└── README.md
```

---

## Technologies Used

- Python
- Flask
- NLTK
- Pandas
- Scikit-learn

Key concepts:

- Natural Language Processing
- Behavioral Analytics
- Privacy-Preserving AI
- Machine Learning

---

## Dataset

This project uses the AOL search query dataset.

Dataset fields:

- AnonID
- Query
- QueryTime
- ItemRank
- ClickURL

Example:

| AnonID | Query | QueryTime |
|--------|-------|-----------|
| 479 | family guy | 2006-03-01 |
| 479 | best weapon | 2006-03-02 |
| 479 | how to attack | 2006-03-03 |

Dataset is not included in this repository.

Place your dataset here:

```bash
data/dataset.txt
```

---

## Installation

Clone repository:

```bash
git clone <your-repo-url>
cd NLP_PROJECT
```

Create virtual environment:

```bash
python -m venv venv
```

Activate:

Linux/macOS:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Download NLTK resources:

```python
import nltk
nltk.download('stopwords')
```

---

## Training

Optional: create smaller dataset:

```bash
python make_small_dataset.py
```

Train model:

```bash
python train_model.py
```

This will create:

```text
models/model.pkl
```

---

## Running the Application

Start Flask app:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## How It Works

### Step 1

User enters search query.

### Step 2

NLP engine extracts:

- Threat keywords
- Intent patterns

### Step 3

Behavioral features are calculated:

- Total searches
- Dangerous searches
- Average score
- Maximum score
- Escalation

### Step 4

Machine learning model predicts risk.

---

## Example

Input sequence:

```text
family guy
car decals
best weapon
how to attack
how to make bomb
```

Prediction:

```text
HIGH RISK
```

---

## Future Improvements

- Transformer-based intent detection
- Semantic similarity analysis
- Real-time streaming analysis
- User dashboard
- Explainable AI

---

## Author

Akash
PG Computer Science