import re
import hashlib
from datetime import datetime, timedelta
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

class PrivacyPreservingThreatDetector:
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.search_history = []
        self.stop_words = set(stopwords.words('english'))
        self.stemmer = PorterStemmer()

        self.threat_keywords = {
            'high': ['bomb', 'explosive', 'attack', 'kill', 'shoot', 'weapon'],
            'medium': ['hurt', 'harm', 'dangerous', 'threat', 'violent'],
            'low': ['fight', 'angry', 'destroy', 'damage']
        }

    def preprocess_text(self, text):
        text = text.lower()
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        words = text.split()
        words = [self.stemmer.stem(w) for w in words if w not in self.stop_words]
        return words

    def detect_intent(self, query):
        patterns = [
            r"how to (make|build|create)",
            r"ways to (kill|attack)",
            r"best weapon for"
        ]
        for p in patterns:
            if re.search(p, query.lower()):
                return True
        return False

    def calculate_threat_score(self, query):
        words = self.preprocess_text(query)
        score = 0
        detected = []

        for w in words:
            if w in self.threat_keywords['high']:
                score += 3
                detected.append(w)
            elif w in self.threat_keywords['medium']:
                score += 2
                detected.append(w)
            elif w in self.threat_keywords['low']:
                score += 1
                detected.append(w)

        if self.detect_intent(query):
            score += 5

        return score, detected

    def detect_escalation(self):
        scores = [s['score'] for s in self.search_history[-5:]]
        if len(scores) >= 3 and scores == sorted(scores) and scores[-1] > scores[0]:
            return True
        return False

    def analyze_query(self, query):
        score, keywords = self.calculate_threat_score(query)

        query_hash = hashlib.sha256(query.encode()).hexdigest()

        self.search_history.append({
            'query_hash': query_hash,
            'score': score,
            'timestamp': self._get_timestamp()
        })

        recent_score = self.get_recent_score()

        if self.detect_escalation():
            return True, {
                "reason": "Escalating behavior detected",
                "score": score,
                "keywords_detected": keywords
            }

        if recent_score >= self.threshold:
            return True, {
                "reason": f"High-risk activity (score: {recent_score})",
                "score": score,
                "keywords_detected": keywords
            }

        return False, {
            "reason": "Safe",
            "score": score,
            "keywords_detected": keywords
        }

    def get_recent_score(self, minutes=30):
        now = datetime.now()
        total = 0
        for s in self.search_history:
            t = datetime.strptime(s['timestamp'], "%Y-%m-%d %H:%M:%S")
            if now - t <= timedelta(minutes=minutes):
                total += s['score']
        return total

    def get_risk_level(self, score):
        if score >= 5:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "SAFE"

    def get_stats(self):
        recent_score = self.get_recent_score()
        return {
            'total_searches': len(self.search_history),
            'recent_score': recent_score,
            'threshold': self.threshold,
            'remaining_before_alert': max(0, self.threshold - recent_score)
        }

    def reset_counter(self):
        self.search_history = []

    def _get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")