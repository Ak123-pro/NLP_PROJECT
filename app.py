from flask import Flask, request, jsonify, session, render_template
from threat_detector import PrivacyPreservingThreatDetector
import hashlib

app = Flask(__name__)
app.secret_key = "secret_key"

detectors = {}

def get_session_id():

    if 'user_id' not in session:
        session['user_id'] = hashlib.md5(
            str(request.remote_addr).encode()
        ).hexdigest()

    return session['user_id']


@app.route('/')
def index():

    return render_template("index.html")


@app.route('/analyze', methods=['POST'])
def analyze():

    data = request.json

    query = data.get('query', '').strip()

    sid = get_session_id()

    if sid not in detectors:
        detectors[sid] = PrivacyPreservingThreatDetector()

    detector = detectors[sid]

    if not query:

        return jsonify({
            'alert': False,
            'risk': 'SAFE',
            'reason': {'score': 0}
        })

    alert, reason = detector.analyze_query(query)

    risk = detector.get_risk_level(reason['score'])

    return jsonify({
        'alert': alert,
        'risk': risk,
        'reason': reason,
        'stats': detector.get_stats()
    })


@app.route('/reset', methods=['POST'])
def reset():

    sid = get_session_id()

    if sid in detectors:
        detectors[sid].reset_counter()

    return jsonify({
        'status': 'reset'
    })


if __name__ == '__main__':
    app.run(debug=True)