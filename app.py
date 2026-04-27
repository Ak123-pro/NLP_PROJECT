from flask import Flask, request, jsonify, session
from threat_detector import PrivacyPreservingThreatDetector
import hashlib

app = Flask(__name__)
app.secret_key = "secret_key"

detectors = {}

def get_session_id():
    if 'user_id' not in session:
        session['user_id'] = hashlib.md5(str(request.remote_addr).encode()).hexdigest()
    return session['user_id']

@app.route('/')
def index():
    return '''
    <h2>🛡️ Threat Detection System</h2>
    <input id="query" placeholder="Type query">
    <button onclick="analyze()">Analyze</button>
    <button onclick="reset()">Reset</button>
    <div id="out"></div>

    <script>
    async function analyze(){
        let q = document.getElementById("query").value;
        let res = await fetch('/analyze',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({query:q})
        });
        let d = await res.json();

        document.getElementById("out").innerHTML =
            `Alert: ${d.alert}<br>
             Risk: ${d.risk}<br>
             Score: ${d.reason.score}<br>
             Keywords: ${d.reason.keywords_detected}`;
    }

    async function reset(){
        await fetch('/reset',{method:'POST'});
        alert("Reset done");
    }
    </script>
    '''

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    query = data.get('query','').strip()

    sid = get_session_id()

    if sid not in detectors:
        detectors[sid] = PrivacyPreservingThreatDetector()

    detector = detectors[sid]

    if not query:
        return jsonify({'alert':False,'risk':'SAFE','reason':{'score':0}})

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
    return jsonify({'status':'reset'})

if __name__ == '__main__':
    app.run(debug=True)