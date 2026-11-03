from flask import Flask, render_template, request, jsonify
from core.scanner import run_port_scan
from ai_engine.engine import parse_prompt_with_ai, generate_ai_report

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def handle_scan():
    data = request.get_json()
    user_prompt = data.get('prompt', '')

    if not user_prompt:
        return jsonify({"error": "Empty prompt query context string configuration."}), 400

    # Step 1: Query the AI engine to translate prompt into target JSON fields
    target_config = parse_prompt_with_ai(user_prompt)
    
    target = target_config.get("target")
    start_p = target_config.get("start_port", 1)
    end_p = target_config.get("end_port", 1024)

    if not target:
        return jsonify({"error": "Could not identify a target host name context from input."}), 400

    # Step 2: Fire off python concurrent network sockets sweep
    scan_results = run_port_scan(target, start_p, end_p)

    # Step 3: Send findings back into LLM context windows to synthesize report
    ai_report = generate_ai_report(scan_results)

    return jsonify({
        "target_config": target_config,
        "scan_results": scan_results,
        "ai_report": ai_report
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)