from flask import Flask, render_template, request, jsonify
import os
import re
import json
import hashlib
from datetime import datetime
from analyzer import PhishingAnalyzer

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

os.makedirs('uploads', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    result = {}
    
    # Handle email text paste
    if 'email_text' in request.form and request.form['email_text'].strip():
        email_content = request.form['email_text']
        analyzer = PhishingAnalyzer(email_content)
        result = analyzer.analyze()
        return jsonify(result)
    
    # Handle file upload
    if 'email_file' in request.files:
        file = request.files['email_file']
        if file.filename != '':
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()
            analyzer = PhishingAnalyzer(email_content)
            result = analyzer.analyze()
            return jsonify(result)
    
    return jsonify({'error': 'No email content provided'}), 400

if __name__ == '__main__':
    app.run(debug=False, port=5001)
