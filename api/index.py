from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/hello')
def hello():
    return jsonify({"message": "Hello from Flask backend!"})
    
def handler(environ, start_response):
    return app(environ, start_response)
