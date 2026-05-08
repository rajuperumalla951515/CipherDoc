import sys
import os
import traceback

# Ensure the root directory is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
except Exception as e:
    error_trace = traceback.format_exc()
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def catch_all(path):
        html = f"""
        <html>
            <body style="font-family: monospace; padding: 20px;">
                <h1 style="color: red;">Vercel Deployment Crash (500 Error)</h1>
                <p>The application failed to start. Here is the exact Python error:</p>
                <div style="background: #1e1e1e; color: #00ff00; padding: 15px; border-radius: 5px; overflow-x: auto;">
                    <pre>{error_trace}</pre>
                </div>
            </body>
        </html>
        """
        return html, 500
