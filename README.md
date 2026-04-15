# CipherDoc

Encrypted Online Question Paper is a Flask-based web application for secure creation, management, and controlled decryption of exam papers.

## Key Features

- Role-based access for Exam Authority (EA) and Authorized Exam Faculty (AEF)
- Encrypted storage and controlled decryption of question papers
- Faculty authorization workflow and access logging
- Exam paper creation, editing, and viewing dashboards

## Tech Stack

- Python
- Flask
- HTML, CSS, Jinja2 templates
- JSON-based local data storage

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies:
   pip install -r requirements.txt
3. Run the app:
   python app.py
4. Open the application in your browser at:
   http://127.0.0.1:5000

## Project Structure

- app.py: Application entry point
- routes/: Route modules for EA, AEF, and authentication
- templates/: Frontend templates
- static/: Static assets
- encryption.py: Encryption/decryption utilities
- data/: JSON data storage

## Note

This project is intended for educational and mini-project use. For production, use a secure database, hardened key management, and deployment-level security controls.
