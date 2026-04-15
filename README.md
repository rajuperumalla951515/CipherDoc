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

## Project Structure

```text
.
├── app.py              # Flask application entry point
├── encryption.py       # Encryption and decryption utilities
├── routes/             # Blueprints for auth, EA, and AEF flows
├── templates/          # Jinja2 HTML templates
├── static/             # Images and other static assets
├── data/               # Local JSON database files
├── keys/               # Generated keys and secrets storage
├── uploads/            # Uploaded or generated exam files
└── requirements.txt    # Python dependencies
```

## How The Project Is Organized

- `routes/` keeps the application split by feature area instead of placing all logic in one file.
- `templates/` holds the UI for login, dashboards, and paper workflows.
- `static/` stores images and supporting frontend assets.
- `data/`, `keys/`, and `uploads/` are runtime folders created by the application when needed.

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies:
   pip install -r requirements.txt
3. Run the app:
   python app.py
4. Open the application in your browser at:
   http://127.0.0.1:5000

## Note

This project is intended for educational and mini-project use. For production, use a secure database, hardened key management, and deployment-level security controls.
