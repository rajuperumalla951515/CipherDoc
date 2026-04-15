from flask import Blueprint, render_template, request, redirect, url_for, session, flash, make_response
from functools import wraps
from tinydb import Query 
from datetime import datetime
import uuid
from encryption import decrypt_text

bp = Blueprint('aef', __name__, url_prefix='/aef')

def get_db():
    from app import users_table, papers_table, keys_table, authorizations_table, logs_table
    return users_table, papers_table, keys_table, authorizations_table, logs_table


def aef_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'AEF':
            flash('Please login as Authorized Examination Faculty to access this page.', 'error')
            return redirect(url_for('auth.aef_login'))
        return f(*args, **kwargs)
    return decorated_function


def log_activity(user_id, action, details=""):
    _, _, _, _, logs_table = get_db()
    logs_table.insert({
        'id': str(uuid.uuid4()),
        'user_id': user_id,
        'user_type': 'AEF',
        'action': action,
        'details': details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@bp.route('/dashboard')
@aef_required
def dashboard():
    users_table, papers_table, _, authorizations_table, _ = get_db()
    User = Query()
    Auth = Query()
    
    user = users_table.search(User.id == session['user_id'])
    is_authorized = user[0]['is_authorized'] if user else False
    
    authorized_papers = []
    if is_authorized:
        auth_records = authorizations_table.search(Auth.faculty_id == session['user_id'])
        paper_ids = [a['paper_id'] for a in auth_records]
        
        Paper = Query()
        for paper_id in paper_ids:
            paper = papers_table.search(Paper.id == paper_id)
            if paper:
                authorized_papers.append(paper[0])
    
    stats = {
        'is_authorized': is_authorized,
        'total_authorized': len(authorized_papers),
        'papers': authorized_papers
    }
    
    return render_template('aef/dashboard.html', stats=stats)


@bp.route('/view-exams')
@aef_required
def view_exams():
    users_table, papers_table, _, authorizations_table, _ = get_db()
    User = Query()
    Auth = Query()
    Paper = Query()
    
    user = users_table.search(User.id == session['user_id'])
    if not user or not user[0]['is_authorized']:
        flash('You are not authorized to view exam papers. Please contact an administrator.', 'error')
        return redirect(url_for('aef.dashboard'))
    
    auth_records = authorizations_table.search(Auth.faculty_id == session['user_id'])
    paper_ids = [a['paper_id'] for a in auth_records]
    
    authorized_papers = []
    for paper_id in paper_ids:
        paper = papers_table.search(Paper.id == paper_id)
        if paper:
            authorized_papers.append(paper[0])
    
    log_activity(session['user_id'], 'VIEW_EXAMS', f"Viewed {len(authorized_papers)} authorized exams")
    return render_template('aef/view_exams.html', papers=authorized_papers)


@bp.route('/decrypt-paper/<paper_id>', methods=['GET', 'POST'])
@aef_required
def decrypt_paper(paper_id):
    users_table, papers_table, keys_table, authorizations_table, _ = get_db()
    User = Query()
    Auth = Query()
    Paper = Query()
    Key = Query()
    
    user = users_table.search(User.id == session['user_id'])
    if not user or not user[0]['is_authorized']:
        flash('You are not authorized to decrypt exam papers.', 'error')
        return redirect(url_for('aef.dashboard'))
    
    auth = authorizations_table.search((Auth.faculty_id == session['user_id']) & (Auth.paper_id == paper_id))
    if not auth:
        flash('You are not authorized to access this exam paper.', 'error')
        return redirect(url_for('aef.view_exams'))
    
    paper = papers_table.search(Paper.id == paper_id)
    if not paper:
        flash('Exam paper not found!', 'error')
        return redirect(url_for('aef.view_exams'))
    
    paper = paper[0]
    decrypted_data = None
    
    if request.method == 'POST':
        key = keys_table.search(Key.id == paper['key_id'])
        if not key:
            flash('Encryption key not found! Contact administrator.', 'error')
            return redirect(url_for('aef.view_exams'))
        
        private_key = key[0]['private_key']
        
        try:
            decrypted_questions = decrypt_text(
                paper['encrypted_questions'],
                paper['encrypted_key'],
                private_key
            )
            decrypted_instructions = decrypt_text(
                paper['encrypted_instructions'],
                paper['instructions_key'],
                private_key
            )
            
            decrypted_data = {
                'questions': decrypted_questions,
                'instructions': decrypted_instructions
            }
            
            session[f'decrypted_{paper_id}'] = decrypted_data
            
            log_activity(session['user_id'], 'DECRYPT_PAPER', 
                        f"Decrypted paper: {paper['exam_name']}")
            flash('Paper decrypted successfully!', 'success')
            
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
            log_activity(session['user_id'], 'DECRYPT_FAILED', 
                        f"Failed to decrypt: {paper['exam_name']} - {str(e)}")
    
    else:
        decrypted_data = session.get(f'decrypted_{paper_id}')
    
    return render_template('aef/decrypt_paper.html', paper=paper, decrypted_data=decrypted_data)


@bp.route('/download-paper/<paper_id>')
@aef_required
def download_paper(paper_id):
    users_table, papers_table, keys_table, authorizations_table, _ = get_db()
    User = Query()
    Auth = Query()
    Paper = Query()
    Key = Query()
    
    user = users_table.search(User.id == session['user_id'])
    if not user or not user[0]['is_authorized']:
        flash('You are not authorized to download exam papers.', 'error')
        return redirect(url_for('aef.dashboard'))
    
    auth = authorizations_table.search((Auth.faculty_id == session['user_id']) & (Auth.paper_id == paper_id))
    if not auth:
        flash('You are not authorized to access this exam paper.', 'error')
        return redirect(url_for('aef.view_exams'))
    
    paper = papers_table.search(Paper.id == paper_id)
    if not paper:
        flash('Exam paper not found!', 'error')
        return redirect(url_for('aef.view_exams'))
    
    paper = paper[0]
    
    decrypted_data = session.get(f'decrypted_{paper_id}')
    if not decrypted_data:
        key = keys_table.search(Key.id == paper['key_id'])
        if not key:
            flash('Encryption key not found!', 'error')
            return redirect(url_for('aef.view_exams'))
        
        private_key = key[0]['private_key']
        
        try:
            decrypted_questions = decrypt_text(
                paper['encrypted_questions'],
                paper['encrypted_key'],
                private_key
            )
            decrypted_instructions = decrypt_text(
                paper['encrypted_instructions'],
                paper['instructions_key'],
                private_key
            )
            decrypted_data = {
                'questions': decrypted_questions,
                'instructions': decrypted_instructions
            }
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
            return redirect(url_for('aef.view_exams'))
    
    content = f"""
================================================================================
                        EXAMINATION QUESTION PAPER
================================================================================

Exam Name: {paper['exam_name']}
Subject: {paper['subject']}
Date: {paper['exam_date']}
Duration: {paper['exam_duration']} minutes
Total Marks: {paper['total_marks']}

================================================================================
                              INSTRUCTIONS
================================================================================

{decrypted_data['instructions']}

================================================================================
                               QUESTIONS
================================================================================

{decrypted_data['questions']}

================================================================================
                           END OF QUESTION PAPER
================================================================================

Downloaded by: {session['user_name']}
Downloaded at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    log_activity(session['user_id'], 'DOWNLOAD_PAPER', f"Downloaded paper: {paper['exam_name']}")
    
    response = make_response(content)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = f'attachment; filename={paper["exam_name"].replace(" ", "_")}_question_paper.txt'
    
    return response
