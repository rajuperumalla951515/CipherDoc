from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file
from functools import wraps
from datetime import datetime
import uuid
import os
import tempfile
import re
from encryption import generate_rsa_key_pair, encrypt_file, encrypt_text, decrypt_text

bp = Blueprint('ea', __name__, url_prefix='/ea')

def ea_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_type') != 'EA':
            flash('Please login as Examination Administrator to access this page.', 'error')
            return redirect(url_for('auth.ea_login'))
        return f(*args, **kwargs)
    return decorated_function


def log_activity(user_id, action, details=""):
    from app import supabase
    supabase.table('access_logs').insert({
        'id': str(uuid.uuid4()),
        'user_id': user_id,
        'user_type': 'EA',
        'action': action,
        'details': details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }).execute()


def has_visible_content(value):
    if not value:
        return False
    text = re.sub(r'<[^>]+>', '', value)
    text = text.replace('&nbsp;', ' ').strip()
    return bool(text)


@bp.route('/dashboard')
@ea_required
def dashboard():
    from app import supabase
    
    total_papers = len(supabase.table('papers').select('id').execute().data)
    total_faculty = len(supabase.table('users').select('id').eq('user_type', 'AEF').execute().data)
    authorized_faculty = len(supabase.table('users').select('id').eq('user_type', 'AEF').eq('is_authorized', True).execute().data)
    total_keys = len(supabase.table('keys').select('id').execute().data)
    recent_logs = supabase.table('access_logs').select('*').order('timestamp', desc=True).limit(5).execute().data
    
    stats = {
        'total_papers': total_papers,
        'total_faculty': total_faculty,
        'authorized_faculty': authorized_faculty,
        'total_keys': total_keys,
        'recent_logs': recent_logs
    }
    
    return render_template('ea/dashboard.html', stats=stats)


@bp.route('/create-paper', methods=['GET', 'POST'])
@ea_required
def create_paper():
    from app import supabase
    
    if request.method == 'POST':
        keys = supabase.table('keys').select('*').execute().data
        if not keys:
            flash('Please generate RSA keys first before creating encrypted papers!', 'error')
            return redirect(url_for('ea.manage_keys'))
        
        active_key = supabase.table('keys').select('*').eq('is_active', True).execute().data
        if not active_key:
            flash('No active RSA key found. Please generate or activate a key.', 'error')
            return redirect(url_for('ea.manage_keys'))
        
        public_key = active_key[0]['public_key']
        
        exam_name = request.form.get('exam_name')
        subject = request.form.get('subject')
        exam_date = request.form.get('exam_date')
        exam_duration = request.form.get('exam_duration')
        total_marks = request.form.get('total_marks')
        instructions = request.form.get('instructions')
        questions = request.form.get('questions')

        if not has_visible_content(instructions) or not has_visible_content(questions):
            flash('Instructions and Questions are required to create a paper.', 'error')
            return redirect(url_for('ea.create_paper'))
        
        encrypted_questions, encrypted_key = encrypt_text(questions, public_key)
        encrypted_instructions, instr_key = encrypt_text(instructions, public_key)
        
        paper_data = {
            'id': str(uuid.uuid4()),
            'exam_name': exam_name,
            'subject': subject,
            'exam_date': exam_date,
            'exam_duration': exam_duration,
            'total_marks': total_marks,
            'encrypted_questions': encrypted_questions,
            'encrypted_key': encrypted_key,
            'encrypted_instructions': encrypted_instructions,
            'instructions_key': instr_key,
            'key_id': active_key[0]['id'],
            'created_by': session['user_id'],
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'encrypted',
            'is_active': True
        }
        
        supabase.table('papers').insert(paper_data).execute()
        log_activity(session['user_id'], 'CREATE_PAPER', f"Created encrypted paper: {exam_name}")
        flash('Question paper created and encrypted successfully!', 'success')
        return redirect(url_for('ea.manage_papers'))
    
    return render_template('ea/create_paper.html')


@bp.route('/manage-papers')
@ea_required
def manage_papers():
    from app import supabase
    papers = supabase.table('papers').select('*').execute().data
    return render_template('ea/manage_papers.html', papers=papers)


@bp.route('/edit-paper/<paper_id>', methods=['GET', 'POST'])
@ea_required
def edit_paper(paper_id):
    from app import supabase
    
    paper_data = supabase.table('papers').select('*').eq('id', paper_id).execute().data
    if not paper_data:
        flash('Paper not found!', 'error')
        return redirect(url_for('ea.manage_papers'))
    
    paper = paper_data[0]
    
    if request.method == 'POST':
        active_key = supabase.table('keys').select('*').eq('is_active', True).execute().data
        if not active_key:
            flash('No active RSA key found.', 'error')
            return redirect(url_for('ea.manage_keys'))
        
        public_key = active_key[0]['public_key']
        questions = request.form.get('questions')
        instructions = request.form.get('instructions')

        if not has_visible_content(instructions) or not has_visible_content(questions):
            flash('Instructions and Questions are required to update a paper.', 'error')
            return redirect(url_for('ea.edit_paper', paper_id=paper_id))
        
        encrypted_questions, encrypted_key = encrypt_text(questions, public_key)
        encrypted_instructions, instr_key = encrypt_text(instructions, public_key)
        
        supabase.table('papers').update({
            'exam_name': request.form.get('exam_name'),
            'subject': request.form.get('subject'),
            'exam_date': request.form.get('exam_date'),
            'exam_duration': request.form.get('exam_duration'),
            'total_marks': request.form.get('total_marks'),
            'encrypted_questions': encrypted_questions,
            'encrypted_key': encrypted_key,
            'encrypted_instructions': encrypted_instructions,
            'instructions_key': instr_key,
            'key_id': active_key[0]['id'],
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }).eq('id', paper_id).execute()
        
        log_activity(session['user_id'], 'EDIT_PAPER', f"Edited paper: {request.form.get('exam_name')}")
        flash('Paper updated successfully!', 'success')
        return redirect(url_for('ea.manage_papers'))
    
    return render_template('ea/edit_paper.html', paper=paper)


@bp.route('/delete-paper/<paper_id>')
@ea_required
def delete_paper(paper_id):
    from app import supabase
    
    paper = supabase.table('papers').select('*').eq('id', paper_id).execute().data
    if paper:
        supabase.table('papers').delete().eq('id', paper_id).execute()
        supabase.table('authorizations').delete().eq('paper_id', paper_id).execute()
        log_activity(session['user_id'], 'DELETE_PAPER', f"Deleted paper: {paper[0]['exam_name']}")
        flash('Paper deleted successfully!', 'success')
    
    return redirect(url_for('ea.manage_papers'))


@bp.route('/manage-keys', methods=['GET', 'POST'])
@ea_required
def manage_keys():
    from app import supabase
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate':
            key_name = request.form.get('key_name')
            private_key, public_key = generate_rsa_key_pair()
            
            supabase.table('keys').update({'is_active': False}).eq('is_active', True).execute()
            
            key_data = {
                'id': str(uuid.uuid4()),
                'key_name': key_name,
                'private_key': private_key,
                'public_key': public_key,
                'created_by': session['user_id'],
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'is_active': True
            }
            
            supabase.table('keys').insert(key_data).execute()
            log_activity(session['user_id'], 'GENERATE_KEY', f"Generated new RSA key pair: {key_name}")
            flash('New RSA key pair generated successfully!', 'success')
        
        elif action == 'activate':
            key_id = request.form.get('key_id')
            supabase.table('keys').update({'is_active': False}).eq('is_active', True).execute()
            supabase.table('keys').update({'is_active': True}).eq('id', key_id).execute()
            log_activity(session['user_id'], 'ACTIVATE_KEY', f"Activated key: {key_id}")
            flash('Key activated successfully!', 'success')
        
        elif action == 'delete':
            key_id = request.form.get('key_id')
            key = supabase.table('keys').select('*').eq('id', key_id).execute().data
            if key and not key[0]['is_active']:
                supabase.table('keys').delete().eq('id', key_id).execute()
                log_activity(session['user_id'], 'DELETE_KEY', f"Deleted key: {key_id}")
                flash('Key deleted successfully!', 'success')
            else:
                flash('Cannot delete active key!', 'error')
        
        return redirect(url_for('ea.manage_keys'))
    
    keys = supabase.table('keys').select('*').execute().data
    return render_template('ea/manage_keys.html', keys=keys)


@bp.route('/download-key/<key_id>/<key_type>')
@ea_required
def download_key(key_id, key_type):
    from app import supabase
    
    key_data = supabase.table('keys').select('*').eq('id', key_id).execute().data
    if not key_data:
        flash('Key not found!', 'error')
        return redirect(url_for('ea.manage_keys'))
    
    key = key_data[0]
    
    if key_type == 'private':
        content = key['private_key']
        filename = f"{key['key_name']}_private.pem"
    else:
        content = key['public_key']
        filename = f"{key['key_name']}_public.pem"
    
    temp_path = os.path.join(tempfile.gettempdir(), filename)
    with open(temp_path, 'w') as f:
        f.write(content)
    
    log_activity(session['user_id'], 'DOWNLOAD_KEY', f"Downloaded {key_type} key: {key['key_name']}")
    return send_file(temp_path, as_attachment=True, download_name=filename)


@bp.route('/authorize-faculty', methods=['GET', 'POST'])
@ea_required
def authorize_faculty():
    from app import supabase
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'authorize':
            faculty_id = request.form.get('faculty_id')
            paper_ids = request.form.getlist('paper_ids')
            
            faculty = supabase.table('users').select('*').eq('id', faculty_id).execute().data
            if faculty:
                supabase.table('users').update({'is_authorized': True}).eq('id', faculty_id).execute()
                
                supabase.table('authorizations').delete().eq('faculty_id', faculty_id).execute()
                
                auth_records = []
                for paper_id in paper_ids:
                    auth_records.append({
                        'id': str(uuid.uuid4()),
                        'faculty_id': faculty_id,
                        'paper_id': paper_id,
                        'authorized_by': session['user_id'],
                        'authorized_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'is_active': True
                    })
                if auth_records:
                    supabase.table('authorizations').insert(auth_records).execute()
                
                log_activity(session['user_id'], 'AUTHORIZE_FACULTY', 
                           f"Authorized faculty {faculty[0]['full_name']} for {len(paper_ids)} papers")
                flash(f"Faculty {faculty[0]['full_name']} authorized successfully for {len(paper_ids)} exam papers!", 'success')
        
        elif action == 'revoke':
            faculty_id = request.form.get('faculty_id')
            faculty = supabase.table('users').select('*').eq('id', faculty_id).execute().data
            if faculty:
                supabase.table('users').update({'is_authorized': False}).eq('id', faculty_id).execute()
                supabase.table('authorizations').delete().eq('faculty_id', faculty_id).execute()
                log_activity(session['user_id'], 'REVOKE_AUTHORIZATION', 
                           f"Revoked authorization for faculty {faculty[0]['full_name']}")
                flash(f"Authorization revoked for {faculty[0]['full_name']}!", 'success')
        
        return redirect(url_for('ea.authorize_faculty'))
    
    faculty_list = supabase.table('users').select('*').eq('user_type', 'AEF').execute().data
    papers = supabase.table('papers').select('*').execute().data
    
    faculty_with_auth = []
    for faculty in faculty_list:
        auth = supabase.table('authorizations').select('paper_id').eq('faculty_id', faculty['id']).execute().data
        authorized_papers = [a['paper_id'] for a in auth]
        faculty['authorized_papers'] = authorized_papers
        faculty_with_auth.append(faculty)
    
    return render_template('ea/authorize_faculty.html', faculty_list=faculty_with_auth, papers=papers)


@bp.route('/access-logs')
@ea_required
def access_logs():
    from app import supabase
    
    logs = supabase.table('access_logs').select('*').order('timestamp', desc=True).execute().data
    users = supabase.table('users').select('id, full_name').execute().data
    
    user_map = {}
    for user in users:
        user_map[user['id']] = user['full_name']
    
    for log in logs:
        log['user_name'] = user_map.get(log['user_id'], 'Unknown User')
    
    return render_template('ea/access_logs.html', logs=logs)


@bp.route('/view-paper/<paper_id>')
@ea_required
def view_paper(paper_id):
    from app import supabase

    paper_data = supabase.table('papers').select('*').eq('id', paper_id).execute().data
    if not paper_data:
        flash('Paper not found!', 'error')
        return redirect(url_for('ea.manage_papers'))
    
    paper = paper_data[0]
    
    # Find the key used for this paper
    paper_key = supabase.table('keys').select('*').eq('id', paper['key_id']).execute().data
    if not paper_key:
        flash('Encryption key for this paper not found!', 'error')
        return redirect(url_for('ea.manage_papers'))
        
    private_key = paper_key[0]['private_key']
    
    try:
        decrypted_questions = decrypt_text(paper['encrypted_questions'], paper['encrypted_key'], private_key)
        decrypted_instructions = decrypt_text(paper['encrypted_instructions'], paper['instructions_key'], private_key)
    except Exception as e:
        flash(f'Failed to decrypt paper. The key may be incorrect or the data corrupted. Error: {e}', 'error')
        decrypted_questions = "Decryption Failed."
        decrypted_instructions = "Decryption Failed."

    paper['decrypted_questions'] = decrypted_questions
    paper['decrypted_instructions'] = decrypted_instructions
    
    log_activity(session['user_id'], 'VIEW_PAPER', f"Viewed paper: {paper['exam_name']}")
    
    return render_template('ea/view_paper.html', paper=paper)
