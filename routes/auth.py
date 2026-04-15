from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from tinydb import Query
from datetime import datetime
import uuid
import random
import string

bp = Blueprint('auth', __name__)

def get_db():
    from app import users_table, logs_table
    return users_table, logs_table


def generate_user_id(users_table, field_name, prefix):
    existing_ids = [user.get(field_name) for user in users_table.all() if user.get(field_name)]
    max_number = 0
    for uid in existing_ids:
        if isinstance(uid, str) and uid.upper().startswith(prefix):
            try:
                current = int(uid[len(prefix):])
                max_number = max(max_number, current)
            except ValueError:
                continue
    return f"{prefix}{max_number + 1:03d}"


def generate_employee_id(users_table):
    return generate_user_id(users_table, 'employee_id', 'EMP')


def generate_faculty_id(users_table):
    return generate_user_id(users_table, 'faculty_id', 'FAC')

def log_activity(user_id, user_type, action, details=""):
    _, logs_table = get_db()
    logs_table.insert({
        'id': str(uuid.uuid4()),
        'user_id': user_id,
        'user_type': user_type,
        'action': action,
        'details': details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@bp.route('/home')
def home():
    return render_template('home.html')


@bp.route('/generate-otp', methods=['POST'])
def generate_otp():
    email = request.json.get('email')
    if not email:
        return {"success": False, "message": "Email is required"}, 400
    
    users_table, _ = get_db()
    User = Query()
    if users_table.search(User.email == email):
        return {"success": False, "message": "Already registered with this mail, try with another mail"}, 400
    
    otp = ''.join(random.choices(string.digits, k=6))
    session['registration_otp'] = otp
    # Return the OTP so the frontend can send it via EmailJS
    return {"success": True, "otp": otp}


@bp.route('/ea/signup', methods=['GET', 'POST'])
def ea_signup():
    if request.method == 'POST':
        users_table, _ = get_db()
        User = Query()
        
        email = request.form.get('email')
        employee_id = generate_employee_id(users_table)
        while users_table.search(User.employee_id == employee_id):
            employee_id = generate_employee_id(users_table)
        
        if not email.lower().endswith('@gmail.com'):
            flash('Only Gmail addresses (@gmail.com) are allowed for registration!', 'error')
            return redirect(url_for('auth.ea_signup'))
            
        if users_table.search(User.email == email):
            flash('Email already exists!', 'error')
            return redirect(url_for('auth.ea_signup'))
        
        otp_input = request.form.get('otp')
        stored_otp = session.get('registration_otp')
        
        if not otp_input or str(otp_input) != str(stored_otp):
            flash('Invalid OTP! Please try again.', 'error')
            return redirect(url_for('auth.ea_signup'))

        user_data = {
            'id': str(uuid.uuid4()),
            'full_name': request.form.get('full_name'),
            'email': email,
            'employee_id': employee_id,
            'department': request.form.get('department'),
            'designation': request.form.get('designation'),
            'contact_number': request.form.get('contact_number'),
            'office_location': request.form.get('office_location'),
            'password_hash': generate_password_hash(request.form.get('password')),
            'user_type': 'EA',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': True
        }
        
        users_table.insert(user_data)
        session.pop('registration_otp', None)
        log_activity(user_data['id'], 'EA', 'SIGNUP', f"New EA registered: {email}")
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.ea_login'))
    
    users_table, _ = get_db()
    employee_id = generate_employee_id(users_table)
    return render_template('ea_signup.html', employee_id=employee_id)


@bp.route('/ea/login', methods=['GET', 'POST'])
def ea_login():
    if request.method == 'POST':
        users_table, _ = get_db()
        User = Query()
        
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_table.search((User.email == email) & (User.user_type == 'EA'))
        
        if user and check_password_hash(user[0]['password_hash'], password):
            session['user_id'] = user[0]['id']
            session['user_type'] = 'EA'
            session['user_name'] = user[0]['full_name']
            session['user_email'] = user[0]['email']
            log_activity(user[0]['id'], 'EA', 'LOGIN', f"EA logged in: {email}")
            return redirect(url_for('ea.dashboard'))
        
        flash('Invalid email or password!', 'error')
    
    return render_template('ea_login.html')


@bp.route('/aef/signup', methods=['GET', 'POST'])
def aef_signup():
    if request.method == 'POST':
        users_table, _ = get_db()
        User = Query()
        
        email = request.form.get('email')
        faculty_id = generate_faculty_id(users_table)
        while users_table.search(User.faculty_id == faculty_id):
            faculty_id = generate_faculty_id(users_table)
        
        if not email.lower().endswith('@gmail.com'):
            flash('Only Gmail addresses (@gmail.com) are allowed for registration!', 'error')
            return redirect(url_for('auth.aef_signup'))

        if users_table.search(User.email == email):
            flash('Email already exists!', 'error')
            return redirect(url_for('auth.aef_signup'))
        
        otp_input = request.form.get('otp')
        stored_otp = session.get('registration_otp')
        
        if not otp_input or str(otp_input) != str(stored_otp):
            flash('Invalid OTP! Please try again.', 'error')
            return redirect(url_for('auth.aef_signup'))

        user_data = {
            'id': str(uuid.uuid4()),
            'full_name': request.form.get('full_name'),
            'email': email,
            'faculty_id': faculty_id,
            'department': request.form.get('department'),
            'subject_expertise': request.form.get('subject_expertise'),
            'qualification': request.form.get('qualification'),
            'contact_number': request.form.get('contact_number'),
            'experience_years': request.form.get('experience_years'),
            'password_hash': generate_password_hash(request.form.get('password')),
            'user_type': 'AEF',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': True,
            'is_authorized': False
        }
        
        users_table.insert(user_data)
        session.pop('registration_otp', None)
        log_activity(user_data['id'], 'AEF', 'SIGNUP', f"New AEF registered: {email}")
        flash('Registration successful! Please login. Note: You need authorization from an Administrator to access exam papers.', 'success')
        return redirect(url_for('auth.aef_login'))
    
    users_table, _ = get_db()
    faculty_id = generate_faculty_id(users_table)
    return render_template('aef_signup.html', faculty_id=faculty_id)


@bp.route('/aef/login', methods=['GET', 'POST'])
def aef_login():
    if request.method == 'POST':
        users_table, _ = get_db()
        User = Query()
        
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_table.search((User.email == email) & (User.user_type == 'AEF'))
        
        if user and check_password_hash(user[0]['password_hash'], password):
            session['user_id'] = user[0]['id']
            session['user_type'] = 'AEF'
            session['user_name'] = user[0]['full_name']
            session['user_email'] = user[0]['email']
            log_activity(user[0]['id'], 'AEF', 'LOGIN', f"AEF logged in: {email}")
            return redirect(url_for('aef.dashboard'))
        
        flash('Invalid email or password!', 'error')
    
    return render_template('aef_login.html')


@bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    if user_id:
        log_activity(user_id, user_type, 'LOGOUT', 'User logged out')
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('auth.home'))
