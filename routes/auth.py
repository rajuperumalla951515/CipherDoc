from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import random
import string

bp = Blueprint('auth', __name__)

def generate_user_id(field_name, prefix):
    from app import supabase
    response = supabase.table('users').select('*').execute()
    existing_ids = [user.get(field_name) for user in response.data if user.get(field_name)]
    max_number = 0
    for uid in existing_ids:
        if isinstance(uid, str) and uid.upper().startswith(prefix):
            try:
                current = int(uid[len(prefix):])
                max_number = max(max_number, current)
            except ValueError:
                continue
    return f"{prefix}{max_number + 1:03d}"


def generate_employee_id():
    return generate_user_id('employee_id', 'EMP')


def generate_faculty_id():
    return generate_user_id('faculty_id', 'FAC')

def log_activity(user_id, user_type, action, details=""):
    from app import supabase
    supabase.table('access_logs').insert({
        'id': str(uuid.uuid4()),
        'user_id': user_id,
        'user_type': user_type,
        'action': action,
        'details': details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }).execute()


@bp.route('/home')
def home():
    return render_template('home.html')


@bp.route('/generate-otp', methods=['POST'])
def generate_otp():
    from app import supabase
    email = request.json.get('email')
    if not email:
        return {"success": False, "message": "Email is required"}, 400
    
    response = supabase.table('users').select('*').eq('email', email).execute()
    if response.data:
        return {"success": False, "message": "Already registered with this mail, try with another mail"}, 400
    
    otp = ''.join(random.choices(string.digits, k=6))
    session['registration_otp'] = otp
    # Return the OTP so the frontend can send it via EmailJS
    return {"success": True, "otp": otp}


@bp.route('/ea/signup', methods=['GET', 'POST'])
def ea_signup():
    from app import supabase
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        employee_id = generate_employee_id()
        while supabase.table('users').select('*').eq('employee_id', employee_id).execute().data:
            employee_id = generate_employee_id()
        
        if not email.endswith('@gmail.com'):
            flash('Only Gmail addresses (@gmail.com) are allowed for registration!', 'error')
            return redirect(url_for('auth.ea_signup'))
            
        if supabase.table('users').select('*').ilike('email', email).execute().data:
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
        
        supabase.table('users').insert(user_data).execute()
        session.pop('registration_otp', None)
        log_activity(user_data['id'], 'EA', 'SIGNUP', f"New EA registered: {email}")
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.ea_login'))
    
    employee_id = generate_employee_id()
    return render_template('ea_signup.html', employee_id=employee_id)


@bp.route('/ea/login', methods=['GET', 'POST'])
def ea_login():
    from app import supabase
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        
        response = supabase.table('users').select('*').ilike('email', email).eq('user_type', 'EA').execute()
        user = response.data
        
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
    from app import supabase
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        faculty_id = generate_faculty_id()
        while supabase.table('users').select('*').eq('faculty_id', faculty_id).execute().data:
            faculty_id = generate_faculty_id()
        
        if not email.endswith('@gmail.com'):
            flash('Only Gmail addresses (@gmail.com) are allowed for registration!', 'error')
            return redirect(url_for('auth.aef_signup'))

        if supabase.table('users').select('*').ilike('email', email).execute().data:
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
        
        supabase.table('users').insert(user_data).execute()
        session.pop('registration_otp', None)
        log_activity(user_data['id'], 'AEF', 'SIGNUP', f"New AEF registered: {email}")
        flash('Registration successful! Please login. Note: You need authorization from an Administrator to access exam papers.', 'success')
        return redirect(url_for('auth.aef_login'))
    
    faculty_id = generate_faculty_id()
    return render_template('aef_signup.html', faculty_id=faculty_id)


@bp.route('/aef/login', methods=['GET', 'POST'])
def aef_login():
    from app import supabase
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        
        response = supabase.table('users').select('*').ilike('email', email).eq('user_type', 'AEF').execute()
        user = response.data
        
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


@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    from app import supabase
    if request.method == 'POST':
        email = request.form.get('email')
        response = supabase.table('users').select('*').eq('email', email).execute()
        user = response.data

        if user:
            otp = ''.join(random.choices(string.digits, k=6))
            session['reset_otp'] = otp
            session['reset_email'] = email
            
            # In a real app, you'd email this OTP.
            # For this project, we'll flash it for demonstration.
            flash('An OTP has been sent to your email.', 'info')
            return redirect(url_for('auth.reset_with_otp'))
        else:
            flash('Email address not found.', 'error')
    
    return render_template('forgot_password.html')

@bp.route('/reset-with-otp', methods=['GET', 'POST'])
def reset_with_otp():
    from app import supabase
    if 'reset_email' not in session:
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        
        if otp == session.get('reset_otp'):
            supabase.table('users').update(
                {'password_hash': generate_password_hash(new_password)}
            ).eq('email', session['reset_email']).execute()
            
            response = supabase.table('users').select('*').eq('email', session['reset_email']).execute()
            user_id = response.data[0]['id'] if response.data else 'Unknown'
            
            log_activity(user_id, 'USER', 'PASSWORD_RESET', f"Password reset for {session['reset_email']}")

            session.pop('reset_otp', None)
            session.pop('reset_email', None)
            
            flash('Your password has been reset successfully. Please login.', 'success')
            # Redirect to home or a generic login page, as we don't know if they are EA or AEF
            return redirect(url_for('auth.home'))
        else:
            flash('Invalid OTP.', 'error')
            
    return render_template('reset_with_otp.html')
