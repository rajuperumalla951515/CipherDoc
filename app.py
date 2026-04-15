import os
import logging
from flask import Flask 
from werkzeug.middleware.proxy_fix import ProxyFix
from tinydb import TinyDB, Query

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'secure-system-key-2024')
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

os.makedirs('data', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
os.makedirs('keys', exist_ok=True)

db = TinyDB('data/exam_db.json')
users_table = db.table('users')
papers_table = db.table('papers')
keys_table = db.table('keys')
authorizations_table = db.table('authorizations')
logs_table = db.table('access_logs')

from routes import auth, ea, aef
app.register_blueprint(auth.bp)
app.register_blueprint(ea.bp)
app.register_blueprint(aef.bp)

from flask import session
@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    if user_id:
        User = Query()
        user = users_table.search(User.id == user_id)
        if user:
            return dict(current_user=user[0])
    return dict(current_user=None)

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return {"success": False, "message": "Unauthorized"}, 401
    
    User = Query()
    user_id = session['user_id']
    user_type = session['user_type']
    
    update_data = {
        'full_name': request.form.get('full_name'),
        'email': request.form.get('email'),
        'department': request.form.get('department'),
        'contact_number': request.form.get('contact_number')
    }
    
    if user_type == 'EA':
        update_data.update({
            'designation': request.form.get('designation'),
            'office_location': request.form.get('office_location')
        })
    else:
        update_data.update({
            'subject_expertise': request.form.get('subject_expertise'),
            'qualification': request.form.get('qualification'),
            'experience_years': request.form.get('experience_years')
        })
    
    users_table.update(update_data, User.id == user_id)
    
    # Sync session
    session['user_name'] = update_data['full_name']
    session['user_email'] = update_data['email']
    
    return {"success": True, "message": "Profile updated successfully"}

from flask import redirect, url_for

@app.route('/')
def index():
    return redirect(url_for('auth.home'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

