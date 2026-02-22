import os
import time
import sqlite3
import json
import requests
import google.oauth2.id_token
# Allow HTTP for local development only (prevents "(insecure_transport) OAuth 2 MUST utilize https." error)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as grequests
from flask import jsonify
from flask_mail import Mail, Message
from matcher import FaceMatcher
import random
import string
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = '123456'

# Email Configuration for OTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')  # Set via environment variable
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')  # Set via environment variable
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')

mail = Mail(app)

# Initialize FaceMatcher (Global singleton)
# Try to use GPU if available
matcher = FaceMatcher(device_choice='gpu')

# Database paths
THIRDUSER_DB = 'thirduser.db'

# Helper function to generate device ID
def generate_device_id(request):
    """Generate a unique device ID based on user agent and IP address"""
    import hashlib
    user_agent = request.headers.get('User-Agent', '')
    ip_address = request.remote_addr
    device_string = f"{user_agent}_{ip_address}"
    return hashlib.sha256(device_string.encode()).hexdigest()

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')
CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), 'client_secrets.json')
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

# --- Configuration for File Uploads ---
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Automatically create the uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    """Checks if a file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Create DB and tables if missing."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ensure DB exists
init_db()

# --- Google OAuth routes ---
@app.route('/login/google')
def login_google():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return ("Google OAuth not configured. Place client_secrets.json in project root."), 500
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # only for local dev
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    # handle provider returning an error (user pressed Cancel)
    err = request.args.get('error')
    if err:
        session.pop('oauth_state', None)
        return redirect(url_for('home' if 'home' in app.view_functions else 'login'))

    state = session.get('oauth_state')
    if not state:
        return redirect(url_for('login'))

    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # get client_id
        client_id = None
        cfg = getattr(flow, 'client_config', None) or {}
        if isinstance(cfg, dict):
            client_id = cfg.get('web', {}).get('client_id') or cfg.get('installed', {}).get('client_id')
        if not client_id:
            with open(CLIENT_SECRETS_FILE, 'r') as f:
                data = json.load(f)
            client_id = data.get('web', {}).get('client_id') or data.get('installed', {}).get('client_id') or data.get('client_id')

        if not client_id:
            return "OAuth client_id not found in client_secrets.json", 500

        # prefer id_token, otherwise use userinfo endpoint
        id_token = getattr(credentials, 'id_token', None) or getattr(credentials, '_id_token', None)
        userinfo = None
        if id_token:
            request_session = grequests.Request()
            id_info = google.oauth2.id_token.verify_oauth2_token(id_token, request_session, audience=client_id)
            userinfo = id_info
        else:
            access_token = getattr(credentials, 'token', None)
            if not access_token:
                return "No id_token or access token returned by Google.", 500
            r = requests.get('https://openidconnect.googleapis.com/v1/userinfo',
                             headers={'Authorization': f'Bearer {access_token}'})
            if r.status_code != 200:
                return f"Failed to fetch user info: {r.status_code}", 500
            userinfo = r.json()

        email = userinfo.get('email')
        first_name = userinfo.get('given_name', '') or userinfo.get('name', '').split(' ')[0:1]
        last_name = userinfo.get('family_name', '') or ''

        # upsert user
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, first_name FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if not user:
            base_username = (email.split('@')[0] if email else 'user')
            username = base_username
            i = 1
            while True:
                try:
                    cur.execute('INSERT INTO users (first_name, last_name, username, email, password) VALUES (?, ?, ?, ?, ?)',
                                (first_name, last_name, username, email, ''))
                    conn.commit()
                    user_id = cur.lastrowid
                    break
                except sqlite3.IntegrityError:
                    username = f"{base_username}{i}"
                    i += 1
        else:
            user_id = user[0]
            first_name = user[1] or first_name
        conn.close()

        session['user_id'] = user_id
        session['first_name'] = first_name
        return redirect(url_for('dashboard' if 'dashboard' in app.view_functions else 'home'))

    except Exception as e:
        msg = str(e).lower()
        if 'access_denied' in msg or 'access denied' in msg:
            session.pop('oauth_state', None)
            return redirect(url_for('home' if 'home' in app.view_functions else 'login'))
        app.logger.error('OAuth callback error: %s', e)
        return f"OAuth error: {e}", 500

# --- Main Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT first_name, last_name, username FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    user_first_name = user_data[0]
    user_last_name = user_data[1]
    username = user_data[2]
    cursor.execute('SELECT id, event_name, event_date, cover_photo FROM events WHERE user_id = ?', (user_id,))
    events = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', user_first_name=user_first_name, user_last_name=user_last_name, username=username, events=events)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE (username = ? OR email = ?) AND password = ?', 
                       (username_or_email, username_or_email, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['first_name'] = user[1] 
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password. Please try again.'
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (first_name, last_name, username, email, password) VALUES (?, ?, ?, ?, ?)', 
                       (first_name, last_name, username, email, password))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        session['user_id'] = user_id
        session['first_name'] = first_name
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

# --- Event Creation Routes ---
@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        event_name = request.form['event_name']
        
        # Handle cover photo upload
        cover_photo_filename = None
        if 'cover_photo' in request.files:
            file = request.files['cover_photo']
            if file and file.filename != '' and allowed_file(file.filename):
                # Create event-specific folder
                event_folder = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(event_name))
                os.makedirs(event_folder, exist_ok=True)
                
                filename = secure_filename(file.filename)
                # Add timestamp to make filename unique
                import uuid
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file.save(os.path.join(event_folder, unique_filename))
                
                # Store relative path: event_name/filename
                cover_photo_filename = f"{secure_filename(event_name)}/{unique_filename}"
        
        session['event_details'] = {
            'event_name': event_name,
            'event_date': request.form['event_date'],
            'event_venue': request.form['event_venue'],
            'event_category': request.form['event_category'],
            'cover_photo': cover_photo_filename
        }
        return redirect(url_for('set_privacy'))
    return render_template('create_event.html')

@app.route('/set_privacy', methods=['GET', 'POST'])
def set_privacy():
    if 'user_id' not in session or 'event_details' not in session:
        return redirect(url_for('create_event'))
    if request.method == 'POST':
        privacy_setting = request.form['privacy']
        details = session['event_details']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events (user_id, event_name, event_date, venue, category, privacy, cover_photo)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], details['event_name'], details['event_date'],
              details['event_venue'], details['event_category'], privacy_setting, details.get('cover_photo')))
        new_event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        session.pop('event_details', None)
        return redirect(url_for('add_album', event_id=new_event_id))
    return render_template('set_privacy.html')

# --- Album and Photo Routes ---
@app.route('/add_album/<int:event_id>')
def add_album(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT event_name, cover_photo FROM events WHERE id = ? AND user_id = ?", (event_id, session['user_id']))
    event = cursor.fetchone()
    conn.close()
    if event:
        return render_template('add_album.html', event_name=event[0], cover_photo=event[1], event_id=event_id)
    return redirect(url_for('dashboard'))

@app.route('/album/<int:event_id>')
def view_album(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT event_name FROM events WHERE id = ? AND user_id = ?", (event_id, session['user_id']))
    event = cursor.fetchone()
    cursor.execute("SELECT id, filename FROM photos WHERE event_id = ?", (event_id,))
    photos = cursor.fetchall()
    conn.close()

    if event:
        return render_template('view_album.html', 
                               event_name=event[0], 
                               user_first_name=session['first_name'], 
                               event_id=event_id, 
                               photos=photos)
    return redirect(url_for('dashboard'))

@app.route('/album/<int:event_id>/upload', methods=['POST'])
def upload_photos(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'photos' not in request.files:
        return redirect(url_for('view_album', event_id=event_id))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Get event name for folder
    cursor.execute("SELECT event_name FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    if not event:
        conn.close()
        return "Event not found", 404
    
    event_name = event[0]
    print(f"DEBUG: Uploading photos for event '{event_name}' (ID: {event_id})")
    
    # Create event-specific folder
    folder_name = secure_filename(event_name)
    event_folder = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)
    print(f"DEBUG: Event folder path: {event_folder}")
    os.makedirs(event_folder, exist_ok=True)
    
    files = request.files.getlist('photos')
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(event_folder, filename))
            
            # Store relative path: event_name/filename
            relative_path = f"{secure_filename(event_name)}/{filename}"
            cursor.execute("INSERT INTO photos (event_id, filename) VALUES (?, ?)", (event_id, relative_path))
    conn.commit()
    conn.close()
    return redirect(url_for('view_album', event_id=event_id))

@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    if not event or event[0] != session['user_id']:
        conn.close()
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT filename FROM photos WHERE event_id = ?", (event_id,))
    photos_to_delete = cursor.fetchall()
    for photo in photos_to_delete:
        filename = photo[0]
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error deleting file {filename}: {e}")

    cursor.execute("DELETE FROM photos WHERE event_id = ?", (event_id,))
    cursor.execute("DELETE FROM events WHERE id = ?", (event_id,))

    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
def delete_photo(photo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT event_id, filename FROM photos WHERE id = ?", (photo_id,))
    photo = cursor.fetchone()
    
    if not photo:
        conn.close()
        return redirect(url_for('dashboard'))
    
    event_id, filename = photo

    cursor.execute("SELECT user_id FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    if not event or event[0] != session['user_id']:
        conn.close()
        return redirect(url_for('dashboard'))

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"Error deleting file {filename}: {e}")

    cursor.execute("DELETE FROM photos WHERE id = ?", (photo_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('view_album', event_id=event_id))

# --- Add this new route to handle deleting all photos in an event ---

@app.route('/album/<int:event_id>/delete_all', methods=['POST'])
def delete_all_photos(event_id):
    # Security check: ensure user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Security check: ensure the event belongs to the current user
    cursor.execute("SELECT user_id FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    if not event or event[0] != session['user_id']:
        conn.close()
        return redirect(url_for('dashboard')) # Redirect if not authorized

    # Step 1: Find and delete all associated photo files from the uploads folder
    cursor.execute("SELECT filename FROM photos WHERE event_id = ?", (event_id,))
    photos_to_delete = cursor.fetchall()
    for photo in photos_to_delete:
        filename = photo[0]
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error deleting file {filename}: {e}") # Log the error

    # Step 2: Delete all photo records for this event from the 'photos' table
    cursor.execute("DELETE FROM photos WHERE event_id = ?", (event_id,))

    conn.commit()
    conn.close()

    # Redirect back to the album page, which will now be empty
    return redirect(url_for('view_album', event_id=event_id))

# --- Add this new route for the public-facing "Find Photos" page ---

@app.route('/event/<int:event_id>/find')
def find_photos(event_id):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    cursor = conn.cursor()

    # Fetch the event details to display its name
    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()

    if event:
        # Pass the event object to the template
        return render_template('find_photos.html', event=event)
    else:
        return "Event not found", 404


@app.route('/guest_signup/<int:event_id>', methods=['POST'])
def guest_signup(event_id):
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    
    # Validate at least one is provided
    if not email and not phone:
        return jsonify({'error': 'Email or phone number required'}), 400
    
    # Store in database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO guest_users (event_id, email, phone)
        VALUES (?, ?, ?)
    ''', (event_id, email if email else None, phone if phone else None))
    conn.commit()
    conn.close()
    
    # Set session
    session[f'guest_auth_{event_id}'] = True
    if email:
        session[f'guest_email_{event_id}'] = email
    if phone:
        session[f'guest_phone_{event_id}'] = phone
    
    return jsonify({'success': True})


# OTP Authentication Routes
def generate_otp():
    """Generate a 6-digit OTP code"""
    return ''.join(random.choices(string.digits, k=6))


@app.route('/request_otp/<int:event_id>', methods=['POST'])
def request_otp(event_id):
    """Generate and send OTP to email or phone"""
    data = request.get_json()
    contact = data.get('contact', '').strip()
    
    if not contact:
        return jsonify({'error': 'Email or phone number required'}), 400
    
    # Generate OTP
    otp_code = generate_otp()
    
    # Set expiration time (10 minutes from now)
    expires_at = datetime.now() + timedelta(minutes=10)
    
    # Store OTP in database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Delete any existing unverified OTPs for this contact and event
    cursor.execute('''
        DELETE FROM otp_codes 
        WHERE event_id = ? AND contact = ? AND verified = 0
    ''', (event_id, contact))
    
    # Insert new OTP
    cursor.execute('''
        INSERT INTO otp_codes (event_id, contact, otp_code, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (event_id, contact, otp_code, expires_at))
    
    conn.commit()
    conn.close()
    
    # Send OTP via email or SMS
    if '@' in contact:  # Email
        try:
            msg = Message(
                subject='Your PixMatch OTP Code',
                recipients=[contact],
                body=f'Your OTP code is: {otp_code}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this code, please ignore this email.'
            )
            mail.send(msg)
            return jsonify({'success': True, 'message': 'OTP sent to your email'})
        except Exception as e:
            print(f"Email error: {e}")
            # For development, return OTP in response (REMOVE IN PRODUCTION)
            return jsonify({'success': True, 'message': f'OTP (dev mode): {otp_code}'})
    else:  # Phone (SMS - placeholder)
        # TODO: Implement SMS sending with Twilio or similar service
        # For now, return OTP in response for development
        return jsonify({'success': True, 'message': f'SMS not configured. OTP (dev mode): {otp_code}'})


@app.route('/verify_otp/<int:event_id>', methods=['POST'])
def verify_otp(event_id):
    """Verify OTP code"""
    data = request.get_json()
    contact = data.get('contact', '').strip()
    otp_code = data.get('otp_code', '').strip()
    
    if not contact or not otp_code:
        return jsonify({'error': 'Contact and OTP code required'}), 400
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Find valid OTP
    cursor.execute('''
        SELECT id, otp_code, expires_at FROM otp_codes
        WHERE event_id = ? AND contact = ? AND verified = 0
        ORDER BY created_at DESC LIMIT 1
    ''', (event_id, contact))
    
    otp_record = cursor.fetchone()
    
    if not otp_record:
        conn.close()
        return jsonify({'error': 'No OTP found. Please request a new one.'}), 400
    
    otp_id, stored_otp, expires_at = otp_record
    
    # Check if OTP has expired
    if datetime.now() > datetime.fromisoformat(expires_at):
        conn.close()
        return jsonify({'error': 'OTP has expired. Please request a new one.'}), 400
    
    # Verify OTP
    if otp_code != stored_otp:
        conn.close()
        return jsonify({'error': 'Invalid OTP code'}), 400
    
    # Mark OTP as verified
    cursor.execute('UPDATE otp_codes SET verified = 1 WHERE id = ?', (otp_id,))
    
    # Check if this user already exists (returning user)
    cursor.execute('''
        SELECT id, first_name, last_name, email, phone 
        FROM guest_users 
        WHERE event_id = ? AND (email = ? OR phone = ?)
    ''', (event_id, contact, contact))
    
    existing_user = cursor.fetchone()
    
    conn.commit()
    conn.close()
    
    # Set session
    session[f'otp_verified_{event_id}'] = True
    session[f'otp_contact_{event_id}'] = contact
    
    if existing_user:
        # Returning user - auto-complete their info
        user_id, first_name, last_name, email, phone = existing_user
        session[f'guest_info_complete_{event_id}'] = True
        session[f'guest_name_{event_id}'] = f'{first_name} {last_name}'
        session[f'guest_email_{event_id}'] = email or phone
        
        return jsonify({
            'success': True, 
            'message': 'OTP verified successfully',
            'returning_user': True,
            'user_name': f'{first_name} {last_name}'
        })
    else:
        # New user - needs to fill in details
        return jsonify({
            'success': True, 
            'message': 'OTP verified successfully',
            'returning_user': False
        })


@app.route('/save_guest_info/<int:event_id>', methods=['POST'])
def save_guest_info(event_id):
    """Save guest user information after OTP verification"""
    data = request.get_json()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()
    contact = data.get('contact', '').strip()
    
    if not first_name or not last_name:
        return jsonify({'error': 'First and last name are required'}), 400
    
    if not email and not phone:
        return jsonify({'error': 'Either email or phone is required'}), 400
    
    # Check if OTP was verified for this event
    if not session.get(f'otp_verified_{event_id}'):
        return jsonify({'error': 'OTP verification required'}), 403
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Determine final email and phone
    final_email = email if email else None
    final_phone = phone if phone else None
    
    # Check if guest already exists
    cursor.execute('''
        SELECT id FROM guest_users 
        WHERE event_id = ? AND (email = ? OR phone = ?)
    ''', (event_id, final_email or '', final_phone or ''))
    
    existing_guest = cursor.fetchone()
    
    if existing_guest:
        # Update existing guest
        cursor.execute('''
            UPDATE guest_users 
            SET first_name = ?, last_name = ?, email = ?, phone = ?
            WHERE id = ?
        ''', (first_name, last_name, final_email, final_phone, existing_guest[0]))
    else:
        # Insert new guest
        cursor.execute('''
            INSERT INTO guest_users (event_id, first_name, last_name, email, phone)
            VALUES (?, ?, ?, ?, ?)
        ''', (event_id, first_name, last_name, final_email, final_phone))
    
    conn.commit()
    conn.close()
    
    # Get device ID from session
    device_id = session.get(f'device_id_{event_id}')
    if not device_id:
        device_id = generate_device_id(request)
        session[f'device_id_{event_id}'] = device_id
    
    # Save to thirduser database for visit tracking
    try:
        conn_third = sqlite3.connect(THIRDUSER_DB)
        cursor_third = conn_third.cursor()
        
        cursor_third.execute('''
            INSERT INTO guest_visitors (event_id, first_name, last_name, email, phone, device_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (event_id, first_name, last_name, final_email, final_phone, device_id))
        
        conn_third.commit()
        conn_third.close()
    except sqlite3.IntegrityError:
        # User already registered, ignore
        pass
    except Exception as e:
        print(f"Error saving to thirduser DB: {e}")
    
    # Mark as fully authenticated
    session[f'guest_info_complete_{event_id}'] = True
    session[f'guest_name_{event_id}'] = f'{first_name} {last_name}'
    session[f'guest_email_{event_id}'] = final_email or final_phone
    
    return jsonify({'success': True, 'message': 'Information saved successfully'})


# --- Add this new route for the public, shareable event page ---


@app.route('/auth/event/<int:event_id>')
def auth_event(event_id):
    """Standalone authentication page for event access"""
    # Generate device ID for this visitor (for tracking purposes only)
    device_id = generate_device_id(request)
    session[f'device_id_{event_id}'] = device_id
    
    # Check if already authenticated in current session
    if session.get(f'otp_verified_{event_id}') and session.get(f'guest_info_complete_{event_id}'):
                                # Already authenticated - fetch event and photos, then show share page
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Fetch event details
        cursor.execute("SELECT event_name, privacy, event_date, cover_photo FROM events WHERE id = ?", (event_id,))
        event = cursor.fetchone()
        
        # Fetch photos for this event
        cursor.execute("SELECT filename FROM photos WHERE event_id = ?", (event_id,))
        photos = cursor.fetchall()
        conn.close()
        
        return render_template('share_page.html', event=event, photos=photos, event_id=event_id, otp_verified=True)
    
    # Show authentication page
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Fetch event details
    cursor.execute("SELECT event_name, event_date, cover_photo FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()
    
    if event:
        return render_template('auth_page.html', event=event, event_id=event_id)
    else:
        return "Event not found.", 404


@app.route('/share/event/<int:event_id>')
def share_event(event_id):
    # Clear any existing guest authentication for this event
    # This ensures users must login every time they access the share link
    session.pop(f'otp_verified_{event_id}', None)
    session.pop(f'guest_info_complete_{event_id}', None)
    session.pop(f'guest_name_{event_id}', None)
    session.pop(f'guest_email_{event_id}', None)
    session.pop(f'otp_contact_{event_id}', None)
    
    conn = sqlite3.connect('database.db')
    # Use row_factory to get results as dictionaries for easy access in the template
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()

    # Fetch event details including privacy setting, date, and cover photo
    cursor.execute("SELECT event_name, privacy, event_date, cover_photo FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()

    # Fetch all photos for this event
    cursor.execute("SELECT filename FROM photos WHERE event_id = ?", (event_id,))
    photos = cursor.fetchall()
    
    conn.close()

    if event:
        # Always redirect to auth page first for share links
        # This ensures guests must authenticate even if they have other sessions
        return redirect(url_for('auth_event', event_id=event_id))
    else:
        # If the event doesn't exist, show a "Not Found" error
        return "Event not found.", 404


# --- API Route for Photo Matching ---
@app.route('/api/match_photos', methods=['POST'])
def match_photos_api():
    if 'photo' not in request.files:
        return jsonify({'status': 'error', 'message': 'No photo provided'}), 400
    
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No photo selected'}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Save temp user photo
        user_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_search_{int(time.time())}_{filename}")
        file.save(user_photo_path)
        
        # Define directories
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Default to Bhuman if no event specified (backward compatibility)
        search_dir = os.path.join(base_dir, 'Bhuman') 
        
        # Check if event_id is provided
        event_id = request.form.get('event_id')
        if event_id:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("SELECT event_name FROM events WHERE id = ?", (event_id,))
            event = cursor.fetchone()
            conn.close()
            
            if event:
                event_name = event[0]
                # Use the event's upload folder
                search_dir = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(event_name))
                print(f"DEBUG: Searching in event folder: {search_dir}")
        else:
            print("DEBUG: searching in default Bhuman folder")

        match_output_dir = os.path.join(base_dir, 'matchphotos')
        match_output_dir = os.path.join(base_dir, 'matchphotos')
        
        # Run matching
        try:
            # Clear matchphotos directory before starting a new search
            if os.path.exists(match_output_dir):
                import shutil
                for f in os.listdir(match_output_dir):
                    file_path = os.path.join(match_output_dir, f)
                    try:
                        if os.path.isfile(file_path) or os.path.islink(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        app.logger.error(f"Error clearing matchphotos file {f}: {e}")
            else:
                os.makedirs(match_output_dir, exist_ok=True)

            result = matcher.find_matches(
                user_photo_path, 
                search_dir, 
                match_output_dir,
                tolerance=0.60
            )
            
            # Remove temp file
            try:
                os.remove(user_photo_path)
            except:
                pass
                
            return jsonify(result)
            
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
            
    return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400

# --- Route to serve matched photos ---
@app.route('/matchphotos/<path:filename>')
def serve_matched_photo(filename):
    """Serve matched photos from the matchphotos directory"""
    from flask import send_from_directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    matchphotos_dir = os.path.join(base_dir, 'matchphotos')
    return send_from_directory(matchphotos_dir, filename)

@app.route('/source_photos/<filename>')
def serve_source_photo(filename):
    """Serve photos directly from Bhuman source directory to speed up display"""
    from flask import send_from_directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    source_dir = os.path.join(base_dir, 'Bhuman')
    return send_from_directory(source_dir, filename)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)