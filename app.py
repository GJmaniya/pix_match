import os
import time
import sqlite3
import hashlib
import json
import requests
from dotenv import load_dotenv

load_dotenv()

import google.oauth2.id_token
# Allow HTTP for local development only (prevents "(insecure_transport) OAuth 2 MUST utilize https." error)
if os.environ.get('APP_ENV') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # HTTP allowed only for local testing
    
from flask import Flask, flash, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as grequests
from flask import jsonify
from flask_mail import Mail, Message
from PIL import Image, ImageOps
from matcher import FaceMatcher
import random
import string
from datetime import datetime, timedelta
import concurrent.futures
import io
import zipfile
import uuid
import secrets
from flask import send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from watermarking import (
    WATERMARK_POSITIONS,
    apply_watermark,
    ensure_watermark_settings_table,
    get_watermark_settings,
    get_watermark_logo_path,
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-long-random-string')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', '')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD) if ADMIN_PASSWORD else ''
ADMIN_ENABLED = bool(
    ADMIN_USERNAME
    and ADMIN_PASSWORD_HASH
    and len(os.environ.get('SECRET_KEY', '')) >= 32
)

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
GOOGLE_REDIRECT_URI = os.environ.get(
    'GOOGLE_REDIRECT_URI',
    'http://127.0.0.1:5000/oauth2callback',
)
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
    """Create the application tables and add columns missing from older databases."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    with conn:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT,
                last_name TEXT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT,
                registered_at TIMESTAMP,
                last_login_at TIMESTAMP,
                is_locked INTEGER NOT NULL DEFAULT 0,
                unlock_code_hash TEXT
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                event_date TEXT,
                venue TEXT,
                category TEXT,
                privacy TEXT,
                cover_photo TEXT,
                pin_code TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                sub_event_id INTEGER,
                FOREIGN KEY (event_id) REFERENCES events (id)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sub_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS guest_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                phone TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                contact TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS admin_unlock_codes (
                code_fingerprint TEXT PRIMARY KEY,
                generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        ensure_watermark_settings_table(conn)

        migrations = {
            'events': ('pin_code', 'TEXT'),
            'photos': ('sub_event_id', 'INTEGER REFERENCES sub_events(id)'),
            'guest_users': ('created_at', 'TIMESTAMP'),
        }
        for table, (column, definition) in migrations.items():
            columns = {row[1] for row in cur.execute(f'PRAGMA table_info({table})')}
            if column not in columns:
                cur.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
                if table == 'guest_users' and column == 'created_at':
                    cur.execute(
                        'UPDATE guest_users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL'
                    )
        user_columns = {row[1] for row in cur.execute('PRAGMA table_info(users)')}
        user_migrations = {
            'registered_at': 'TIMESTAMP',
            'last_login_at': 'TIMESTAMP',
            'is_locked': 'INTEGER NOT NULL DEFAULT 0',
            'unlock_code_hash': 'TEXT',
        }
        for column, definition in user_migrations.items():
            if column not in user_columns:
                cur.execute(f'ALTER TABLE users ADD COLUMN {column} {definition}')
    conn.close()

# ensure DB exists
init_db()

@app.before_request
def reject_locked_user_sessions():
    user_id = session.get('user_id')
    if user_id is None:
        return None

    conn = sqlite3.connect(DB_PATH)
    user = conn.execute(
        'SELECT is_locked FROM users WHERE id = ?',
        (user_id,),
    ).fetchone()
    conn.close()
    if user is None:
        session.clear()
        return redirect(url_for('login'))
    if user[0] and request.endpoint not in {'account_unlock', 'logout', 'static'}:
        if request.endpoint and request.endpoint.startswith('api_'):
            return jsonify({
                'status': 'error',
                'message': 'Account is locked. Enter the unlock code to continue.',
            }), 423
        return render_template(
            'account_locked.html',
            csrf_token=session.setdefault(
                'account_unlock_csrf_token',
                secrets.token_urlsafe(32),
            ),
            error=None,
        ), 423
    return None

# --- Google OAuth routes ---
@app.route('/login/google')
def login_google():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return ("Google OAuth not configured. Place client_secrets.json in project root."), 500
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        autogenerate_code_verifier=False,
        redirect_uri=GOOGLE_REDIRECT_URI
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
            autogenerate_code_verifier=False,
            state=state,
            redirect_uri=GOOGLE_REDIRECT_URI
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
        first_name = userinfo.get('given_name', '') or (userinfo.get('name', '').split(' ') or [''])[0]
        last_name = userinfo.get('family_name', '') or ''

        # upsert user
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, first_name, is_locked FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if not user:
            base_username = (email.split('@')[0] if email else 'user')
            username = base_username
            i = 1
            while True:
                try:
                    cur.execute('''
                        INSERT INTO users (
                            first_name, last_name, username, email, password,
                            registered_at, last_login_at
                        ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ''', (first_name, last_name, username, email, ''))
                    conn.commit()
                    user_id = cur.lastrowid
                    break
                except sqlite3.IntegrityError:
                    username = f"{base_username}{i}"
                    i += 1
        else:
            user_id = user[0]
            first_name = user[1] or first_name
            cur.execute(
                'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?',
                (user_id,),
            )
            conn.commit()
        conn.close()

        session.clear()
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT first_name, last_name, username FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    if user_data is None:
        conn.close()
        session.clear()
        return redirect(url_for('login'))
    user_first_name = user_data[0]
    user_last_name = user_data[1]
    username = user_data[2]
    cursor.execute('SELECT id, event_name, event_date, cover_photo FROM events WHERE user_id = ?', (user_id,))
    events = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', user_first_name=user_first_name, user_last_name=user_last_name, username=username, events=events)


@app.route('/watermark', methods=['GET', 'POST'])
def watermark_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    settings = get_watermark_settings(conn, user_id)
    csrf_token = session.setdefault('watermark_csrf_token', secrets.token_urlsafe(32))
    error = None
    saved = False
    status_code = 200
    new_logo_path = None

    if request.method == 'POST':
        if not secrets.compare_digest(
            csrf_token,
            request.form.get('csrf_token', ''),
        ):
            error = 'Your settings form expired. Refresh the page and try again.'
            status_code = 400
        else:
            position = request.form.get('position', '')
            try:
                opacity = int(request.form.get('opacity', ''))
                size = int(request.form.get('size', ''))
            except ValueError:
                opacity = -1
                size = -1

            if position not in WATERMARK_POSITIONS:
                error = 'Choose one of the available watermark positions.'
            elif not 10 <= opacity <= 100:
                error = 'Watermark opacity must be between 10 and 100.'
            elif not 5 <= size <= 50:
                error = 'Watermark size must be between 5 and 50.'

            uploaded_primary = request.files.get('logo_file')
            primary_bytes = uploaded_primary.read(5 * 1024 * 1024 + 1) if uploaded_primary and uploaded_primary.filename else b''
            if not error and len(primary_bytes) > 5 * 1024 * 1024:
                error = 'The logo must be 5 MB or smaller.'

            cleaned_primary = None
            if not error and primary_bytes:
                try:
                    with Image.open(io.BytesIO(primary_bytes)) as uploaded_image:
                        if uploaded_image.format not in {'PNG', 'JPEG', 'WEBP'}:
                            raise ValueError('Unsupported image type')
                        if uploaded_image.width * uploaded_image.height > 20_000_000:
                            raise ValueError('Image dimensions are too large')
                        uploaded_image.load()
                        cleaned_primary = uploaded_image.convert('RGBA')
                except (OSError, ValueError, Image.DecompressionBombError):
                    error = 'Upload a valid PNG, JPG, or WEBP logo (20 megapixels or less).'

            if not error:
                remove_primary = (
                    request.form.get('remove_logo') == '1'
                    and cleaned_primary is None
                )
                old_primary_filename = settings.get('logo_filename')
                old_secondary_filename = settings.get('secondary_logo_filename')
                primary_filename = None if remove_primary else old_primary_filename

                if cleaned_primary is not None:
                    primary_filename = f'user_{user_id}_{uuid.uuid4().hex}.png'
                    watermark_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'watermarks')
                    os.makedirs(watermark_folder, exist_ok=True)
                    new_logo_path = os.path.join(watermark_folder, primary_filename)
                    cleaned_primary.save(new_logo_path, format='PNG', optimize=True)

                # --- Secondary logo ---
                uploaded_secondary = request.files.get('secondary_logo_file')
                secondary_bytes = uploaded_secondary.read(5 * 1024 * 1024 + 1) if uploaded_secondary and uploaded_secondary.filename else b''
                if not error and len(secondary_bytes) > 5 * 1024 * 1024:
                    error = 'The secondary logo must be 5 MB or smaller.'

                cleaned_secondary = None
                if not error and secondary_bytes:
                    try:
                        with Image.open(io.BytesIO(secondary_bytes)) as uploaded_secondary_image:
                            if uploaded_secondary_image.format not in {'PNG', 'JPEG', 'WEBP'}:
                                raise ValueError('Unsupported image type')
                            if uploaded_secondary_image.width * uploaded_secondary_image.height > 20_000_000:
                                raise ValueError('Image dimensions are too large')
                            uploaded_secondary_image.load()
                            cleaned_secondary = uploaded_secondary_image.convert('RGBA')
                    except (OSError, ValueError, Image.DecompressionBombError):
                        error = 'Upload a valid PNG, JPG, or WEBP secondary logo (20 megapixels or less).'

                new_secondary_logo_path = None
                secondary_filename = old_secondary_filename
                remove_secondary = (
                    request.form.get('remove_secondary_logo') == '1'
                    and cleaned_secondary is None
                )
                if remove_secondary:
                    secondary_filename = None

                if not error and cleaned_secondary is not None:
                    secondary_filename = f'user_{user_id}_sec_{uuid.uuid4().hex}.png'
                    watermark_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'watermarks')
                    os.makedirs(watermark_folder, exist_ok=True)
                    new_secondary_logo_path = os.path.join(watermark_folder, secondary_filename)
                    cleaned_secondary.save(new_secondary_logo_path, format='PNG', optimize=True)

                enabled = int(
                    request.form.get('enabled') == '1'
                    and not remove_primary
                )
                if enabled and not primary_filename:
                    error = 'The primary watermark logo is required when watermarking is enabled.'

                if not error:
                    try:
                        conn.execute(
                            '''
                            INSERT INTO watermark_settings
                                (user_id, logo_filename, secondary_logo_filename, enabled, position, opacity, size)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(user_id) DO UPDATE SET
                                logo_filename = excluded.logo_filename,
                                secondary_logo_filename = excluded.secondary_logo_filename,
                                enabled = excluded.enabled,
                                position = excluded.position,
                                opacity = excluded.opacity,
                                size = excluded.size
                            ''',
                            (
                                user_id,
                                primary_filename,
                                secondary_filename,
                                enabled,
                                position,
                                opacity,
                                size,
                            ),
                        )
                        conn.commit()
                        settings = get_watermark_settings(conn, user_id)
                        saved = True
                        for old_filename, new_filename, key in [
                            (old_primary_filename, primary_filename, 'logo_filename'),
                            (old_secondary_filename, secondary_filename, 'secondary_logo_filename'),
                        ]:
                            if old_filename and old_filename != new_filename:
                                old_logo_path = get_watermark_logo_path(
                                    {key: old_filename},
                                    app.static_folder,
                                    key=key,
                                )
                                try:
                                    os.remove(old_logo_path)
                                except FileNotFoundError:
                                    pass
                                except OSError:
                                    app.logger.exception('Failed to remove the replaced watermark logo')
                    except sqlite3.Error:
                        conn.rollback()
                        for file_path in [locals().get('new_logo_path'), locals().get('new_secondary_logo_path')]:
                            if file_path:
                                try:
                                    os.remove(file_path)
                                except OSError:
                                    app.logger.exception('Failed to remove an uncommitted watermark logo')
                        app.logger.exception('Failed to save watermark settings for user %s', user_id)
                        error = 'Your watermark settings could not be saved. Please try again.'
                        status_code = 500

    conn.close()
    logo_filename = settings.get('logo_filename')
    logo_preview_url = (
        url_for('static', filename=f'uploads/watermarks/{logo_filename}')
        if logo_filename
        else None
    )
    secondary_logo_filename = settings.get('secondary_logo_filename')
    secondary_logo_preview_url = (
        url_for('static', filename=f'uploads/watermarks/{secondary_logo_filename}')
        if secondary_logo_filename
        else None
    )
    return render_template(
        'watermark.html',
        user_first_name=session.get('first_name', ''),
        settings=settings,
        csrf_token=csrf_token,
        logo_preview_url=logo_preview_url,
        secondary_logo_preview_url=secondary_logo_preview_url,
        error=error,
        saved=saved,
    ), status_code

def _render_admin_accounts(unlock_code=None, error=None, notice=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, first_name, last_name, username, email,
               registered_at, last_login_at, is_locked
        FROM users
        ORDER BY registered_at DESC, id DESC
    ''')
    users = cursor.fetchall()
    conn.close()
    return render_template(
        'admin.html',
        users=users,
        user_count=len(users),
        csrf_token=session.setdefault('admin_csrf_token', secrets.token_urlsafe(32)),
        unlock_code=unlock_code,
        error=error,
        notice=notice,
    )

def _admin_csrf_valid():
    expected = session.get('admin_csrf_token', '')
    provided = request.form.get('csrf_token', '')
    return bool(expected and secrets.compare_digest(expected, provided))

def _generate_unique_unlock_code(conn):
    while True:
        code = ''.join(
            secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
            for _ in range(6)
        )
        fingerprint = hashlib.sha256(code.encode('utf-8')).hexdigest()
        try:
            conn.execute(
                'INSERT INTO admin_unlock_codes (code_fingerprint) VALUES (?)',
                (fingerprint,),
            )
            return code
        except sqlite3.IntegrityError:
            continue

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if not ADMIN_ENABLED:
        return render_template(
            'admin_login.html',
            error='Admin login is not configured. Set ADMIN_USERNAME, ADMIN_PASSWORD, and a strong SECRET_KEY.',
        ), 503

    if not session.get('admin_authenticated'):
        error = None
        csrf_token = session.setdefault('admin_csrf_token', secrets.token_urlsafe(32))
        if request.method == 'POST':
            if not _admin_csrf_valid():
                return render_template(
                    'admin_login.html',
                    error='Your login form expired. Please refresh and try again.',
                    csrf_token=csrf_token,
                ), 400
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            username_valid = secrets.compare_digest(username, ADMIN_USERNAME)
            password_valid = check_password_hash(ADMIN_PASSWORD_HASH, password)
            if username_valid and password_valid:
                session.clear()
                session['admin_authenticated'] = True
                session['admin_csrf_token'] = secrets.token_urlsafe(32)
                return redirect(url_for('admin_panel'))
            error = 'Invalid username or password.'
        return render_template('admin_login.html', error=error, csrf_token=csrf_token)

    return _render_admin_accounts()

@app.route('/admin/users/<int:user_id>/lock', methods=['POST'])
def admin_lock_user(user_id):
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))
    if not _admin_csrf_valid():
        return 'Invalid or expired request token.', 400

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        'SELECT id FROM users WHERE id = ?',
        (user_id,),
    ).fetchone()
    if row is None:
        conn.close()
        return 'Account not found.', 404

    with conn:
        unlock_code = _generate_unique_unlock_code(conn)
        conn.execute(
            'UPDATE users SET is_locked = 1, unlock_code_hash = ? WHERE id = ?',
            (generate_password_hash(unlock_code), user_id),
        )
    conn.close()
    return _render_admin_accounts(
        unlock_code=unlock_code,
        notice='Account locked. Share this one-time six-character code with the user. It will not be shown again.',
    )

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))
    if not _admin_csrf_valid():
        return 'Invalid or expired request token.', 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    if cursor.fetchone() is None:
        conn.close()
        return 'Account not found.', 404

    cursor.execute(
        'SELECT photos.filename FROM photos '
        'JOIN events ON events.id = photos.event_id '
        'WHERE events.user_id = ?',
        (user_id,),
    )
    files_to_check = set()
    files_to_check.update(row[0] for row in cursor.fetchall() if row[0])
    cursor.execute(
        'SELECT cover_photo FROM events WHERE user_id = ?',
        (user_id,),
    )
    files_to_check.update(row[0] for row in cursor.fetchall() if row[0])
    cursor.execute('SELECT id FROM events WHERE user_id = ?', (user_id,))
    event_ids = [row[0] for row in cursor.fetchall()]

    with conn:
        cursor.execute(
            'DELETE FROM otp_codes WHERE event_id IN '
            '(SELECT id FROM events WHERE user_id = ?)',
            (user_id,),
        )
        cursor.execute(
            'DELETE FROM guest_users WHERE event_id IN '
            '(SELECT id FROM events WHERE user_id = ?)',
            (user_id,),
        )
        cursor.execute(
            'DELETE FROM photos WHERE event_id IN '
            '(SELECT id FROM events WHERE user_id = ?)',
            (user_id,),
        )
        cursor.execute(
            'DELETE FROM sub_events WHERE event_id IN '
            '(SELECT id FROM events WHERE user_id = ?)',
            (user_id,),
        )
        cursor.execute('DELETE FROM events WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

    remaining_files = set()
    cursor.execute('SELECT filename FROM photos')
    remaining_files.update(row[0] for row in cursor.fetchall() if row[0])
    cursor.execute('SELECT cover_photo FROM events')
    remaining_files.update(row[0] for row in cursor.fetchall() if row[0])
    conn.close()

    cleanup_failed = False
    if event_ids and os.path.exists(THIRDUSER_DB):
        visitors_conn = None
        try:
            visitors_conn = sqlite3.connect(THIRDUSER_DB)
            visitors_table = visitors_conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'guest_visitors'"
            ).fetchone()
            if visitors_table:
                with visitors_conn:
                    for start in range(0, len(event_ids), 900):
                        event_id_batch = event_ids[start:start + 900]
                        placeholders = ','.join('?' for _ in event_id_batch)
                        visitors_conn.execute(
                            f'DELETE FROM guest_visitors WHERE event_id IN ({placeholders})',
                            event_id_batch,
                        )
        except sqlite3.Error:
            app.logger.exception('Unable to remove visitor records for deleted account %s.', user_id)
            cleanup_failed = True
        finally:
            if visitors_conn is not None:
                visitors_conn.close()

    upload_root = os.path.realpath(app.config['UPLOAD_FOLDER'])
    for relative_path in files_to_check - remaining_files:
        file_path = os.path.realpath(os.path.join(upload_root, relative_path))
        if os.path.commonpath((upload_root, file_path)) != upload_root:
            app.logger.warning('Skipped unsafe account-owned upload path during deletion.')
            cleanup_failed = True
            continue
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except OSError:
            app.logger.exception('Unable to remove account-owned upload: %s', file_path)
            cleanup_failed = True

    notice = 'Account and its event data were deleted.'
    if cleanup_failed:
        notice += ' Some related records or uploaded files could not be removed; check the server log.'
    return _render_admin_accounts(notice=notice)

@app.route('/account/unlock', methods=['POST'])
def account_unlock():
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('login'))

    expected = session.get('account_unlock_csrf_token', '')
    provided = request.form.get('csrf_token', '')
    if not expected or not secrets.compare_digest(expected, provided):
        return 'Invalid or expired request token. Refresh the page and try again.', 400

    unlock_code = request.form.get('unlock_code', '').strip().upper()
    if len(unlock_code) != 6 or not unlock_code.isascii() or not unlock_code.isalnum():
        return render_template(
            'account_locked.html',
            csrf_token=expected,
            error='Enter the 6-character code provided by the administrator.',
        ), 423

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        'SELECT is_locked, unlock_code_hash FROM users WHERE id = ?',
        (user_id,),
    ).fetchone()
    if row is None:
        conn.close()
        session.clear()
        return redirect(url_for('login'))
    if not row[0] or not row[1] or not check_password_hash(row[1], unlock_code):
        conn.close()
        return render_template(
            'account_locked.html',
            csrf_token=expected,
            error='That code is incorrect or expired. Please try again.',
        ), 423

    with conn:
        conn.execute(
            'UPDATE users SET is_locked = 0, unlock_code_hash = NULL WHERE id = ?',
            (user_id,),
        )
    conn.close()
    session.pop('account_unlock_csrf_token', None)
    return redirect(url_for('dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    return redirect(url_for('admin_panel'))

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
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, first_name, is_locked FROM users WHERE (username = ? OR email = ?) AND password = ? AND password != \'\'', 
                       (username_or_email, username_or_email, password))
        user = cursor.fetchone()
        if user:
            cursor.execute(
                'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?',
                (user[0],),
            )
            conn.commit()
        conn.close()
        if user:
            session.clear()
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
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (
                first_name, last_name, username, email, password,
                registered_at, last_login_at
            ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (first_name, last_name, username, email, password))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        session.clear()
        session['user_id'] = user_id
        session['first_name'] = first_name
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

# --- Event Creation Routes ---
def get_or_create_pin(event_id, conn, return_only=False):
    """
    Helper function to get an event's PIN, or create one if it doesn't exist.
    If return_only is True, it expects a db connection to be handled externally.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT pin_code FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    if row and row[0]:
        return row[0]
        
    # Generate 6-char alphanumeric PIN
    import string
    import random
    new_pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    cursor.execute("UPDATE events SET pin_code = ? WHERE id = ?", (new_pin, event_id))
    conn.commit()
    return new_pin

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
        
        # Generate a random 6-character PIN code for the event
        import string
        import random
        new_pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        # Save event directly to DB, skipping privacy step
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events (user_id, event_name, event_date, venue, category, privacy, cover_photo, pin_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], event_name, request.form['event_date'],
              request.form['event_venue'], request.form['event_category'], 'Full access', cover_photo_filename, new_pin))
        
        new_event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return redirect(url_for('add_album', event_id=new_event_id))
        
    return render_template('create_event.html')

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
    
    if not event:
        conn.close()
        return redirect(url_for('dashboard'))

    # Get or generate a PIN for this event
    pin_code = get_or_create_pin(event_id, conn, return_only=True)
    
    # Fetch root photos (not in any sub-event)
    cursor.execute("SELECT id, filename FROM photos WHERE event_id = ? AND sub_event_id IS NULL", (event_id,))
    photos = cursor.fetchall()
    
    # Fetch sub-events (folders)
    cursor.execute("SELECT id, name FROM sub_events WHERE event_id = ? ORDER BY created_at DESC", (event_id,))
    sub_events = cursor.fetchall()
    
    conn.commit()
    conn.close()

    if event:
        return render_template('view_album.html', 
                               event_name=event[0], 
                               user_first_name=session['first_name'], 
                               event_id=event_id, 
                               photos=photos,
                               sub_events=sub_events,
                               current_sub_event=None,
                               pin_code=pin_code)
    return redirect(url_for('dashboard'))

@app.route('/album/<int:event_id>/folder/<int:sub_event_id>')
def view_sub_album(event_id, sub_event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Verify event ownership
    cursor.execute("SELECT event_name FROM events WHERE id = ? AND user_id = ?", (event_id, session['user_id']))
    event = cursor.fetchone()
    
    # Verify sub-event exists
    cursor.execute("SELECT id, name FROM sub_events WHERE id = ? AND event_id = ?", (sub_event_id, event_id))
    sub_event = cursor.fetchone()
    
    if not event or not sub_event:
        conn.close()
        return redirect(url_for('view_album', event_id=event_id))
        
    # Fetch photos for this sub-event
    cursor.execute("SELECT id, filename FROM photos WHERE event_id = ? AND sub_event_id = ?", (event_id, sub_event_id))
    photos = cursor.fetchall()
    
    # Get or generate a PIN for this event
    pin_code = get_or_create_pin(event_id, conn, return_only=True)
    
    conn.commit()
    conn.close()

    return render_template('view_album.html', 
                           event_name=f"{event[0]} > {sub_event[1]}", 
                           user_first_name=session['first_name'], 
                           event_id=event_id, 
                           photos=photos,
                           sub_events=[], # Don't show folders inside folders
                           current_sub_event=sub_event,
                           pin_code=pin_code)

@app.route('/album/<int:event_id>/create_folder', methods=['POST'])
def create_sub_event(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    folder_name = request.form.get('folder_name', '').strip()
    if not folder_name:
        return redirect(url_for('view_album', event_id=event_id))
        
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Verify event ownership
    cursor.execute("SELECT id FROM events WHERE id = ? AND user_id = ?", (event_id, session['user_id']))
    if not cursor.fetchone():
        conn.close()
        return redirect(url_for('dashboard'))
        
    cursor.execute("INSERT INTO sub_events (event_id, name) VALUES (?, ?)", (event_id, folder_name))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_album', event_id=event_id))

@app.route('/album/<int:event_id>/folder/<int:sub_event_id>/delete', methods=['POST'])
def delete_folder(event_id, sub_event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Verify event ownership
    cursor.execute("SELECT id FROM events WHERE id = ? AND user_id = ?", (event_id, session['user_id']))
    if not cursor.fetchone():
        conn.close()
        return redirect(url_for('dashboard'))
        
    # Get all photos in this folder
    cursor.execute("SELECT filename FROM photos WHERE sub_event_id = ?", (sub_event_id,))
    photos_to_delete = cursor.fetchall()
    
    # Delete physical files
    for photo in photos_to_delete:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], photo[0])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            app.logger.error(f"Error removing file {file_path}: {e}")
            
    # Delete records from DB
    cursor.execute("DELETE FROM photos WHERE sub_event_id = ?", (sub_event_id,))
    cursor.execute("DELETE FROM sub_events WHERE id = ? AND event_id = ?", (sub_event_id, event_id))
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_album', event_id=event_id))

@app.route('/album/<int:event_id>/upload', methods=['POST'])
def upload_photos(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'photos' not in request.files:
        return redirect(url_for('view_album', event_id=event_id))
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Check event ownership and load the account's watermark settings.
    cursor.execute("SELECT event_name, user_id FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    if not event or event[1] != session['user_id']:
        conn.close()
        return "Event not found", 404
    
    event_name = event[0]
    watermark_settings = get_watermark_settings(conn, event[1])
    watermark_logo_path = get_watermark_logo_path(
        watermark_settings,
        app.static_folder,
        key='logo_filename',
    )
    if (
        watermark_settings['enabled']
        and watermark_settings['logo_filename']
        and not os.path.isfile(primary_logo_path)
    ):
        conn.close()
        app.logger.error(
            'Configured watermark logo is missing for user %s',
            event[1],
        )
        return "Configured watermark logo is missing. Update it in Watermark settings.", 500
    sub_event_id = request.form.get('sub_event_id')
    compress_quality = request.form.get('compress', '85')
    
    print(f"DEBUG: Uploading photos for event '{event_name}' (ID: {event_id}), Folder ID: {sub_event_id}, Compress Quality: {compress_quality}")
    
    # Create event-specific folder
    folder_name = secure_filename(event_name)
    event_folder = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)
    os.makedirs(event_folder, exist_ok=True)
    
    files = request.files.getlist('photos')
    
    # Helper to process a single photo
    def process_photo(file_data, filename, save_path, quality_str):
        try:
            # Load the main image
            img = Image.open(io.BytesIO(file_data))
            img = ImageOps.exif_transpose(img)
            img = apply_watermark(img, watermark_logo_path, watermark_settings)

            # Save the processed image
            if quality_str != '100':
                quality = int(quality_str)
                img.save(save_path, optimize=True, quality=quality)
            else:
                # Even if original quality is requested, we need to save the watermarked modified image
                img.save(save_path, quality=95) # Save high quality
                
            return filename, True
            
        except Exception:
            app.logger.exception('Failed to process uploaded photo %s', filename)
            return filename, False

    # Extract valid files into memory so we can detach them from the Flask request context
    tasks = []
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(event_folder, filename)
            file_data = file.read()
            tasks.append((file_data, filename, save_path, compress_quality))
            
    # Process files concurrently
    processed_filenames = []
    failed_filenames = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(process_photo, *task) for task in tasks]
        for future in concurrent.futures.as_completed(futures):
            try:
                fname, succeeded = future.result()
                if succeeded:
                    processed_filenames.append(fname)
                else:
                    failed_filenames.append(fname)
            except Exception as e:
                app.logger.exception('Photo processing thread failed: %s', e)
    if failed_filenames:
        flash(
            f'{len(failed_filenames)} photo(s) could not be processed and were not saved.',
            'error',
        )

    # Batch insert into database
    for filename in processed_filenames:
        relative_path = f"{secure_filename(event_name)}/{filename}"
        if sub_event_id:
            cursor.execute("INSERT INTO photos (event_id, sub_event_id, filename) VALUES (?, ?, ?)", (event_id, sub_event_id, relative_path))
        else:
            cursor.execute("INSERT INTO photos (event_id, filename) VALUES (?, ?)", (event_id, relative_path))
            
    conn.commit()
    conn.close()
    
    # Auto-train ML model in the background
    try:
        import threading
        # Ensure matcher processes the new embedding without blocking the user upload request
        cache_path = os.path.join(event_folder, "embeddings_cache.pt")
        def train_model():
            try:
                print(f"DEBUG: Starting background auto-training for event {event_name}...")
                matcher.load_or_compute_directory_embeddings(event_folder, cache_path)
                print(f"DEBUG: Completed background auto-training for event {event_name}.")
            except Exception as e:
                print(f"DEBUG: Background training failed: {e}")
                
        bg_thread = threading.Thread(target=train_model)
        bg_thread.daemon = True
        bg_thread.start()
    except Exception as e:
        print(f"DEBUG: Failed to start auto-train thread: {e}")

    if sub_event_id:
        return redirect(url_for('view_sub_album', event_id=event_id, sub_event_id=sub_event_id))
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
    cursor.execute("DELETE FROM sub_events WHERE event_id = ?", (event_id,))
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

    # We could redirect accurately if we checked sub_event_id before closing DB,
    # but for simplicity returning to the event works too.
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

@app.route('/event/<int:event_id>/guests')
def guest_visitors(event_id):
    # Security check: ensure user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Security check: ensure the event belongs to the current user
    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    if not event or event['user_id'] != session['user_id']:
        conn.close()
        return redirect(url_for('dashboard'))

    # Fetch all guest visitors for this event
    cursor.execute("""
        SELECT * FROM guest_users 
        WHERE event_id = ? 
        ORDER BY created_at DESC
    """, (event_id,))
    guests = cursor.fetchall()

    # Also fetch standard event data required by the sidebar
    cursor.execute("SELECT first_name FROM users WHERE id = ?", (session['user_id'],))
    user_row = cursor.fetchone()
    user_first_name = user_row['first_name'] if user_row else 'User'
    
    conn.close()

    return render_template('guest_visitors.html', 
                           event=event, 
                           guests=guests, 
                           event_name=event['event_name'],
                           event_id=event_id,
                           user_first_name=user_first_name)
                           
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
        INSERT INTO guest_users (event_id, email, phone, created_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
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
            INSERT INTO guest_users (event_id, first_name, last_name, email, phone, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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
    session[f'otp_verified_{event_id}'] = True
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
        
        mode = request.args.get('mode', 'public')
        
        if mode == 'private' and not session.get(f'pin_verified_{event_id}'):
            return render_template('verify_pin.html', event=event, event_id=event_id, mode=mode)
            
        return render_template('share_page.html', event=event, photos=photos, event_id=event_id, otp_verified=True, mode=mode)
    
    # Show authentication page
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Fetch event details
    cursor.execute("SELECT event_name, event_date, cover_photo FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()
    
    if event:
        mode = request.args.get('mode', 'public')
        return render_template('auth_page.html', event=event, event_id=event_id, mode=mode)
    else:
        return "Event not found.", 404

@app.route('/auth/event/<int:event_id>/verify_pin', methods=['POST'])
def verify_pin(event_id):
    entered_pin = request.form.get('pin_code', '').strip().upper()
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT pin_code FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()
    
    if event and event[0] == entered_pin:
        session[f'pin_verified_{event_id}'] = True
        return redirect(url_for('auth_event', event_id=event_id, mode='private'))
    
    # Return to the auth route but we should flash an error or pass a pin_error.
    # We will let the verify_pin template handle the error param via the URL.
    return redirect(url_for('auth_event', event_id=event_id, mode='private', error='Invalid Privacy Code'))


@app.route('/share/event/<int:event_id>')
def share_event(event_id):
    # Make the guest's session persistent so they don't have to re-enter details
    session.permanent = True
    
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
        mode = request.args.get('mode', 'public')
        return redirect(url_for('auth_event', event_id=event_id, mode=mode))
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
            
            match_count = result.get('matches_found', 0)
            
            # ---- Save persistent copy for guest visitors tracking ----
            if event_id and session.get(f'guest_info_complete_{event_id}'):
                try:
                    guest_email = session.get(f'guest_email_{event_id}')
                    if guest_email:
                        # Create a persistent copy
                        guest_faces_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'guest_faces')
                        os.makedirs(guest_faces_dir, exist_ok=True)
                        
                        persistent_filename = f"guest_{event_id}_{int(time.time())}_{filename}"
                        persistent_path = os.path.join(guest_faces_dir, persistent_filename)
                        
                        import shutil
                        shutil.copy2(user_photo_path, persistent_path)
                        
                        # Update database
                        conn = sqlite3.connect('database.db')
                        cursor = conn.cursor()
                        
                        # We might have email or phone in the session variable 'guest_email'
                        cursor.execute('''
                            UPDATE guest_users 
                            SET photo_path = ?, matches_found = ?
                            WHERE event_id = ? AND (email = ? OR phone = ?)
                        ''', (persistent_filename, match_count, event_id, guest_email, guest_email))
                        
                        conn.commit()
                        conn.close()
                except Exception as e:
                    app.logger.error(f"Error saving guest profile face: {e}")
            # -------------------------------------------------------------
            
            # Remove temp file
            try:
                os.remove(user_photo_path)
            except:
                pass
                
            return jsonify({
                'status': 'success', 
                'match_count': match_count,
                'matched_files': result.get('matched_files', [])
            })
            
        except Exception as e:
            app.logger.error(f"Error mapping photos: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
        
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
                
            return jsonify({
                'status': 'success', 
                'match_count': result.get('matches_found', 0),
                'matched_files': result.get('matched_files', [])
            })
            
        except Exception as e:
            app.logger.error(f"Error mapping photos: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
            
    return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400

@app.route('/api/event/<int:event_id>/download_zip_api', methods=['POST'])
def download_zip_api(event_id):
    data = request.get_json()
    if not data or 'photos' not in data:
        return jsonify({'status': 'error', 'message': 'No photos specified'}), 400
        
    photos = data.get('photos', [])
    if not photos:
        return jsonify({'status': 'error', 'message': 'Photo list is empty'}), 400

    # Ensure downloads directory exists
    downloads_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    
    # We will search both the event folder and matchphotos folder
    base_dir = os.path.dirname(os.path.abspath(__file__))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT event_name FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()
    
    event_name = event[0] if event else f"event_{event_id}"
    safe_event_name = secure_filename(event_name)
    event_folder = os.path.join(app.config['UPLOAD_FOLDER'], safe_event_name)
    match_folder = os.path.join(base_dir, 'matchphotos')

    # Generate unique zip file
    zip_filename = f"{safe_event_name}_photos_{uuid.uuid4().hex[:8]}.zip"
    zip_path = os.path.join(downloads_dir, zip_filename)

    try:
        # Create ZIP
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for filename in photos:
                # Try event folder first (if they are using a public link viewing all photos)
                file_path = os.path.join(event_folder, filename)
                if not os.path.exists(file_path):
                    # Try match folder (if they are viewing from their private selfie link)
                    file_path = os.path.join(match_folder, filename)
                
                # Check directly in upload dir as fallback
                if not os.path.exists(file_path):
                     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                if os.path.exists(file_path):
                    zipf.write(file_path, arcname=filename)
        
        # Check if zip actually has files
        if os.path.getsize(zip_path) < 100: # Basically empty zip
             os.remove(zip_path)
             return jsonify({'status': 'error', 'message': 'Could not locate photos on server'}), 500

    except Exception as e:
        app.logger.error(f"Error creating zip file: {e}")
        return jsonify({'status': 'error', 'message': 'Error zipping files.'}), 500

    # Construct download URL
    download_url = request.host_url.rstrip('/') + url_for('download_zip', filename=zip_filename)
        
    return jsonify({'status': 'success', 'download_url': download_url, 'filename': zip_filename})

@app.route('/downloads/<filename>')
def download_zip(filename):
    downloads_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'downloads')
    return send_from_directory(downloads_dir, filename, as_attachment=True)


# --- API Route for Favoriting Photos ---
@app.route('/api/toggle_favorite', methods=['POST'])
def toggle_favorite():
    data = request.get_json()
    if not data or 'photo_url' not in data:
        return jsonify({'status': 'error', 'message': 'Photo URL required'}), 400
        
    photo_url = data['photo_url']
    
    # Extract filename from URL
    # URLs might look like /static/uploads/event_name/file.jpg or /matchphotos/file.jpg
    import urllib.parse
    filename = urllib.parse.unquote(photo_url.split('/')[-1])
    
    # Determine source path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    source_path = ""
    
    print(f"DEBUG: toggle_favorite received photo_url: {photo_url}")
    print(f"DEBUG: toggle_favorite parsed filename: {filename}")
    
    if '/static/uploads/' in photo_url:
        # It's an event photo, we need the event_name/filename part
        parts = photo_url.split('/static/uploads/')
        if len(parts) > 1:
            rel_path = urllib.parse.unquote(parts[1])
            source_path = os.path.join(app.config['UPLOAD_FOLDER'], rel_path)
            print(f"DEBUG: toggle_favorite matched /static/uploads/ with rel_path: {rel_path}")
        else:
            source_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(f"DEBUG: toggle_favorite matched /static/uploads/ but no rel_path, using filename: {filename}")
    elif '/matchphotos/' in photo_url:
        source_path = os.path.join(base_dir, 'matchphotos', filename)
        print(f"DEBUG: toggle_favorite matched /matchphotos/ source_path: {source_path}")
    else:
        # Fallback
        source_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(f"DEBUG: toggle_favorite fallback source_path: {source_path}")
        
    print(f"DEBUG: toggle_favorite final source_path: {source_path}")
        
    if not os.path.exists(source_path):
        print(f"DEBUG: toggle_favorite source_path does not exist!")
        return jsonify({'status': 'error', 'message': 'Original photo not found'}), 404
        
    # Setup favorites directory
    # Depending on requirements, this might need to be per-event or per-user
    # For now, creating a global favorites folder
    favorites_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'favorites')
    os.makedirs(favorites_dir, exist_ok=True)
    
    dest_path = os.path.join(favorites_dir, filename)
    
    import shutil
    try:
        # If it's already favorited, we might want to "unfavorite" it by removing it?
        # The prompt says "create one favorite folder in this folder stor only favorite photos"
        # We will assume toggle behavior: if it's there, remove it; if not, copy it.
        is_favorited = data.get('is_favorited', True)
        
        if is_favorited:
            if not os.path.exists(dest_path):
                shutil.copy2(source_path, dest_path)
            return jsonify({'status': 'success', 'message': 'Photo added to favorites', 'action': 'added'})
        else:
            if os.path.exists(dest_path):
                os.remove(dest_path)
            return jsonify({'status': 'success', 'message': 'Photo removed from favorites', 'action': 'removed'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
    app.run(debug=True, port=int(os.environ.get('PORT', '5000')))
