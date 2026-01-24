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
from matcher import FaceMatcher

app = Flask(__name__)
app.secret_key = '123456'

# Initialize FaceMatcher (Global singleton)
# Try to use GPU if available
matcher = FaceMatcher(device_choice='gpu')

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

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id, event_name, event_date FROM events WHERE user_id = ?", (session['user_id'],))
    events = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', 
                           user_first_name=session['first_name'], 
                           events=events)

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
        session['event_details'] = {
            'event_name': request.form['event_name'],
            'event_date': request.form['event_date'],
            'event_venue': request.form['event_venue'],
            'event_category': request.form['event_category']
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
            INSERT INTO events (user_id, event_name, event_date, venue, category, privacy)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], details['event_name'], details['event_date'],
              details['event_venue'], details['event_category'], privacy_setting))
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
    cursor.execute("SELECT event_name FROM events WHERE id = ? AND user_id = ?", (event_id, session['user_id']))
    event = cursor.fetchone()
    conn.close()
    if event:
        return render_template('add_album.html', event_name=event[0], event_id=event_id)
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
    
    files = request.files.getlist('photos')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cursor.execute("INSERT INTO photos (event_id, filename) VALUES (?, ?)", (event_id, filename))
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


# --- Add this new route for the public, shareable event page ---

@app.route('/share/event/<int:event_id>')
def share_event(event_id):
    conn = sqlite3.connect('database.db')
    # Use row_factory to get results as dictionaries for easy access in the template
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()

    # Fetch event details including privacy setting
    cursor.execute("SELECT event_name, privacy FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()

    # Fetch all photos for this event
    cursor.execute("SELECT filename FROM photos WHERE event_id = ?", (event_id,))
    photos = cursor.fetchall()
    
    conn.close()

    if event:
        # We will create a new template for this public page
        return render_template('share_page.html', event=event, photos=photos)
    else:
        # If the event doesn't exist, show a "Not Found" error
        return "Event not found.", 404
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
        # Using Bhuman as the source directory as identified
        base_dir = os.path.dirname(os.path.abspath(__file__))
        search_dir = os.path.join(base_dir, 'Bhuman') 
        match_output_dir = os.path.join(base_dir, 'matchphotos')
        
        # Run matching
        try:
            # We can run this in a thread if we want to return immediately, 
            # but for a simple API usually we wait for result or return a job ID.
            # Given the requirement "process Final.py ... add in matchphotos folder",
            # We'll wait and return the summary.
            
            result = matcher.find_matches(
                user_photo_path, 
                search_dir, 
                match_output_dir,
                tolerance=0.5
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
@app.route('/matchphotos/<filename>')
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