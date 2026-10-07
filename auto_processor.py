import time
import os
import sqlite3
import threading
from werkzeug.utils import secure_filename
from PIL import Image
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watermarking import apply_watermark, get_watermark_logo_path, get_watermark_settings

# You must have matcher initialized to run embeddings
from matcher import FaceMatcher

print("Initializing Face Matcher for Auto-Processing...")
matcher = FaceMatcher(device_choice='gpu') # Use GPU if available
print("Matcher Ready.")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'database.db')

class PhotoUploadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        # Check if the file is an image
        if event.src_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            print(f"\\n[WATCHER] Detected new incoming file: {event.src_path}")
            
            # Wait a brief moment to ensure the Wi-Fi sync app has finished writing the file completely
            time.sleep(1.5)
            
            self.process_new_photo(event.src_path)

    def process_new_photo(self, filepath):
        try:
            # 1. Determine which Event folder this was dropped into
            rel_path = os.path.relpath(filepath, UPLOADS_DIR)
            folder_parts = rel_path.split(os.sep)
            
            if len(folder_parts) < 2:
                print(f"[WATCHER] File not in a specific event directory, skipping: {rel_path}")
                return
                
            event_name = folder_parts[0]
            filename = folder_parts[-1]
            
            print(f"[WATCHER] Processing photo '{filename}' for event '{event_name}'...")
            
            # 2. Get Event ID from Database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, user_id FROM events WHERE event_name = ?",
                (event_name,),
            )
            event_row = cursor.fetchone()
            
            if not event_row:
                print(f"[WATCHER] Unregistered event folder '{event_name}'. Skipping.")
                conn.close()
                return
                
            event_id, user_id = event_row
            watermark_settings = get_watermark_settings(conn, user_id)
            watermark_logo_path = get_watermark_logo_path(
                watermark_settings,
                os.path.join(BASE_DIR, 'static'),
                key='logo_filename',
            )
            if (
                watermark_settings['enabled']
                and watermark_settings['logo_filename']
                and not os.path.isfile(watermark_logo_path)
            ):
                print(f"[WATCHER] Configured watermark logo is missing for user {user_id}.")
                conn.close()
                return
            
            # Check if photo is already in database (maybe it was uploaded via website)
            db_rel_path = f"{event_name}/{filename}"
            # If there is a subevent
            if len(folder_parts) > 2:
                 db_rel_path = f"{event_name}/{folder_parts[1]}/{filename}"
                 
            cursor.execute("SELECT id FROM photos WHERE filename = ?", (db_rel_path,))
            if cursor.fetchone():
                print(f"[WATCHER] Photo '{filename}' already in database. Skipping.")
                conn.close()
                return

            # 3. Apply the account's configured watermark.
            try:
                with Image.open(filepath) as original:
                    img = apply_watermark(
                        original,
                        watermark_logo_path,
                        watermark_settings,
                    )
                    if watermark_settings['enabled'] and os.path.isfile(watermark_logo_path):
                        img.save(filepath, quality=90)
                        print(f"[WATCHER] Configured watermark applied to {filename}.")
            except Exception as e:
                print(f"[WATCHER] Failed to apply watermark to {filename}: {e}")
                conn.close()
                return

            # 4. Insert into Database
            sub_event_id = None
            if len(folder_parts) > 2:
                 sub_folder_name = folder_parts[1]
                 cursor.execute("SELECT id FROM sub_events WHERE event_id = ? AND name = ?", (event_id, sub_folder_name))
                 sub_row = cursor.fetchone()
                 if sub_row:
                     sub_event_id = sub_row[0]

            if sub_event_id:
                cursor.execute("INSERT INTO photos (event_id, sub_event_id, filename) VALUES (?, ?, ?)", (event_id, sub_event_id, db_rel_path))
            else:
                cursor.execute("INSERT INTO photos (event_id, filename) VALUES (?, ?)", (event_id, db_rel_path))

            conn.commit()
            conn.close()
            print(f"[WATCHER] Photo {filename} registered in database successfully.")

            # 5. Background ML Training
            event_folder = os.path.dirname(filepath)
            cache_path = os.path.join(event_folder, "embeddings_cache.pt")
            
            def train_model():
                try:
                    print(f"\\n[ML-TRAINING] Extracting faces for new photo '{filename}'...")
                    matcher.load_or_compute_directory_embeddings(event_folder, cache_path)
                    print(f"[ML-TRAINING] Done! Ready for matching.")
                except Exception as e:
                    print(f"[ML-TRAINING] Error extracting faces: {e}")

            # Run in a separate thread so the watcher can immediately look for the next photo
            bg_thread = threading.Thread(target=train_model)
            bg_thread.daemon = True
            bg_thread.start()

        except Exception as e:
            print(f"[WATCHER] Fatal error processing {filepath}: {e}")

if __name__ == "__main__":
    if not os.path.exists(UPLOADS_DIR):
        print(f"Creating missing uploads directory: {UPLOADS_DIR}")
        os.makedirs(UPLOADS_DIR, exist_ok=True)
        
    event_handler = PhotoUploadHandler()
    observer = Observer()
    observer.schedule(event_handler, UPLOADS_DIR, recursive=True)
    
    print(f"\\n================================================")
    print(f"    PixMatch Auto-Processor Started!")
    print(f"    Watching directory: {UPLOADS_DIR}")
    print(f"    Any photos synced here over Wi-Fi will be automatically watermarked and processed.")
    print(f"================================================\\n")
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
