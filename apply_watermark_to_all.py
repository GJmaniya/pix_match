import sqlite3
import os
import io
from PIL import Image, ImageOps

# Paths
DB_PATH = 'database.db'
UPLOAD_FOLDER = 'static/uploads'
LOGO_PATH = 'static/images/MM LOGO.png'

def main():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database {DB_PATH} not found.")
        return
    
    if not os.path.exists(LOGO_PATH):
        print(f"Error: Watermark logo {LOGO_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Load the logo once
        logo = Image.open(LOGO_PATH)
    except Exception as e:
        print(f"Failed to load logo: {e}")
        return

    # Fetch all photos
    cursor.execute("SELECT id, filename FROM photos")
    photos = cursor.fetchall()
    
    if not photos:
        print("No photos found in database.")
        conn.close()
        return

    success_count = 0
    fail_count = 0

    for photo_id, relative_path in photos:
        # The filename in the DB typically includes the event folder: event_name/photo.jpg
        full_path = os.path.join(UPLOAD_FOLDER, relative_path)
        
        if not os.path.exists(full_path):
            print(f"Warning: Photo not found on disk: {full_path}")
            fail_count += 1
            continue
            
        try:
            # We process the image
            img = Image.open(full_path)
            img = ImageOps.exif_transpose(img)
            
            # Since we're retroactively watermarking, we have to re-save. 
            # We don't know the exact original quality, so we'll guess 95 for high quality
            
            # Convert if necessary
            if img.mode in ('RGBA', 'P', 'LA'):
                 img = img.convert('RGB')
                 
            # Calculate watermark size (20% of the main image width)
            wm_width = int(img.width * 0.20)
            wm_ratio = wm_width / float(logo.width)
            wm_height = int(float(logo.height) * float(wm_ratio))
            
            # Resize temp logo for this specific image size
            temp_logo = logo.resize((wm_width, wm_height), Image.Resampling.LANCZOS)
            
            # Calculate position (bottom right corner with padding)
            padding = int(img.width * 0.02) # 2% padding
            position = (img.width - wm_width - padding, img.height - wm_height - padding)
            
            # Paste the logo
            if img.mode != 'RGBA':
                temp_img = img.convert('RGBA')
                temp_img.paste(temp_logo, position, temp_logo)
                img = temp_img.convert('RGB')
            else:
                img.paste(temp_logo, position, temp_logo)
            
            # Overwrite the original file with the watermarked one
            img.save(full_path, quality=95)
            
            print(f"Success: Watermarked {relative_path}")
            success_count += 1
            
        except Exception as e:
            print(f"Error: Failed to process {relative_path}. Reason: {e}")
            fail_count += 1

    conn.close()
    print(f"\n--- Summary ---")
    print(f"Total processed: {len(photos)}")
    print(f"Successfully watermarked: {success_count}")
    print(f"Failed/Skipped: {fail_count}")

if __name__ == '__main__':
    main()
