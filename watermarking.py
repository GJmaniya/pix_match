import os

from PIL import Image, ImageOps


DEFAULT_WATERMARK_SETTINGS = {
    'enabled': True,
    'position': 'bottom-right',
    'opacity': 100,
    'size': 20,
    'logo_filename': None,
    'secondary_logo_filename': None,
}

WATERMARK_POSITIONS = {
    'top-left',
    'top-right',
    'bottom-left',
    'bottom-right',
}


def ensure_watermark_settings_table(conn):
    conn.execute('''
        CREATE TABLE IF NOT EXISTS watermark_settings (
            user_id INTEGER PRIMARY KEY,
            logo_filename TEXT,
            secondary_logo_filename TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            position TEXT NOT NULL DEFAULT 'bottom-right',
            opacity INTEGER NOT NULL DEFAULT 100,
            size INTEGER NOT NULL DEFAULT 20,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    columns = [row[1] for row in conn.execute('PRAGMA table_info(watermark_settings)')]
    if 'secondary_logo_filename' not in columns:
        conn.execute('ALTER TABLE watermark_settings ADD COLUMN secondary_logo_filename TEXT')


def get_watermark_settings(conn, user_id):
    ensure_watermark_settings_table(conn)
    row = conn.execute(
        '''
        SELECT logo_filename, secondary_logo_filename, enabled, position, opacity, size
        FROM watermark_settings
        WHERE user_id = ?
        ''',
        (user_id,),
    ).fetchone()
    if row is None:
        return DEFAULT_WATERMARK_SETTINGS.copy()
    return {
        'logo_filename': row[0],
        'secondary_logo_filename': row[1],
        'enabled': bool(row[2]),
        'position': row[3],
        'opacity': row[4],
        'size': row[5],
    }


def get_watermark_logo_path(settings, static_folder, key='logo_filename'):
    filename = settings.get(key)
    if filename:
        return os.path.join(
            static_folder,
            'uploads',
            'watermarks',
            os.path.basename(filename),
        )
    if key == 'logo_filename':
        return os.path.join(static_folder, 'images', 'MM LOGO.png')
    return None


def _resolve_logo_position(base_size, logo_size, position, offset_index=0):
    width, height = base_size
    logo_width, logo_height = logo_size
    padding = max(1, round(min((width, height)) * 0.02))
    positions = {
        'top-left': (padding, padding),
        'top-right': (width - logo_width - padding, padding),
        'bottom-left': (padding, height - logo_height - padding),
        'bottom-right': (width - logo_width - padding, height - logo_height - padding),
    }

    primary_position = positions.get(position, positions['bottom-right'])
    if offset_index == 0:
        return primary_position

    secondary_positions = {
        'top-left': positions['bottom-right'],
        'top-right': positions['bottom-left'],
        'bottom-left': positions['top-right'],
        'bottom-right': positions['top-left'],
    }
    return secondary_positions.get(position, positions['bottom-right'])


def apply_watermark(image, logo_paths, settings):
    if not settings.get('enabled'):
        return image

    if isinstance(logo_paths, (str, os.PathLike)):
        logo_paths = [logo_paths]
    logo_paths = [path for path in logo_paths if path]
    if not logo_paths:
        return image

    image = ImageOps.exif_transpose(image)
    base = image.convert('RGBA')
    size = max(5, min(50, int(settings.get('size', 20))))
    opacity = max(0, min(100, int(settings.get('opacity', 70))))
    padding = max(1, round(min(base.size) * 0.02))
    position = settings.get('position', 'bottom-right')
    if position not in WATERMARK_POSITIONS:
        position = 'bottom-right'

    for index, logo_path in enumerate(logo_paths):
        try:
            with Image.open(logo_path) as logo_file:
                logo = logo_file.convert('RGBA')
        except FileNotFoundError:
            continue

        if logo.width <= 0 or logo.height <= 0 or image.width <= 0 or image.height <= 0:
            continue

        max_width = max(1, base.width - 2 * padding)
        max_height = max(1, min(base.height - 2 * padding, round(base.height * 0.4)))
        scale = min(
            (base.width * size / 100) / logo.width,
            max_width / logo.width,
            max_height / logo.height,
        )
        logo = logo.resize(
            (max(1, round(logo.width * scale)), max(1, round(logo.height * scale))),
            Image.Resampling.LANCZOS,
        )
        alpha = logo.getchannel('A')
        alpha = alpha.point(lambda value: value * opacity // 100)
        logo.putalpha(alpha)

        overlay = Image.new('RGBA', base.size, (0, 0, 0, 0))
        overlay_position = _resolve_logo_position(base.size, logo.size, position, offset_index=index)
        overlay.alpha_composite(logo, overlay_position)
        base = Image.alpha_composite(base, overlay)

    return base.convert('RGB')
