# Security changes

Every problem found in the security review was fixed. Fixes marked **(verified)** were
reproduced against the old code and re-tested after the fix.

| # | Severity | Problem | Fix |
|---|----------|---------|-----|
| 1 | High | Event folder came from the event name and names were not unique, so two users with the same event name shared one folder (could view, overwrite, delete each other's photos) **(verified)** | Every new event gets a unique folder (`<name>_<random>`) stored in `events.folder_name`. Existing events keep their current folder (migration runs automatically). Deleting an event now also removes its folder and face-embedding cache. |
| 2 | High | Names such as `શાદી` or `???` sanitise to an empty folder, so photos were written into the shared uploads root **(verified)** | Same fix as #1: the folder name always has a prefix and a random suffix, never empty. |
| 3 | Medium | `/admin` login had no brute-force protection **(verified)** | 5 failed attempts per IP and 30 in total per 15 minutes, then HTTP 429. Non-ASCII usernames no longer crash the login. |
| 4 | Medium | Rate limits lived in process memory, so with several gunicorn workers each worker had its own counter | Counters are now stored in a small SQLite file (`private_data/rate_limits.db`) shared by all workers. Falls back to memory if the file is unavailable. |
| 5 | Medium | `torch.load(..., weights_only=False)` on the embeddings cache (pickle = code execution if the file is tampered with) | Cache is now `embeddings_cache.npz`, loaded with `numpy.load(allow_pickle=False)` and written atomically. Old `.pt` caches are ignored and removed; embeddings are recomputed once per event. |
| 6 | Low | Cover photo was saved as raw bytes after an extension check only | Cover photos are validated and re-encoded with Pillow (strips EXIF/GPS and any appended payload). |
| 7 | Low | `requests.get` to Google had no timeout | `timeout=10` |
| 8 | Low | No CSP header; server messages were inserted with `innerHTML` | Added `Content-Security-Policy: base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'`. Error messages are rendered with `textContent`. |
| 9 | Low | CSRF check was skipped when no `Origin`/`Referer` was sent; `/logout` could be triggered from another site | POSTs without `Origin`/`Referer` now need `Sec-Fetch-Site: same-origin` (override for curl/tests: `ALLOW_MISSING_ORIGIN=1`). Cross-site `GET /logout` and `/admin/logout` are ignored. |
| 10 | Low | `requirements.txt` was completely unpinned | Bounded version ranges, plus `requirements-hardened.txt` (see below). |

### Additional problems found while fixing

* **delete_folder IDOR (High, verified):** a logged-in user could delete another user's sub-folder photos by sending their own `event_id` with someone else's `sub_event_id`. The folder must now belong to the event.
* **Upload into someone else's sub-folder (Medium):** `sub_event_id` on upload is now checked against the event.
* **Photos overwriting each other / non-ASCII file names (Medium):** uploads get a unique file name; `ફોટો.jpg` used to be saved as `jpg` with no extension.
* **500 errors on non-ASCII tokens/PINs (Low):** every `secrets.compare_digest` on user input now goes through a Unicode-safe helper.
* **File deletion hardening:** every deletion goes through `safe_join` (cannot leave the uploads folder).
* **Inconsistent DB path:** all code now uses the absolute `DB_PATH` (a relative `database.db` could silently create a second, empty database when started from another directory).
* **Input limits:** event name (120), venue, category, date, sub-folder name (80); compression quality is clamped to 1-100.
* **`watchdog` was missing from requirements** although `auto_processor.py` needs it.

### Dependencies (important)

`facenet-pytorch 2.6.0` forces **Pillow < 10.3** and **torch < 2.3**. `pip-audit` reports
about 29 known vulnerabilities in Pillow 10.2.0 (this app parses untrusted uploaded images)
and about 23 in torch 2.2.2. For production use the hardened set:

```bash
pip install -r requirements-hardened.txt
pip install --no-deps facenet-pytorch==2.6.0
python smoke_test_models.py      # must print: MODEL SMOKE TEST OK
```

If the smoke test fails on your machine, use `requirements.txt` instead and re-run
`pip-audit` regularly.

### Deployment checklist

```bash
# production environment (.env or host dashboard)
APP_ENV=production
SECRET_KEY=<64 random hex chars>
TRUST_PROXY=1                    # behind Render/Railway/Nginx
ADMIN_USERNAME=...  ADMIN_PASSWORD=<long random password>

gunicorn -w 2 --threads 4 -b 0.0.0.0:$PORT app:app
```

* After upgrading, delete old caches if you want: `find static/uploads -name embeddings_cache.pt -delete`.
* If two of your existing events had the same name, their photos are already mixed in one
  folder. The app logs a warning for each such folder at start-up; move those photos manually.
* Back up `database.db` and `static/uploads/` regularly (free hosts often have ephemeral disks).

### Still recommended (not changed automatically)

* Add Subresource Integrity (`integrity="sha384-..." crossorigin="anonymous"`) to the three
  cdnjs `<script>` tags in `templates/share_page.html`, or self-host those files.
* A strict `script-src` CSP needs the inline `<script>` blocks moved into `.js` files first.
* Turn on GitHub secret scanning and Dependabot for the repository.
