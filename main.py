import os
import json
import hashlib
import time
from flask import (
    Flask, render_template, request, redirect, url_for, flash, 
    send_from_directory, session
)

app = Flask(__name__)
app.secret_key = "a-very-secret-key"

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "files")
DATA_JSON = os.path.join(BASE_DIR, "file_data.json")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DEFAULT_ADMIN_PASS = "1234"
DEFAULT_MAX_FILE_SIZE_MB = 100
DEFAULT_MAX_UPLOADS_PER_IP = 5

def hash_pw(pw):
    # Simple SHA-256 for demonstration (use stronger hashing in production!)
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def now():
    return int(time.time())

def load_json():
    if not os.path.isfile(DATA_JSON):
        # Initialize with default admin key if config missing
        return {
            "_admin": {
                "pw_hash": hash_pw(DEFAULT_ADMIN_PASS)
            }
        }
    with open(DATA_JSON, "r") as f:
        return json.load(f)

def save_json(data):
    with open(DATA_JSON, "w") as f:
        json.dump(data, f, indent=2)

def get_admin_hash(json_data=None):
    json_data = json_data or load_json()
    pw_hash = json_data.get("_admin", {}).get("pw_hash", "")
    if pw_hash == "" or pw_hash is None:
        # If hash is empty or missing, reset to default
        default_hash = hash_pw(DEFAULT_ADMIN_PASS)
        set_admin_hash(default_hash)
        return default_hash
    return pw_hash

def set_admin_hash(new_hash):
    json_data = load_json()
    json_data["_admin"] = {"pw_hash": new_hash}
    save_json(json_data)

def admin_logged_in():
    return session.get("admin") == True

def admin_required(f):
    from functools import wraps
    def decorated(*args, **kwargs):
        if not admin_logged_in():
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wraps(f)(decorated)

def get_settings(json_data=None):
    json_data = json_data or load_json()
    settings = json_data.get("_settings", {})
    if "max_file_size" not in settings:
        settings["max_file_size"] = DEFAULT_MAX_FILE_SIZE_MB
    if "max_uploads_per_ip" not in settings:
        settings["max_uploads_per_ip"] = DEFAULT_MAX_UPLOADS_PER_IP
    return settings

def set_settings(new_settings):
    json_data = load_json()
    json_data["_settings"] = new_settings
    save_json(json_data)

def log_upload(ip):
    """Log a timestamp for this IP's upload"""
    json_data = load_json()
    logs = json_data.get("_upload_log", {})
    t = now()
    logs.setdefault(ip, []).append(t)
    # Purge entries older than 24h
    logs[ip] = [ts for ts in logs[ip] if t - ts < 24*3600]
    json_data["_upload_log"] = logs
    save_json(json_data)

def count_uploads_last_24h(ip):
    """Returns count of uploads for this IP in last 24h"""
    json_data = load_json()
    logs = json_data.get("_upload_log", {})
    t = now()
    if ip not in logs:
        return 0
    # Remove old entries from log
    logs[ip] = [ts for ts in logs[ip] if t - ts < 24*3600]
    json_data["_upload_log"] = logs
    save_json(json_data)
    return len(logs[ip])

@app.route("/", methods=["GET", "POST"])
def index():
    json_data = load_json()
    settings = get_settings(json_data)
    max_file_size = settings.get("max_file_size", DEFAULT_MAX_FILE_SIZE_MB)
    max_uploads_per_ip = settings.get("max_uploads_per_ip", DEFAULT_MAX_UPLOADS_PER_IP)
    if request.method == "POST":
        custom_url = request.form.get("custom_url", "").strip()
        file = request.files.get("file")
        if not custom_url or "/" in custom_url or "\\" in custom_url:
            flash("Please provide a valid custom URL (no slashes or backslashes).")
            return redirect(url_for("index"))
        if not file:
            flash("Please choose a file to upload.")
            return redirect(url_for("index"))
        # Enforce file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        if file_length > max_file_size * 1024 * 1024:
            flash(f"File too large! Limit: {max_file_size} MB.", "error")
            return redirect(url_for("index"))
        # Enforce per-IP upload limit
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        uploads = count_uploads_last_24h(ip)
        if uploads >= max_uploads_per_ip:
            flash(f"Upload limit reached: {max_uploads_per_ip} files per 24 hours.", "error")
            return redirect(url_for("index"))
        json_data = load_json()
        if custom_url in json_data:
            flash("Custom URL already exists. Choose another.")
            return redirect(url_for("index"))
        if custom_url.startswith("_"):
            flash("Custom URL can't start with '_'")
            return redirect(url_for("index"))
        filename = file.filename
        # Each file in its own subdir
        upload_subdir = os.path.join(UPLOAD_FOLDER, custom_url)
        os.makedirs(upload_subdir, exist_ok=True)
        save_path = os.path.join(upload_subdir, filename)
        file.save(save_path)
        # Save metadata
        json_data[custom_url] = {
            "filename": filename,
            "save_dir": upload_subdir,
            "url": f"/file/{custom_url}",
            "original_filename": filename,
            "downloads": 0
        }
        save_json(json_data)
        log_upload(ip)
        flash(f"File uploaded! Access it at /file/{custom_url}")
        return redirect(url_for("index"))
    return render_template("index.html", max_file_size=max_file_size, max_uploads_per_ip=max_uploads_per_ip)

@app.route("/file/<custom_url>")
def get_file(custom_url):
    json_data = load_json()
    file_entry = json_data.get(custom_url)
    if not file_entry:
        flash("File not found.")
        return redirect(url_for("index"))
    # Increment download count
    if "downloads" not in file_entry:
        file_entry["downloads"] = 0
    file_entry["downloads"] += 1
    json_data[custom_url] = file_entry
    save_json(json_data)
    directory = os.path.join(UPLOAD_FOLDER, custom_url)
    filename = file_entry["original_filename"]
    return send_from_directory(directory, filename, as_attachment=True)

# --- Admin authentication and dashboard ---

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if admin_logged_in():
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        password = request.form.get("password", "")
        json_data = load_json()
        pw_hash = get_admin_hash(json_data)  # will reset blank to default automatically
        if hash_pw(password) == pw_hash:
            session["admin"] = True
            flash("Logged in as admin.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid password.", "error")
    return render_template("admin.html", mode="login")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    flash("Logged out.", "success")
    return redirect(url_for("admin_login"))

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    data = load_json()
    files = []
    for k, v in data.items():
        if not k.startswith("_"):
            entry = dict(v)
            entry["custom_url"] = k
            if "url" not in entry:
                entry["url"] = f"/files/{k}"
            files.append(entry)
    return render_template("admin.html", mode="dashboard", files=files)

@app.route("/admin/delete/<custom_url>", methods=["POST"])
@admin_required
def admin_delete(custom_url):
    data = load_json()
    entry = data.get(custom_url)
    if entry:
        # Delete file and subfolder
        dir_path = os.path.join(UPLOAD_FOLDER, custom_url)
        try:
            os.remove(os.path.join(dir_path, entry["original_filename"]))
            os.rmdir(dir_path) # Remove empty directory
        except Exception:
            pass  # Ignore errors for now
        del data[custom_url]
        save_json(data)
        flash("File/link deleted.", "success")
    else:
        flash("No such file.", "error")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/rename/<custom_url>", methods=["POST"])
@admin_required
def admin_rename(custom_url):
    data = load_json()
    entry = data.get(custom_url)
    new_url = request.form.get("new_url", "").strip()
    if not entry or not new_url or "/" in new_url or "\\" in new_url:
        flash("Invalid or blank new URL.", "error")
        return redirect(url_for("admin_dashboard"))
    if new_url in data:
        flash("Custom URL already exists.", "error")
        return redirect(url_for("admin_dashboard"))
    # Move directory
    old_path = os.path.join(UPLOAD_FOLDER, custom_url)
    new_path = os.path.join(UPLOAD_FOLDER, new_url)
    os.rename(old_path, new_path)
    entry["save_dir"] = new_path
    entry["url"] = f"/file/{new_url}"
    # Move in JSON
    data[new_url] = entry
    del data[custom_url]
    save_json(data)
    flash("URL renamed.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/config", methods=["GET", "POST"])
@admin_required
def admin_config():
    json_data = load_json()
    settings = get_settings(json_data)
    max_file_size = settings.get("max_file_size", DEFAULT_MAX_FILE_SIZE_MB)
    max_uploads_per_ip = settings.get("max_uploads_per_ip", DEFAULT_MAX_UPLOADS_PER_IP)

    if request.method == "POST":
        # Handle password change/reset
        new_pass = request.form.get("new_pass", "")
        if new_pass:
            new_hash = hash_pw(new_pass)
            flash("Admin password updated.", "success")
            set_admin_hash(new_hash)
        # Handle settings
        try:
            new_max_file_size = int(request.form.get("max_file_size", max_file_size))
            if new_max_file_size < 1: raise ValueError
        except ValueError:
            new_max_file_size = max_file_size
            flash("Invalid file size, keeping previous value.", "error")
        try:
            new_max_uploads = int(request.form.get("max_uploads_per_ip", max_uploads_per_ip))
            if new_max_uploads < 0: raise ValueError
        except ValueError:
            new_max_uploads = max_uploads_per_ip
            flash("Invalid per-IP upload quota, keeping previous value.", "error")
        # Update settings
        set_settings({
            "max_file_size": new_max_file_size,
            "max_uploads_per_ip": new_max_uploads
        })
        flash("Settings updated.", "success")
        return redirect(url_for("admin_config"))
    return render_template("admin.html", mode="config", max_file_size=max_file_size, max_uploads_per_ip=max_uploads_per_ip)

if __name__ == "__main__":
    app.run()
