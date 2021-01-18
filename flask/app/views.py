from app import app, db
from flask.helpers import send_file
from flask import render_template, request, session, redirect, url_for
from .models import FilesModel, UsersModel, PrivNotesModel, PublicNotesModel, SharedNotesModel, KnownDevicesModel, BlockedDevicesModel
from math import log2
from hmac import compare_digest
from datetime import datetime, timedelta
import os
import re
import time
import uuid
import crypt
import unicodedata

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def aes_encrypt(secret_password, content):
    salt_bytes = get_random_bytes(8)
    key = PBKDF2(secret_password, salt_bytes, 32, count=2000000)
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(content.encode())
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    salt = b64encode(salt_bytes).decode('utf-8')
    return ct, nonce, salt

def aes_decrypt(secret_password, ct, nonce, salt):
    try:
        key = PBKDF2(secret_password, b64decode(salt), 32, count=2000000)
        cipher = AES.new(key, AES.MODE_CTR, nonce=b64decode(nonce))
        pt = cipher.decrypt(b64decode(ct))
        return pt.decode("utf-8")
    except ValueError:
        return None


import logging
from flask.logging import default_handler

formatter = logging.Formatter(  # pylint: disable=invalid-name
    '%(asctime)s %(levelname)s %(process)d ---- %(threadName)s  '
    '%(module)s : %(funcName)s {%(pathname)s:%(lineno)d} %(message)s','%Y-%m-%dT%H:%M:%SZ')

handler = logging.StreamHandler()
handler.setFormatter(formatter)

app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(handler)
app.logger.removeHandler(default_handler)

allowed_extensions = [".png", ".jpg", ".jpeg", ".pdf", ".txt", ".doc", ".docx", ".xml"]

@app.after_request
def set_header(resp):
    resp.headers['Server'] = 'unknown'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com"
    return resp

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        now = datetime.now()
        time.sleep(1)
        ip=request.access_route[0]
        blocked_ip = BlockedDevicesModel.query.filter_by(device_ip=ip).first()
        if blocked_ip and blocked_ip.ban_exp_time and blocked_ip.ban_exp_time > now:
            return render_template("index.html", exp=(blocked_ip.ban_exp_time + timedelta(hours=1)).strftime("%H:%M:%S %d/%m/%Y"))
        username, password = request.form["username"], request.form["password"]
        rule = re.compile(r"""^[^<>'"\/;`%-]{1,30}$""")
        if rule.match(username) and rule.match(password):
            if username == "admin1" and password == "password123":
                if not blocked_ip:
                    blocked_ip = BlockedDevicesModel(ip)
                blocked_ip.ban_exp_time = now + timedelta(days=365)
                db.session.add(blocked_ip)
                db.session.commit()
                app.logger.warning(f'Someone logged on honeypot account. Host ip: {ip}')
                return f"<h2>U tried to sign in admin account that was a honeypot. This incident will be reported.</h2>"

            user = UsersModel.query.filter_by(username=username).all()
            if user:
                if compare_digest(crypt.crypt(password, user[0].password), user[0].password):
                    if blocked_ip:
                        blocked_ip.tries = 0
                        db.session.commit()
                    session["username"] = username
                    session["uid"] = user[0].id
                    session.permanent = True
                    if not KnownDevicesModel.query.filter_by(device_ip=ip).first():
                        db.session.add(KnownDevicesModel(ip, user[0].id))
                        db.session.commit()
                        return redirect(url_for("dashboard", status="new device"))
                    return redirect(url_for("dashboard"))
            if blocked_ip:
                blocked_ip.tries += 1
            else:
                blocked_ip = BlockedDevicesModel(ip)
                db.session.add(blocked_ip)
            if blocked_ip.tries >= 3 and blocked_ip.tries < 5:
                blocked_ip.ban_exp_time = now + timedelta(seconds=30)
            elif blocked_ip.tries >= 5 and blocked_ip.tries < 10:
                blocked_ip.ban_exp_time = now + timedelta(minutes=2)
            elif blocked_ip.tries >= 10:
                blocked_ip.ban_exp_time = now + timedelta(minutes=30)
            db.session.commit()
        return render_template("index.html", status="failed")
    else:
        if 'username' in session:
            return redirect(url_for("dashboard"))
        return render_template("index.html")


@app.route("/registration", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form["username"], request.form["password"]
        rule = re.compile(r"""^[^<>'"\/;`%-]{1,30}$""")
        if rule.match(username) and rule.match(password):
            if get_entropy(password) > 3 and get_pass_strength(password) > 50:
                if not UsersModel.query.filter_by(username=username).first():
                    db.session.add(UsersModel(username, crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512, rounds=3000000))))
                    db.session.commit()
                    return render_template("register.html", status="success")
                else:
                    return render_template("register.html", status="username taken")
            else:
                return render_template("register.html", status="weak password")
        else:
            return render_template("register.html", status="failed")
    else:
        if 'username' in session:
            return redirect(url_for("dashboard"))  
        return render_template("register.html", status=request.args.get('status'))


@app.route("/logout")
def logout():
    if 'username' in session:
        session.pop('username')
    return redirect(url_for("index"))


@app.route("/dashboard", methods=['GET'])
def dashboard():
    if 'username' in session:
        user = UsersModel.query.filter_by(username=session['username']).first_or_404()
        priv_notes = PrivNotesModel.query.filter_by(user_id=user.id).all()
        public_notes = PublicNotesModel.query.all()
        shared_notes = SharedNotesModel.query.filter((SharedNotesModel.author_id == user.id) | (SharedNotesModel.reciepment_id == user.id)).all()
        files = FilesModel.query.filter_by(user_id=user.id).all()
        return render_template("dashboard.html", status=request.args.get('status'), priv_notes=priv_notes, files=files, public_notes=public_notes, shared_notes=shared_notes)
    return redirect(url_for("index", status="not logged"))

@app.route("/add/note", methods=["POST"])
def add_note():
    if 'username' in session:
        note_type, content = request.form["note-type"], request.form["note-input"]
        if note_type == "private":
            encrypted = request.form.get('encrypted')
            if encrypted:
                content = unicodedata.normalize('NFKD', content).encode('ascii', 'ignore').decode()
                secret_password = request.form.get('note-password')
                if not secret_password or not re.match(r"^[a-zA-Z0-9_]*$", secret_password):
                    return redirect(url_for("dashboard", status="password error"))
                encrypted_content, nonce, salt = aes_encrypt(secret_password, content)
                priv_enc_note = PrivNotesModel(encrypted_content, session['uid'])
                db.session.add(priv_enc_note)
                priv_enc_note.nonce = nonce
                priv_enc_note.salt = salt
                db.session.commit()
                return redirect(url_for("dashboard"))
            else:
                db.session.add(PrivNotesModel(content, session['uid']))
                db.session.commit()
                return redirect(url_for("dashboard"))
        elif note_type == "public":
            db.session.add(PublicNotesModel(content))
            db.session.commit()
            return redirect(url_for("dashboard"))
        elif note_type == "shared":
            recipient = UsersModel.query.filter_by(username=request.form["recipient"]).first()
            if recipient:
                db.session.add(SharedNotesModel(content, session["uid"], recipient.id))
                db.session.commit()
                return redirect(url_for("dashboard"))
            return redirect(url_for("dashboard", status="user not found"))
        return "Note type not provided or invalid", 404
    return redirect(url_for("index"))

@app.route("/add/file", methods=["POST"])
def add_file():
    if 'username' in session:
        file_id = uuid.uuid4().hex
        upload_file = request.files["file-input"]
        file_extension = os.path.splitext(upload_file.filename)[1]
        if file_extension in allowed_extensions:
            upload_file.save(os.path.join(app.config["UPLOAD_FOLDER"], file_id + file_extension))
            db.session.add(FilesModel(file_id, upload_file.filename, session['uid']))
            db.session.commit()
            return redirect(url_for("dashboard"))
    return redirect(url_for("index"))

@app.route("/decrypt", methods=["POST"])
def decrypt_note():
    if 'username' in session:
        secret_password, content = request.form["note-password"], request.form["note-input"]
        if not secret_password or not re.match(r"^[a-zA-Z0-9_]*$", secret_password):
                    return redirect(url_for("dashboard", status="password error"))
        note = PrivNotesModel.query.filter((PrivNotesModel.user_id == session['uid']) & (PrivNotesModel.nonce != None) & (PrivNotesModel.salt != None) & (PrivNotesModel.content == content)).first()
        if note:
            decrypted_content = aes_decrypt(secret_password, content, note.nonce, note.salt)
            if decrypted_content:
                note.content = decrypted_content
                note.nonce, note.salt = None, None
                db.session.commit()
                return redirect(url_for("dashboard"))
        return redirect(url_for("dashboard", status="note not found"))
    return redirect(url_for("index"))

@app.route("/file/<string:file_uid>", methods=["GET"])
def get_file(file_uid):
    if 'username' in session:
        file = FilesModel.query.filter_by(file_uid=file_uid).first_or_404()
        if file.user_id == session['uid']:
            filename = file_uid + os.path.splitext(file.filename)[1]
            return send_file(os.path.join("upload_files/", filename), attachment_filename=filename)
    return redirect(url_for("index"))

def get_entropy(string):
    counts = {}
    entropy = 0
    for char in string:
        if char in counts:
            counts[char] += 1
        else:
            counts[char] = 1
    L = sum(counts.values())
    for c in counts:
        entropy -= counts[c] / L * log2(counts[c] / L)
    
    return entropy

def get_pass_strength(string):
    charset_range = 0
    if re.match(r".*[a-z].*", string):
        charset_range += 26
    if re.match(r".*[A-Z].*", string):
        charset_range += 26
    if re.match(r".*[0-9].*", string):
        charset_range += 10
    if re.match(r".*[\W].*", string):
        charset_range += 33
    if any(ord(c) > 128 for c in string):
        charset_range = 137993
    
    strength = log2(charset_range**len(string))
    return strength