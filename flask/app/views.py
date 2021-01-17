from app import app, db
from flask import render_template, request, session, redirect, url_for
from .models import UsersModel, PrivNotesModel, PublicNotesModel, SharedNotesModel, KnownDevicesModel, BlockedDevicesModel
import re
import crypt
from hmac import compare_digest
from math import log2
from datetime import datetime, timedelta
import time


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
                    db.session.add(UsersModel(username, crypt.crypt(password)))
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
        files = ["file", "file", "file"]
        return render_template("dashboard.html", status=request.args.get('status'), priv_notes=priv_notes, files=files, public_notes=public_notes, shared_notes=shared_notes)
    return redirect(url_for("index", status="not logged"))

@app.route("/add/note", methods=["POST"])
def add_note():
    note_type, content = request.form["note-type"], request.form["note-input"]
    if note_type == "private":
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