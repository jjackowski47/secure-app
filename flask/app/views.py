from app import app, db
from flask import render_template, request, session, redirect, url_for
from .models import UsersModel, PrivNotesModel, PublicNotesModel, SharedNotesModel
import re
import crypt
from hmac import compare_digest

@app.after_request
def set_header(resp):
    resp.headers['Server'] = 'unknown'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com"
    return resp

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username, password = request.form["username"], request.form["password"]
        rule = re.compile(r"""^[^<>'"\/;`%-]{1,30}$""")
        if rule.match(username) and rule.match(password):
            user = UsersModel.query.filter_by(username=username).all()
            if user:
                if compare_digest(crypt.crypt(password, user[0].password), user[0].password):
                    session["username"] = username
                    session.permanent = True
                    return redirect(url_for("dashboard"))
        return render_template("index.html", status="failed")
    else:
        return render_template("index.html")


@app.route("/registration", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form["username"], request.form["password"]
        rule = re.compile(r"""^[^<>'"\/;`%-]{1,30}$""")
        if rule.match(username) and rule.match(password):
            db.session.add(UsersModel(username, crypt.crypt(password)))
            db.session.commit()
            return render_template("register.html", status="success")
        else:
            return render_template("register.html", status="failed")
    else:
        return render_template("register.html", status=request.args.get('status'))


@app.route("/logout")
def logout():
    if 'username' in session:
        session.pop('username')
    return redirect(url_for("index"))


@app.route("/dashboard", methods=['GET'])
def dashboard():
    if 'username' in session:
        notes = ['test1', 'test2', "test3"]

        return render_template("dashboard.html", priv_notes=notes, files=notes, public_notes=notes, shared_notes=notes,)
    return redirect(url_for("index", status="not logged"))

@app.route("/add/note", methods=["POST"])
def add_note():
    note_type, content = request.form["note-type"], request.form["note-input"]
    if note_type == "shared":
        recipient = request.form["recipient"]
        return f"{note_type}, {content}, {recipient}", 200
    return f"{note_type}, {content}", 200    
